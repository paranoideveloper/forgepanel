package egress

// A minimal SOCKS5 server (RFC 1928) spoken over the tunnel stream.
//
// The zone model's "socks5" mode means the CLIENT'S stream is itself a SOCKS5
// conversation: the client's local application connects to a SOCKS5 listener on
// its own machine, that traffic is tunnelled through DNS, and this end has to be
// the SOCKS5 server. There is nothing to dial — the destination is whatever the
// client asks for once the handshake completes.
//
// CONNECT with no authentication only. BIND and UDP ASSOCIATE are not
// implemented and are refused explicitly with the RFC's own "command not
// supported" reply, rather than left to look like a hang: a client that gets no
// answer retries, and a DNS tunnel is far too slow to spend on a retry that can
// never succeed. Authentication is absent because the tunnel already
// authenticates — a v2 session carries a per-session HMAC — and a second
// password inside it would protect nothing.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	authNoneOK    = 0x00
	authNoAccept  = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repHostUnreachable     = 0x04
	repConnRefused         = 0x05
	repCommandNotSupported = 0x07
	repAddrNotSupported    = 0x08
)

// SOCKS5Options configure the in-process SOCKS5 server.
type SOCKS5Options struct {
	// DialTimeout bounds the connection to the requested destination.
	DialTimeout time.Duration
	// Dial overrides how destinations are reached. Injected by tests; nil uses
	// a plain net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Allow decides whether a destination may be reached. nil allows everything.
	//
	// A DNS tunnel is an open door by design, so this is the seam that stops it
	// being an open PROXY: without a policy, anyone who can send a UDP packet to
	// the zone can reach any host the server can, including the private network
	// it sits in.
	Allow func(host string, port int) bool
}

// SOCKS5Dialer returns a Dialer that serves SOCKS5 over each session's stream.
//
// It hands the bridge one end of an in-memory pipe and serves the other, so the
// bridge's plumbing does not have to know whether the far side is a socket or a
// protocol handler.
func SOCKS5Dialer(opts SOCKS5Options) Dialer {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.Dial == nil {
		var d net.Dialer
		opts.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		}
	}
	return func(ctx context.Context, _ uint64) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			// context.WithoutCancel: the dial context bounds opening the tunnel
			// connection, not the lifetime of the proxied session. Letting it
			// cancel here would tear down a working connection when the DNS
			// query that happened to create it returned.
			_ = serveSOCKS5(context.WithoutCancel(ctx), server, opts)
		}()
		return client, nil
	}
}

func serveSOCKS5(ctx context.Context, conn net.Conn, opts SOCKS5Options) error {
	dest, err := socks5Handshake(ctx, conn, opts)
	if err != nil {
		return err
	}
	defer dest.Close()

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(dest, conn); errc <- err }()
	go func() { _, err := io.Copy(conn, dest); errc <- err }()
	<-errc
	return nil
}

// socks5Handshake performs method negotiation and the CONNECT request, and
// returns the connected destination.
func socks5Handshake(ctx context.Context, conn net.Conn, opts SOCKS5Options) (net.Conn, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("socks5: unsupported version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}
	offersNone := false
	for _, m := range methods {
		if m == authNone {
			offersNone = true
			break
		}
	}
	if !offersNone {
		// Say so rather than dropping the connection: a client that gets no
		// reply cannot tell "wrong auth method" from "tunnel is broken".
		_, _ = conn.Write([]byte{socks5Version, authNoAccept})
		return nil, errors.New("socks5: client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socks5Version, authNoneOK}); err != nil {
		return nil, err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return nil, err
	}
	if req[0] != socks5Version {
		return nil, fmt.Errorf("socks5: unsupported version %d in request", req[0])
	}
	// Parse the WHOLE request before judging the command. Replying early leaves
	// the address and port unread in the stream, and on any transport that does
	// not buffer independently in both directions — a pipe, and the tunnel this
	// runs over — the client is still writing them while this end is trying to
	// write its reply, and both sides stop. Consuming the request first also
	// leaves the stream in a defined state for the error reply.
	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = string(b)
	default:
		socks5Reply(conn, repAddrNotSupported)
		return nil, fmt.Errorf("socks5: address type %d is not supported", req[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(pb))

	if req[1] != cmdConnect {
		socks5Reply(conn, repCommandNotSupported)
		return nil, fmt.Errorf("socks5: command %d is not supported", req[1])
	}

	if opts.Allow != nil && !opts.Allow(host, port) {
		socks5Reply(conn, repGeneralFailure)
		return nil, fmt.Errorf("socks5: %s:%d is not permitted by policy", host, port)
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()
	dest, err := opts.Dial(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		code := repHostUnreachable
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Err != nil {
			code = repConnRefused
		}
		socks5Reply(conn, byte(code))
		return nil, fmt.Errorf("socks5: connect %s:%d: %w", host, port, err)
	}
	if err := socks5Reply(conn, repSuccess); err != nil {
		dest.Close()
		return nil, err
	}
	return dest, nil
}

// socks5Reply writes a reply with a zero BND.ADDR/BND.PORT.
//
// The bound address is what the server would use for a subsequent BIND, which
// is not supported here; RFC 1928 permits reporting all zeroes, and every client
// that only uses CONNECT ignores it.
func socks5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// DenyPrivate refuses destinations on loopback, link-local and RFC 1918
// networks.
//
// A DNS tunnel is reachable by anyone who can send a UDP packet to the zone, so
// without a policy the SOCKS5 mode is a route into whatever private network the
// panel is sitting in — the server's own admin interfaces, the cloud metadata
// endpoint at 169.254.169.254, the database on the next host.
func DenyPrivate(host string, _ int) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname. It is resolved by the dialer, so this cannot judge it
		// here without resolving it twice and risking a different answer the
		// second time; the name-based case is left to the dialer's own policy.
		return true
	}
	return !isPrivate(ip)
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()
}
