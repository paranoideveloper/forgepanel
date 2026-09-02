//go:build harness

// socks.go is a hand-rolled SOCKS5 client (RFC 1928). The harness drives every
// proxy client core through its local SOCKS/mixed inbound, so it needs both
// CONNECT (for the TCP payload probe) and UDP ASSOCIATE (for the DNS probe that
// proves UDP actually traverses the tunnel).
//
// It is written against the wire format rather than a library so the harness
// keeps the standard library as its only dependency and so a malformed reply
// from a core surfaces as a precise error instead of a generic dial failure.
package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 wire constants.
const (
	socks5Version    = 0x05
	socksNoAuth      = 0x00
	socksCmdConnect  = 0x01
	socksCmdUDPAssoc = 0x03
	socksAtypIPv4    = 0x01
	socksAtypDomain  = 0x03
	socksAtypIPv6    = 0x04
)

var socksReplyText = map[byte]string{
	0: "succeeded", 1: "general SOCKS server failure", 2: "connection not allowed",
	3: "network unreachable", 4: "host unreachable", 5: "connection refused",
	6: "TTL expired", 7: "command not supported", 8: "address type not supported",
}

// SocksDialer dials through a SOCKS5 proxy listening at Addr.
type SocksDialer struct {
	Addr    string // host:port of the SOCKS5 server
	Timeout time.Duration
}

// DialContext implements the hook http.Transport wants. The address is passed
// to the proxy as a DOMAIN when it is not an IP literal, which is what makes
// the probe prove *remote* name resolution: the harness client cannot resolve
// the origin's name itself, so a successful request means the far side did.
func (d SocksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5: unsupported network %q", network)
	}
	to := d.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	var dl net.Dialer
	dl.Timeout = to
	c, err := dl.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", d.Addr, err)
	}
	if dead, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dead)
	} else {
		_ = c.SetDeadline(time.Now().Add(to))
	}
	if err := socksGreet(c); err != nil {
		c.Close()
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("socks5: bad target %q: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("socks5: bad port in %q: %w", address, err)
	}
	req := append([]byte{socks5Version, socksCmdConnect, 0x00}, encodeSocksAddr(host, port)...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks5: write CONNECT: %w", err)
	}
	if _, _, err := readSocksReply(c); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// UDPAssociate opens a UDP relay through the proxy. The returned conn sends and
// receives bare datagrams: the SOCKS UDP request header is added and stripped
// here. Callers must Close it, which also tears down the TCP control channel
// the proxy uses to keep the association alive.
func (d SocksDialer) UDPAssociate(target string) (*SocksUDPConn, error) {
	to := d.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	ctrl, err := net.DialTimeout("tcp", d.Addr, to)
	if err != nil {
		return nil, fmt.Errorf("socks5-udp: dial proxy %s: %w", d.Addr, err)
	}
	_ = ctrl.SetDeadline(time.Now().Add(to))
	if err := socksGreet(ctrl); err != nil {
		ctrl.Close()
		return nil, err
	}
	// A zero requester address means "I will tell you my source later", which is
	// what every proxy core here accepts and what a client behind NAT must send.
	req := append([]byte{socks5Version, socksCmdUDPAssoc, 0x00},
		encodeSocksAddr("0.0.0.0", 0)...)
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("socks5-udp: write ASSOCIATE: %w", err)
	}
	bndHost, bndPort, err := readSocksReply(ctrl)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	// Cores commonly answer 0.0.0.0 to mean "the address you reached me on".
	if bndHost == "" || bndHost == "0.0.0.0" || bndHost == "::" {
		h, _, _ := net.SplitHostPort(d.Addr)
		bndHost = h
	}
	relay, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bndHost, strconv.Itoa(bndPort)))
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("socks5-udp: resolve relay: %w", err)
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("socks5-udp: open local socket: %w", err)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		pc.Close()
		ctrl.Close()
		return nil, fmt.Errorf("socks5-udp: bad target %q: %w", target, err)
	}
	port, _ := strconv.Atoi(portStr)
	_ = ctrl.SetDeadline(time.Time{})
	return &SocksUDPConn{ctrl: ctrl, pc: pc, relay: relay, host: host, port: port}, nil
}

// SocksUDPConn is one UDP association: datagrams written here are wrapped in a
// SOCKS UDP request header addressed to the association's target.
type SocksUDPConn struct {
	ctrl  net.Conn
	pc    *net.UDPConn
	relay *net.UDPAddr
	host  string
	port  int
}

// Write sends one datagram to the association target through the proxy.
func (u *SocksUDPConn) Write(p []byte) (int, error) {
	pkt := append([]byte{0x00, 0x00, 0x00}, encodeSocksAddr(u.host, u.port)...)
	pkt = append(pkt, p...)
	if _, err := u.pc.WriteToUDP(pkt, u.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns the payload of the next datagram from the proxy, with the SOCKS
// UDP header removed.
func (u *SocksUDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 65535)
	n, _, err := u.pc.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	if n < 10 {
		return 0, fmt.Errorf("socks5-udp: reply of %d bytes is shorter than a header", n)
	}
	off := 3
	switch buf[off] {
	case socksAtypIPv4:
		off += 1 + 4
	case socksAtypIPv6:
		off += 1 + 16
	case socksAtypDomain:
		if n < off+2 {
			return 0, errors.New("socks5-udp: truncated domain in reply header")
		}
		off += 1 + 1 + int(buf[off+1])
	default:
		return 0, fmt.Errorf("socks5-udp: unknown address type 0x%02x in reply", buf[off])
	}
	off += 2 // port
	if off > n {
		return 0, errors.New("socks5-udp: reply header longer than datagram")
	}
	return copy(p, buf[off:n]), nil
}

// SetDeadline bounds Read/Write on the datagram socket.
func (u *SocksUDPConn) SetDeadline(t time.Time) error { return u.pc.SetDeadline(t) }

// Close releases the datagram socket and the control channel.
func (u *SocksUDPConn) Close() error {
	err := u.pc.Close()
	if cerr := u.ctrl.Close(); err == nil {
		err = cerr
	}
	return err
}

func socksGreet(c net.Conn) error {
	if _, err := c.Write([]byte{socks5Version, 0x01, socksNoAuth}); err != nil {
		return fmt.Errorf("socks5: write greeting: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return fmt.Errorf("socks5: read greeting reply: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5: server answered version %d", resp[0])
	}
	if resp[1] != socksNoAuth {
		return fmt.Errorf("socks5: server demands auth method 0x%02x", resp[1])
	}
	return nil
}

// readSocksReply consumes a reply and returns the bound address it carries.
func readSocksReply(c net.Conn) (host string, port int, err error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: read reply: %w", err)
	}
	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5: reply version %d", head[0])
	}
	if head[1] != 0x00 {
		txt := socksReplyText[head[1]]
		if txt == "" {
			txt = "unknown"
		}
		return "", 0, fmt.Errorf("socks5: request rejected: %s (0x%02x)", txt, head[1])
	}
	switch head[3] {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case socksAtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("socks5: unknown reply address type 0x%02x", head[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	return host, int(pb[0])<<8 | int(pb[1]), nil
}

func encodeSocksAddr(host string, port int) []byte {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, socksAtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, socksAtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		out = append(out, socksAtypDomain, byte(len(host)))
		out = append(out, host...)
	}
	return append(out, byte(port>>8), byte(port))
}
