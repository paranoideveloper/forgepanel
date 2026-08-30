package frontrouter

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Defaults chosen for a DNS front door rather than a general proxy.
const (
	// defaultMaxPacket is the largest UDP datagram accepted. DNS tunnels rely on
	// EDNS0 buffers well above 512, so a 512 cap would silently cripple them;
	// 4096 is the practical ceiling resolvers advertise.
	defaultMaxPacket = 4096
	// defaultBackendTimeout bounds how long a backend may take. A tunnel that
	// stops answering must not pin the query goroutine and its buffer forever.
	defaultBackendTimeout = 5 * time.Second
	// defaultMaxInFlight bounds concurrent backend exchanges. Without a ceiling
	// a UDP flood on a public port turns into unbounded goroutines and sockets —
	// the process dies of resource exhaustion rather than dropping queries.
	defaultMaxInFlight = 512
)

// Options tunes the router. The zero value is usable; every field has a
// deliberate default above.
type Options struct {
	MaxPacketSize  int
	BackendTimeout time.Duration
	MaxInFlight    int
	// OnError observes per-query failures. It must not block: it is called on
	// the serving path. Nil disables reporting.
	OnError func(stage string, err error)
	// TLSHandshakeTimeout bounds how long a peer may take to send a whole
	// ClientHello on the TLS ports. Zero uses defaultHandshakeTimeout.
	TLSHandshakeTimeout time.Duration
	// TLSStreamIdle reaps a spliced TLS connection idle in both directions.
	// Zero uses defaultStreamIdle, which is generous: DoT connections are
	// long-lived and idle by design.
	TLSStreamIdle time.Duration
}

// HandshakeTimeout is the effective ClientHello deadline.
func (o Options) HandshakeTimeout() time.Duration {
	if o.TLSHandshakeTimeout <= 0 {
		return defaultHandshakeTimeout
	}
	return o.TLSHandshakeTimeout
}

// StreamIdle is the effective idle deadline for a spliced TLS connection.
func (o Options) StreamIdle() time.Duration {
	if o.TLSStreamIdle <= 0 {
		return defaultStreamIdle
	}
	return o.TLSStreamIdle
}

func (o Options) withDefaults() Options {
	if o.MaxPacketSize <= 0 {
		o.MaxPacketSize = defaultMaxPacket
	}
	if o.BackendTimeout <= 0 {
		o.BackendTimeout = defaultBackendTimeout
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = defaultMaxInFlight
	}
	return o
}

// Server multiplexes one public DNS socket across many tunnel backends.
type Server struct {
	table *Table
	opts  Options
	sem   chan struct{}

	mu    sync.Mutex
	stats Stats
}

// Stats is a snapshot of what the router has done. Counters are the minimum an
// operator needs to answer "is it working, and if not, where is it failing".
type Stats struct {
	Queries    uint64
	Forwarded  uint64
	NoRoute    uint64
	Malformed  uint64
	BackendErr uint64
	Overloaded uint64
}

// New builds a router over an immutable table.
func New(table *Table, opts Options) (*Server, error) {
	if table == nil || len(table.routes) == 0 {
		return nil, fmt.Errorf("frontrouter: refusing to start with no routes; every query would be REFUSED")
	}
	o := opts.withDefaults()
	return &Server{table: table, opts: o, sem: make(chan struct{}, o.MaxInFlight)}, nil
}

// Stats returns a copy of the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Server) bump(f func(*Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

func (s *Server) report(stage string, err error) {
	if s.opts.OnError != nil && err != nil {
		s.opts.OnError(stage, err)
	}
}

// ServeUDP reads queries from conn until ctx is cancelled or conn is closed.
//
// The datagram is forwarded to the backend BYTE FOR BYTE. Re-encoding would
// change the packet the tunnel client built and, because tunnels pack payload
// into the name itself, could shrink the usable bytes per query. The router's
// job is to choose a destination, not to interpret the tunnel's own framing.
func (s *Server) ServeUDP(ctx context.Context, conn net.PacketConn) error {
	// One extra byte so a datagram larger than the cap is detected on read
	// rather than silently truncated into a malformed query.
	buf := make([]byte, s.opts.MaxPacketSize+1)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A closed socket during shutdown is the normal exit path.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		s.bump(func(st *Stats) { st.Queries++ })
		if n > s.opts.MaxPacketSize {
			s.bump(func(st *Stats) { st.Malformed++ })
			s.report("oversize", fmt.Errorf("datagram of %d bytes exceeds the %d-byte cap", n, s.opts.MaxPacketSize))
			continue
		}

		name, err := QuestionName(buf[:n])
		if err != nil {
			s.bump(func(st *Stats) { st.Malformed++ })
			s.report("parse", err)
			continue
		}
		backend, ok := s.table.Match(name)
		if !ok {
			s.bump(func(st *Stats) { st.NoRoute++ })
			s.report("route", fmt.Errorf("no backend owns %q", name))
			// Deliberately silent. A REFUSED reply here would make the router an
			// unsolicited responder to spoofed source addresses; dropping costs
			// the attacker the same and us nothing.
			continue
		}

		// Copy: buf is reused by the next read as soon as the loop turns.
		query := make([]byte, n)
		copy(query, buf[:n])

		select {
		case s.sem <- struct{}{}:
		default:
			s.bump(func(st *Stats) { st.Overloaded++ })
			s.report("overload", fmt.Errorf("in-flight limit of %d reached; dropping query for %q", s.opts.MaxInFlight, name))
			continue
		}
		go func(query []byte, client net.Addr, backend Backend) {
			defer func() { <-s.sem }()
			reply, err := s.exchangeUDP(backend, query)
			if err != nil {
				s.bump(func(st *Stats) { st.BackendErr++ })
				s.report("backend", fmt.Errorf("%s: %w", backend.Name, err))
				return
			}
			if _, err := conn.WriteTo(reply, client); err != nil {
				s.report("reply", err)
				return
			}
			s.bump(func(st *Stats) { st.Forwarded++ })
		}(query, client, backend)
	}
}

// exchangeUDP sends one query to a backend and returns its reply.
//
// A fresh socket per exchange is deliberate: the ephemeral source port is what
// keeps concurrent replies from different clients apart, and a shared socket
// would require correlating by transaction ID, which a malicious backend or an
// off-path spoofer could game.
func (s *Server) exchangeUDP(backend Backend, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", backend.UDPAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", backend.UDPAddr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.opts.BackendTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, s.opts.MaxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return buf[:n], nil
}

// ServeTCP accepts DNS-over-TCP connections and forwards them to the backend
// that owns the first question.
func (s *Server) ServeTCP(ctx context.Context, listener net.Listener) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.bump(func(st *Stats) { st.Overloaded++ })
			conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { <-s.sem }()
			defer c.Close()
			if err := s.handleTCP(c); err != nil {
				s.report("tcp", err)
			}
		}(conn)
	}
}

// handleTCP relays a single length-prefixed exchange.
func (s *Server) handleTCP(client net.Conn) error {
	if err := client.SetDeadline(time.Now().Add(s.opts.BackendTimeout)); err != nil {
		return err
	}
	query, err := readTCPMessage(client, s.opts.MaxPacketSize)
	if err != nil {
		s.bump(func(st *Stats) { st.Malformed++ })
		return err
	}
	s.bump(func(st *Stats) { st.Queries++ })

	name, err := QuestionName(query)
	if err != nil {
		s.bump(func(st *Stats) { st.Malformed++ })
		return err
	}
	backend, ok := s.table.Match(name)
	if !ok {
		s.bump(func(st *Stats) { st.NoRoute++ })
		return fmt.Errorf("no backend owns %q", name)
	}
	// An empty TCPAddr means the backend genuinely does not serve TCP. Saying so
	// beats dialling the UDP port with a stream socket, which fails in a way
	// that looks like the backend is down.
	addr := backend.TCPAddr
	if addr == "" {
		s.bump(func(st *Stats) { st.BackendErr++ })
		return fmt.Errorf("backend %q has no DNS-over-TCP address", backend.Name)
	}

	upstream, err := net.DialTimeout("tcp", addr, s.opts.BackendTimeout)
	if err != nil {
		s.bump(func(st *Stats) { st.BackendErr++ })
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer upstream.Close()
	if err := upstream.SetDeadline(time.Now().Add(s.opts.BackendTimeout)); err != nil {
		return err
	}
	if err := writeTCPMessage(upstream, query); err != nil {
		s.bump(func(st *Stats) { st.BackendErr++ })
		return err
	}
	reply, err := readTCPMessage(upstream, s.opts.MaxPacketSize)
	if err != nil {
		s.bump(func(st *Stats) { st.BackendErr++ })
		return err
	}
	if err := writeTCPMessage(client, reply); err != nil {
		return err
	}
	s.bump(func(st *Stats) { st.Forwarded++ })
	return nil
}

// readTCPMessage reads one RFC 1035 §4.2.2 length-prefixed DNS message.
//
// The advertised length is checked against max BEFORE allocating: it is
// attacker-controlled, and a 65535 prefix on every connection is a cheap way to
// make the process allocate far more than it will ever use.
func readTCPMessage(r io.Reader, max int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 {
		return nil, fmt.Errorf("frontrouter: zero-length DNS message")
	}
	if length > max {
		return nil, fmt.Errorf("frontrouter: message of %d bytes exceeds the %d-byte cap", length, max)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xffff {
		return fmt.Errorf("frontrouter: message of %d bytes cannot be length-prefixed", len(msg))
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(msg)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}
