package frontrouter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// defaultHandshakeTimeout bounds how long a peer may take to finish sending
	// a ClientHello. Without it, opening connections and saying nothing is a
	// free way to pin every accepted socket on a public port.
	defaultHandshakeTimeout = 10 * time.Second
	// defaultStreamIdle bounds a spliced connection with no traffic in either
	// direction. DoT connections are long-lived and idle by nature, so this is
	// generous; it exists to reap the ones nobody will ever close.
	defaultStreamIdle = 10 * time.Minute
)

// tlsPick chooses which of a backend's addresses this listener forwards to.
//
// A function rather than a field because the two TLS ports route by the same
// rule to different places: :853 to the backend's DoT listener and :443 to its
// DoH listener. One implementation, told which address it is carrying.
type tlsPick func(Backend) string

// ServeTLS routes TLS streams by SNI, passing them through unchanged.
//
// It reads only the ClientHello — enough to pick a backend — then replays those
// exact bytes to the backend and splices the two connections. Nothing is
// decrypted, so the client validates the BACKEND's certificate and negotiates
// ALPN with the backend, and this router cannot read the tunnel it carries.
//
// Returns nil when ctx is cancelled or the listener is closed, matching ServeUDP
// and ServeTCP: shutdown is not an error the caller should report.
func (s *Server) ServeTLS(ctx context.Context, ln net.Listener, pick tlsPick) error {
	if pick == nil {
		return errors.New("frontrouter: ServeTLS needs an address selector")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("frontrouter: accept: %w", err)
		}
		// The in-flight ceiling is shared with the DNS path deliberately: both
		// are ways for one public socket to consume this process's resources,
		// and one budget is easier to reason about than two.
		select {
		case s.sem <- struct{}{}:
		default:
			s.bump(func(st *Stats) { st.Overloaded++ })
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-s.sem }()
			s.handleTLS(conn, pick)
		}()
	}
}

// handleTLS peeks one ClientHello, picks a backend, and splices.
func (s *Server) handleTLS(client net.Conn, pick tlsPick) {
	defer client.Close()
	s.bump(func(st *Stats) { st.Queries++ })

	hello, name, err := readClientHello(client, s.opts.HandshakeTimeout())
	if err != nil {
		// Malformed and never-completed are the same to an operator — something
		// that is not a TLS client is talking to the TLS port.
		s.bump(func(st *Stats) { st.Malformed++ })
		s.report("tls-hello", err)
		return
	}

	backend, ok := s.table.Match(name)
	addr := ""
	if ok {
		addr = pick(backend)
	}
	if !ok || addr == "" {
		// Refused rather than sent to a default. A stream handed to a backend
		// that does not own the name fails with a certificate error naming
		// neither this router nor the real cause, which is strictly worse for
		// the operator than a closed connection and a counter.
		s.bump(func(st *Stats) { st.NoRoute++ })
		if ok {
			s.report("tls-route", fmt.Errorf("backend %q has no TLS listener for %q", backend.Name, name))
		} else {
			s.report("tls-route", fmt.Errorf("no backend owns %q", name))
		}
		return
	}

	upstream, err := net.DialTimeout("tcp", addr, s.opts.BackendTimeout)
	if err != nil {
		s.bump(func(st *Stats) { st.BackendErr++ })
		s.report("tls-dial", err)
		return
	}
	defer upstream.Close()

	// Replay the bytes already taken off the wire. Without this the backend
	// sees a stream that begins mid-handshake and the connection dies in a way
	// that looks like a broken backend rather than a broken router.
	if _, err := upstream.Write(hello); err != nil {
		s.bump(func(st *Stats) { st.BackendErr++ })
		s.report("tls-replay", err)
		return
	}
	s.bump(func(st *Stats) { st.Forwarded++ })
	splice(client, upstream, s.opts.StreamIdle())
}

// readClientHello reads until one whole ClientHello is buffered.
//
// It returns the raw bytes as well as the name because those bytes still have
// to reach the backend: this is a peek, not a consume, and the router has no
// way to push them back onto the socket.
func readClientHello(conn net.Conn, timeout time.Duration) ([]byte, string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, "", err
	}
	// Cleared before the splice: the deadline here is for the handshake only,
	// and leaving it set would kill every long-lived DoT connection at the same
	// age.
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 2048)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			name, perr := ServerName(buf)
			if perr == nil {
				return buf, name, nil
			}
			// Only "incomplete" justifies another read. A hello that is complete
			// and carries no SNI, or bytes that are not TLS at all, will not
			// improve with more data.
			if !errors.Is(perr, ErrShortClientHello) {
				return nil, "", perr
			}
			if len(buf) >= maxClientHello {
				return nil, "", ErrNotClientHello
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, "", ErrShortClientHello
			}
			return nil, "", err
		}
	}
}

// splice copies in both directions until either side finishes.
//
// Each direction refreshes a shared idle deadline, so a connection that is
// carrying traffic is never reaped and one that has gone silent in both
// directions eventually is.
func splice(a, b net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Closing both is what unblocks the other copier. Half-close would be
	// tidier for protocols that use it; TLS does not, and a peer that has sent
	// its close_notify has nothing further to say.
	_ = a.Close()
	_ = b.Close()
	<-done
}
