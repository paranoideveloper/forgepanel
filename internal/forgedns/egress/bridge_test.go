package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// echoServer accepts connections and echoes bytes back.
func echoServer(t *testing.T) (addr string, received func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						mu.Lock()
						got = append(got, buf[:n]...)
						mu.Unlock()
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), got...)
	}
}

// pollAsClient drives the real v1 frame protocol: each new request sequence
// implicitly acknowledges the previous answer, which is what actually advances
// the downstream queue. Driving the protocol rather than reaching into the
// manager keeps the test honest about how bytes really leave.
func pollAsClient(m *session.Manager, id uint64, seq uint16) []byte {
	resp := m.Ingest(codec.Frame{SessionID: uint16(id), Seq: seq, Flags: codec.FlagKA})
	return resp.Payload
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestBridgeOpensOneConnectionPerSessionAndReusesIt(t *testing.T) {
	var dials int
	var mu sync.Mutex
	m := session.NewManager(time.Minute)
	b := New(m, func(ctx context.Context, id uint64) (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		c, _ := net.Pipe()
		return c, nil
	}, Options{})
	defer b.Shutdown()

	// A session with nothing reassembled must not dial: a tunnel that opens an
	// upstream socket for every probe is a resource amplifier for anyone who can
	// send a UDP packet.
	b.Deliver(context.Background(), 1)
	mu.Lock()
	n := dials
	mu.Unlock()
	if n != 0 {
		t.Fatalf("dialled %d time(s) for a session with no data", n)
	}
}

func TestBridgeCarriesBytesBothWays(t *testing.T) {
	// The whole point of the row: bytes in, bytes out. Before this the manager
	// reassembled upstream data into a buffer nothing drained, and nothing ever
	// queued a downstream byte.
	addr, received := echoServer(t)
	m := session.NewManager(time.Minute)
	b := New(m, TCPDialer(addr), Options{})
	defer b.Shutdown()

	const id = 42
	// Establish the session, then hand the bridge a connection and write.
	c, err := b.connFor(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.nc.Write([]byte("hello upstream")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the destination to receive the bytes", func() bool {
		return string(received()) == "hello upstream"
	})
	waitFor(t, "the echo to be queued for the client", func() bool {
		return m.PendingOutbound(id) == len("hello upstream")
	})
	if got := b.Counters().BytesDown; got != uint64(len("hello upstream")) {
		t.Fatalf("BytesDown = %d, want %d", got, len("hello upstream"))
	}
}

func TestDownstreamBytesAreNeverDroppedWhenTheQueueIsFull(t *testing.T) {
	// QueueOutbound truncates past its cap and counts the rest as dropped. That
	// is right for a queue and wrong for a byte stream: dropping from the middle
	// of a TCP stream does not slow the sender, it corrupts the stream, and the
	// client sees a protocol error nowhere near the cause. The bridge must wait
	// for room instead.
	const cap = 64
	m := session.NewManagerWithOptions(session.Options{
		IdleTTL: time.Minute, MaxOutboundBytes: cap,
	})
	server, client := net.Pipe()
	b := New(m, func(context.Context, uint64) (net.Conn, error) { return client, nil }, Options{})
	defer b.Shutdown()

	const id = 7
	if _, err := b.connFor(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	// Push four times the queue cap at it.
	payload := make([]byte, cap*4)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	go func() { server.Write(payload); server.Close() }()

	// Drain the client side the way repeated polls do.
	var drained []byte
	var seq uint16
	deadline := time.Now().Add(10 * time.Second)
	for len(drained) < len(payload) && time.Now().Before(deadline) {
		seq++
		if chunk := pollAsClient(m, id, seq); len(chunk) > 0 {
			drained = append(drained, chunk...)
			continue
		}
		time.Sleep(2 * time.Millisecond)
	}
	if string(drained) != string(payload) {
		t.Fatalf("the client received %d of %d bytes, and they %s match — "+
			"bytes were dropped from the middle of the stream",
			len(drained), len(payload),
			map[bool]string{true: "do", false: "do NOT"}[string(drained) == string(payload)])
	}
	if got := b.Counters().BytesDown; got != uint64(len(payload)) {
		t.Fatalf("BytesDown = %d, want %d — bytes were dropped from the middle of the stream", got, len(payload))
	}
	if c := m.Counters().OutboundDropped; c != 0 {
		t.Fatalf("the session manager dropped %d byte(s); the bridge overfilled the queue", c)
	}
}

func TestBridgeRefusesMoreThanMaxConns(t *testing.T) {
	// A DNS tunnel is reachable by anyone who can send a UDP packet, so an
	// unbounded connection map is a file-descriptor exhaustion primitive.
	m := session.NewManager(time.Minute)
	b := New(m, func(context.Context, uint64) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	}, Options{MaxConns: 2})
	defer b.Shutdown()

	for i := uint64(1); i <= 2; i++ {
		if _, err := b.connFor(context.Background(), i); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if _, err := b.connFor(context.Background(), 3); err == nil {
		t.Fatal("a third connection was allowed past MaxConns=2")
	}
	if got := b.Counters().Refused; got != 1 {
		t.Fatalf("Refused = %d, want 1", got)
	}
}

func TestAFailedDialLeavesNoReservedSlot(t *testing.T) {
	// The slot is reserved before dialling so two concurrent queries for one
	// session cannot both dial. If a failure left the reservation behind, that
	// session could never connect again and the cap would leak downward.
	m := session.NewManager(time.Minute)
	fail := errors.New("nope")
	var attempts int
	b := New(m, func(context.Context, uint64) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, fail
		}
		c, _ := net.Pipe()
		return c, nil
	}, Options{MaxConns: 1})
	defer b.Shutdown()

	if _, err := b.connFor(context.Background(), 1); err == nil {
		t.Fatal("expected the dial to fail")
	}
	if _, err := b.connFor(context.Background(), 1); err != nil {
		t.Fatalf("the session could not connect after one failed dial: %v", err)
	}
}

func TestConnectionsForEvictedSessionsAreClosed(t *testing.T) {
	// The session manager evicts its own state on an idle timer. A connection
	// bound to an evicted session would otherwise stay open forever with nobody
	// left to read it — one leaked socket per abandoned tunnel.
	m := session.NewManager(time.Minute)
	closed := make(chan struct{}, 1)
	server, client := net.Pipe()
	go func() { io.Copy(io.Discard, server); closed <- struct{}{} }()

	b := New(m, func(context.Context, uint64) (net.Conn, error) { return client, nil },
		Options{SweepInterval: 5 * time.Millisecond})
	defer b.Shutdown()

	// Session 99 never exists in the manager, so the sweeper must reap it.
	if _, err := b.connFor(context.Background(), 99); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection for an evicted session was left open")
	}
}

func TestShutdownClosesEverythingAndStopsGoroutines(t *testing.T) {
	m := session.NewManager(time.Minute)
	var conns []net.Conn
	var mu sync.Mutex
	b := New(m, func(context.Context, uint64) (net.Conn, error) {
		c, other := net.Pipe()
		go io.Copy(io.Discard, other)
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c, nil
	}, Options{})
	for i := uint64(1); i <= 3; i++ {
		if _, err := b.connFor(context.Background(), i); err != nil {
			t.Fatal(err)
		}
	}
	b.Shutdown() // must not hang
	mu.Lock()
	defer mu.Unlock()
	for i, c := range conns {
		if _, err := c.Write([]byte("x")); err == nil {
			t.Errorf("connection %d was still open after Shutdown", i)
		}
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	b := New(session.NewManager(time.Minute), func(context.Context, uint64) (net.Conn, error) {
		return nil, fmt.Errorf("unused")
	}, Options{})
	b.Shutdown()
	b.Shutdown() // a second call must not panic on a closed channel
}
