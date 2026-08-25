package frontrouter

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeBackend is a tunnel stand-in: it echoes the query back with the QR bit
// set and a marker appended, so a test can tell WHICH backend answered.
func fakeBackend(t *testing.T, marker byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			binary.BigEndian.PutUint16(reply[2:4], 0x8180) // QR + RA
			_, _ = conn.WriteTo(append(reply, marker), addr)
		}
	}()
	return conn.LocalAddr().String()
}

// runRouter starts a router on an ephemeral public port and returns its address.
func runRouter(t *testing.T, tbl *Table, opts Options) (string, *Server) {
	t.Helper()
	pub, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("public listen: %v", err)
	}
	srv, err := New(tbl, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = pub.Close() })
	go func() { _ = srv.ServeUDP(ctx, pub) }()
	return pub.LocalAddr().String(), srv
}

// ask sends one query and returns the reply, or nil on timeout.
func ask(t *testing.T, routerAddr, name string) []byte {
	t.Helper()
	conn, err := net.Dial("udp", routerAddr)
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(buildQuery(name)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// The headline capability: two tunnels, one public port, each query delivered
// to the backend that owns its suffix. Before this package the panel could
// serve exactly one of these on :53.
func TestRouterDeliversEachSuffixToItsOwnBackend(t *testing.T) {
	alpha := fakeBackend(t, 0xA1)
	beta := fakeBackend(t, 0xB2)
	tbl, err := NewTable([]Backend{
		{Name: "alpha", Suffixes: []string{"alpha.example.com"}, UDPAddr: alpha},
		{Name: "beta", Suffixes: []string{"beta.example.com"}, UDPAddr: beta},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	addr, srv := runRouter(t, tbl, Options{})

	for _, tc := range []struct {
		name   string
		marker byte
	}{
		{"payload.alpha.example.com", 0xA1},
		{"payload.beta.example.com", 0xB2},
		{"alpha.example.com", 0xA1},
	} {
		reply := ask(t, addr, tc.name)
		if reply == nil {
			t.Fatalf("%s: no reply from the router", tc.name)
		}
		if got := reply[len(reply)-1]; got != tc.marker {
			t.Errorf("%s answered by the wrong backend: marker %#x, want %#x", tc.name, got, tc.marker)
		}
	}
	if got := srv.Stats().Forwarded; got != 3 {
		t.Errorf("Forwarded = %d, want 3", got)
	}
}

// The forwarded datagram must reach the backend unchanged. Tunnels encode their
// payload in the name itself, so a router that re-serialised packets would
// silently reduce every tunnel's usable bytes per query.
func TestRouterForwardsQueryBytesUnchanged(t *testing.T) {
	received := make(chan []byte, 1)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		got := make([]byte, n)
		copy(got, buf[:n])
		received <- got
		_, _ = conn.WriteTo(got, addr)
	}()

	tbl, err := NewTable([]Backend{{Name: "t", Suffixes: []string{"t.example.com"}, UDPAddr: conn.LocalAddr().String()}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	addr, _ := runRouter(t, tbl, Options{})

	sent := buildQuery("c2FtcGxlLXBheWxvYWQ.t.example.com")
	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(sent); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, sent) {
			t.Fatalf("backend received %d bytes, sent %d — the router must not rewrite the packet", len(got), len(sent))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the query")
	}
}

// A query for a name nobody owns is dropped, not answered.
//
// Replying REFUSED would make the router respond to spoofed source addresses,
// turning a public port 53 into an unsolicited-traffic generator. Dropping
// costs an attacker exactly as much and costs us nothing.
func TestRouterDropsUnroutableNamesSilently(t *testing.T) {
	backend := fakeBackend(t, 0xCC)
	tbl, err := NewTable([]Backend{{Name: "only", Suffixes: []string{"known.example.com"}, UDPAddr: backend}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	addr, srv := runRouter(t, tbl, Options{})

	if reply := ask(t, addr, "somewhere.else.example.org"); reply != nil {
		t.Fatalf("router answered an unroutable name with %d bytes; it must stay silent", len(reply))
	}
	if got := srv.Stats().NoRoute; got != 1 {
		t.Errorf("NoRoute = %d, want 1", got)
	}
}

// Malformed input must be counted and dropped, never forwarded. Anything that
// reaches a public port 53 will include garbage.
func TestRouterDropsMalformedQueries(t *testing.T) {
	backend := fakeBackend(t, 0xDD)
	tbl, _ := NewTable([]Backend{{Name: "b", Suffixes: []string{"t.example.com"}, UDPAddr: backend}})
	addr, srv := runRouter(t, tbl, Options{})

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Too short to hold a header, and a header with no question.
	if _, err := conn.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	headerOnly := make([]byte, dnsHeaderLen)
	if _, err := conn.Write(headerOnly); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Stats().Malformed >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.Stats().Malformed; got != 2 {
		t.Errorf("Malformed = %d, want 2", got)
	}
	if got := srv.Stats().Forwarded; got != 0 {
		t.Errorf("Forwarded = %d, want 0 — malformed input must never reach a backend", got)
	}
}

// A backend that never answers must not pin the query forever.
func TestRouterTimesOutADeadBackend(t *testing.T) {
	// A socket that accepts datagrams and never replies.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	tbl, _ := NewTable([]Backend{{Name: "dead", Suffixes: []string{"t.example.com"}, UDPAddr: dead.LocalAddr().String()}})
	addr, srv := runRouter(t, tbl, Options{BackendTimeout: 200 * time.Millisecond})

	start := time.Now()
	if reply := ask(t, addr, "x.t.example.com"); reply != nil {
		t.Fatal("a dead backend must not produce a reply")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("query took %v; the backend timeout did not apply", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Stats().BackendErr >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.Stats().BackendErr; got != 1 {
		t.Errorf("BackendErr = %d, want 1", got)
	}
}

// Starting with no routes is refused: every query would be dropped, which looks
// exactly like the router being broken.
func TestNewRefusesAnEmptyTable(t *testing.T) {
	if _, err := New(&Table{}, Options{}); err == nil {
		t.Fatal("expected New to refuse a table with no routes")
	}
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("expected New to refuse a nil table")
	}
}

// DNS-over-TCP: the length-prefixed path must route by the same rules.
func TestRouterRoutesDNSOverTCP(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		msg, err := readTCPMessage(conn, 4096)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(msg[2:4], 0x8180)
		_ = writeTCPMessage(conn, append(msg, 0xEE))
	}()

	tbl, err := NewTable([]Backend{{
		Name: "tcpbackend", Suffixes: []string{"t.example.com"},
		UDPAddr: "127.0.0.1:1", TCPAddr: backend.Addr().String(),
	}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	srv, err := New(tbl, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("public listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = pub.Close() })
	go func() { _ = srv.ServeTCP(ctx, pub) }()

	client, err := net.Dial("tcp", pub.Addr().String())
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer client.Close()
	if err := writeTCPMessage(client, buildQuery("x.t.example.com")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := readTCPMessage(client, 4096)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[len(reply)-1] != 0xEE {
		t.Fatalf("reply did not come from the TCP backend")
	}
}

// An attacker-controlled length prefix must be rejected before allocation.
func TestReadTCPMessageRejectsAnOversizedLengthPrefix(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(60000))
	if _, err := readTCPMessage(&buf, 4096); err == nil {
		t.Fatal("expected a 60000-byte prefix to be refused against a 4096 cap")
	}
	var zero bytes.Buffer
	_ = binary.Write(&zero, binary.BigEndian, uint16(0))
	if _, err := readTCPMessage(&zero, 4096); err == nil {
		t.Fatal("expected a zero-length message to be refused")
	}
}
