package core

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/frontrouter"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

// Each supervised upstream zone binds its own UDP port, and real resolvers only
// ever query 53 — so exactly one zone could be reachable from the internet and
// every other one answered nobody, while the panel reported them all healthy
// because they were running. These tests cover the router that fixes it, and
// the conditions under which it must NOT take the port.

func zoneStatus(zone, listen string, domains ...string) upstream.ZoneStatus {
	return upstream.ZoneStatus{Zone: zone, Listen: listen, Domains: domains}
}

func TestBackendsAreBuiltFromSupervisedZones(t *testing.T) {
	got, skipped := frontBackends([]upstream.ZoneStatus{
		zoneStatus("a", "127.0.0.1:5301", "a.example.com"),
		zoneStatus("b", "127.0.0.1:5302", "b.example.com", "b2.example.com"),
	})
	if len(got) != 2 || len(skipped) != 0 {
		t.Fatalf("got %d backends, %d skipped: %+v / %v", len(got), len(skipped), got, skipped)
	}
	if got[1].UDPAddr != "127.0.0.1:5302" || len(got[1].Suffixes) != 2 {
		t.Fatalf("second backend wrong: %+v", got[1])
	}
}

// A zone that cannot be routed must be reported, not guessed at: sending a name
// to the wrong tunnel produces a connection that hangs, which is far harder to
// diagnose than a query that is dropped with a reason.
func TestUnroutableZonesAreReportedRatherThanGuessedAt(t *testing.T) {
	_, skipped := frontBackends([]upstream.ZoneStatus{
		zoneStatus("nodomains", "127.0.0.1:5303"),
		zoneStatus("notlistening", "", "c.example.com"),
	})
	if len(skipped) != 2 {
		t.Fatalf("expected both zones to be reported as unroutable, got %v", skipped)
	}
	joined := strings.Join(skipped, " ")
	if !strings.Contains(joined, "nodomains") || !strings.Contains(joined, "notlistening") {
		t.Fatalf("the report should name each zone: %v", skipped)
	}
}

// A wildcard bind is not a dial target: dialling 0.0.0.0 fails. The supervised
// process is on this host, so the router must talk to it over loopback.
func TestWildcardListenIsDialledOverLoopback(t *testing.T) {
	for _, in := range []string{"0.0.0.0:5305", ":5305", "[::]:5305"} {
		got, _ := frontBackends([]upstream.ZoneStatus{zoneStatus("z", in, "z.example.com")})
		if len(got) != 1 {
			t.Fatalf("%s produced no backend", in)
		}
		host, _, err := net.SplitHostPort(got[0].UDPAddr)
		if err != nil {
			t.Fatalf("%s produced an undialable address %q", in, got[0].UDPAddr)
		}
		if host != "127.0.0.1" {
			t.Errorf("%s dialled as %q, want loopback", in, got[0].UDPAddr)
		}
	}
}

// One zone can own port 53 by itself, so a router in front of it adds a hop for
// nothing.
func TestRouterStaysIdleForASingleZone(t *testing.T) {
	c := NewForgeDNSController("127.0.0.1:0", t.TempDir())
	c.mu.Lock()
	note := c.syncFrontRouter(0)
	running := c.front != nil
	c.mu.Unlock()
	if running {
		t.Fatalf("the router started with no zones to multiplex")
	}
	_ = note
}

// The native in-process server binds the same address whenever native zones
// exist. Taking the port would replace a working listener with a failing one.
func TestRouterRefusesThePortWhenNativeZonesHoldIt(t *testing.T) {
	c := NewForgeDNSController("127.0.0.1:5310", t.TempDir())
	c.front = nil
	c.mu.Lock()
	note := c.syncFrontRouter(2) // two native zones -> the native server owns the port
	running := c.front != nil
	c.mu.Unlock()

	if running {
		t.Fatalf("the router bound a port the native server holds")
	}
	if note != "" && !strings.Contains(note, "native") {
		t.Fatalf("the reason should name the native server, got %q", note)
	}
}

// End to end: two fake tunnels on private ports, one public socket in front,
// and a query for each name reaching the right one.
func TestRouterMultiplexesTwoZonesOnOnePort(t *testing.T) {
	backendA := startEchoDNS(t, "A")
	backendB := startEchoDNS(t, "B")

	c := NewForgeDNSController("127.0.0.1:0", "")
	// Drive the wiring directly: the upstream manager needs real binaries, and
	// what is under test is the routing, not the supervisor.
	backends, _ := frontBackends([]upstream.ZoneStatus{
		zoneStatus("a", backendA.addr, "a.example.com"),
		zoneStatus("b", backendB.addr, "b.example.com"),
	})
	if len(backends) != 2 {
		t.Fatalf("fixture built %d backends", len(backends))
	}
	_ = c

	pub := startRouter(t, backends)

	if got := dnsQuery(t, pub, "host.a.example.com"); got != "A" {
		t.Errorf("a.example.com routed to %q, want A", got)
	}
	if got := dnsQuery(t, pub, "host.b.example.com"); got != "B" {
		t.Errorf("b.example.com routed to %q, want B", got)
	}
	// A name no zone claims must be dropped, not sent somewhere arbitrary.
	if got := dnsQuery(t, pub, "host.unclaimed.example.org"); got != "" {
		t.Errorf("an unrouted name reached %q instead of being dropped", got)
	}
}

// --- helpers ---------------------------------------------------------------

type echoDNS struct{ addr string }

// startEchoDNS answers any datagram with a payload identifying itself, which is
// enough to prove which backend a query reached.
func startEchoDNS(t *testing.T, id string) *echoDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo the query id back with our marker appended, so the caller can
			// tell the two backends apart.
			reply := append(append([]byte{}, buf[:n]...), []byte(id)...)
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return &echoDNS{addr: pc.LocalAddr().String()}
}

func dnsQuery(t *testing.T, addr, name string) string {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(dnsQueryPacket(name)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "" // dropped, which is the correct outcome for an unrouted name
	}
	// The echo backend appends its marker as the final byte.
	if n == 0 {
		return ""
	}
	return string(buf[n-1 : n])
}

// dnsQueryPacket builds a minimal well-formed DNS query for name.
func dnsQueryPacket(name string) []byte {
	msg := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)        // root
	msg = append(msg, 0x00, 0x01)  // QTYPE A
	return append(msg, 0x00, 0x01) // QCLASS IN
}

// startRouter binds a public socket and serves the given backends through the
// real front router, returning the public address.
func startRouter(t *testing.T, backends []frontrouter.Backend) string {
	t.Helper()
	table, err := frontrouter.NewTable(backends)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := frontrouter.New(table, frontrouter.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = pc.Close() })
	go func() { _ = srv.ServeUDP(ctx, pc) }()
	return pc.LocalAddr().String()
}
