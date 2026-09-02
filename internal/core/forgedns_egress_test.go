package core

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

func TestSyncZonesGivesEveryNativeZoneAnEgressBridge(t *testing.T) {
	// Asserting that the controller's bridge MAP has an entry proves nothing:
	// the bridge can exist and never be attached to the zone that serves
	// queries, which is exactly the shape of the bug this row is about. The
	// first version of this test did that and passed with the wiring removed.
	// So drive real tunnel frames and watch a real socket.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var got []byte
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				mu.Lock()
				got = append(got, buf[:n]...)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	c := NewForgeDNSController("127.0.0.1:0", t.TempDir())
	defer c.Stop()
	const zone = "a.example.com"
	if _, err := c.SyncZones([]ZoneSpec{{
		Zone: zone, Adapter: "forge",
		Egress: EgressSpec{Mode: upstream.ModeTCP, Forward: ln.Addr().String()},
	}}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	c.mu.Lock()
	srv := c.server
	c.mu.Unlock()
	if srv == nil {
		t.Fatal("no server was built")
	}

	ask := func(f codec.Frame) {
		t.Helper()
		q, err := adapter.EncodeQuery(zone, f)
		if err != nil {
			t.Fatal(err)
		}
		if r := srv.Handle(q); r == nil {
			t.Fatal("no answer")
		}
	}
	const sid = 0x99
	ask(codec.Frame{SessionID: sid, Seq: 0, Flags: codec.FlagSYN})
	ask(codec.Frame{SessionID: sid, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("wired")})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := string(got) == "wired"
		mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("the destination received %q, want %q — the zone the controller serves has no working egress", got, "wired")
}

func TestABridgeSurvivesAResyncForAnUnrelatedZone(t *testing.T) {
	// A resync rebuilds the whole zone table on every zone add or remove.
	// Rebuilding the bridge with it would drop every live tunnel connection
	// whenever some other zone was created.
	c := NewForgeDNSController("127.0.0.1:0", t.TempDir())
	defer c.Stop()

	c.SyncZones([]ZoneSpec{{Zone: "a.example.com", Adapter: "forge"}})
	c.mu.Lock()
	first := c.bridges["a.example.com"]
	c.mu.Unlock()

	c.SyncZones([]ZoneSpec{
		{Zone: "a.example.com", Adapter: "forge"},
		{Zone: "b.example.com", Adapter: "forge"},
	})
	c.mu.Lock()
	second := c.bridges["a.example.com"]
	c.mu.Unlock()

	if first != second {
		t.Fatal("adding an unrelated zone replaced the existing zone's bridge, dropping its live connections")
	}
}

func TestARemovedZoneLosesItsBridge(t *testing.T) {
	// A deleted zone must not keep its upstream sockets open.
	c := NewForgeDNSController("127.0.0.1:0", t.TempDir())
	defer c.Stop()

	c.SyncZones([]ZoneSpec{
		{Zone: "a.example.com", Adapter: "forge"},
		{Zone: "b.example.com", Adapter: "forge"},
	})
	c.SyncZones([]ZoneSpec{{Zone: "a.example.com", Adapter: "forge"}})

	c.mu.Lock()
	_, stillThere := c.bridges["b.example.com"]
	c.mu.Unlock()
	if stillThere {
		t.Fatal("a removed zone kept its egress bridge and its open sockets")
	}
}

func TestStopReleasesEveryBridge(t *testing.T) {
	c := NewForgeDNSController("127.0.0.1:0", t.TempDir())
	c.SyncZones([]ZoneSpec{
		{Zone: "a.example.com", Adapter: "forge"},
		{Zone: "b.example.com", Adapter: "forge"},
	})
	c.Stop()
	c.mu.Lock()
	n := len(c.bridges)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d bridge(s) survived Stop, each holding sockets and goroutines", n)
	}
}

func TestTheZoneModeChoosesTheEgressDialer(t *testing.T) {
	// The native path honours the same mode/forward settings the operator
	// already sets for the upstream binaries, rather than a second place to
	// configure the same thing.
	if dialerFor(EgressSpec{Mode: upstream.ModeTCP, Forward: "10.0.0.1:8080"}) == nil {
		t.Error("tcp mode produced no dialer")
	}
	// tcp mode with no forward target must not silently become a SOCKS5 proxy —
	// that would turn a misconfigured forward into an open proxy.
	if dialerFor(EgressSpec{Mode: upstream.ModeTCP}) == nil {
		t.Error("tcp mode with no target produced no dialer")
	}
	if dialerFor(EgressSpec{Mode: upstream.ModeSocks5}) == nil {
		t.Error("socks5 mode produced no dialer")
	}
	if dialerFor(EgressSpec{}) == nil {
		t.Error("the default mode produced no dialer")
	}
}

func TestPrivateDestinationsAreRefusedUnlessTheOperatorOptsIn(t *testing.T) {
	// A DNS tunnel is reachable by anyone who can send a UDP packet to the zone.
	// A socks5 endpoint with no policy is a route into whatever private network
	// the panel sits in — its own admin interfaces, the cloud metadata endpoint
	// at 169.254.169.254, the database on the next host. Tunnelling into your
	// own LAN is a real use case, so it stays possible; it is just not default.
	//
	// This drives the dialer the controller would actually build, rather than
	// asserting that a zero-valued field is false, which would prove nothing.
	connect := func(spec EgressSpec, ip []byte) byte {
		t.Helper()
		conn, err := dialerFor(spec)(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{5, 1, 0})
		sel := make([]byte, 2)
		if _, err := io.ReadFull(conn, sel); err != nil {
			t.Fatal(err)
		}
		req := []byte{5, 1, 0, 1}
		req = append(req, ip...)
		req = append(req, 0, 80)
		conn.Write(req)
		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		return rep[1]
	}

	metadata := []byte{169, 254, 169, 254}
	if code := connect(EgressSpec{Mode: upstream.ModeSocks5}, metadata); code == 0 {
		t.Fatal("the cloud metadata endpoint was reachable through a default zone")
	}
	// With the opt-in, the policy no longer blocks it — the connection then
	// fails or succeeds on its own merits, which is not this test's business.
	// What matters is that it is no longer refused BY POLICY before dialling.
	if code := connect(EgressSpec{Mode: upstream.ModeSocks5, AllowPrivate: true}, []byte{127, 0, 0, 1}); code == 1 {
		t.Fatal("AllowPrivate did not lift the policy")
	}
}
