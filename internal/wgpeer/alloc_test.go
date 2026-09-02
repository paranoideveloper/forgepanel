package wgpeer

import (
	"net/netip"
	"testing"
	"time"
)

func mustPool(t *testing.T, cidr string) *Pool {
	t.Helper()
	p, err := NewPool(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAllocatesTheLowestFreeAddress(t *testing.T) {
	// Lowest-free rather than random, so an operator reading `wg show` sees a
	// contiguous block in the order clients were added — which is what makes an
	// unexpected peer obvious.
	p := mustPool(t, "10.66.66.1/24")
	got, err := p.Allocate(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.66.66.2" {
		t.Fatalf("got %s, want 10.66.66.2 (.0 is the network, .1 is the server)", got)
	}
}

func TestNeverHandsOutTheServersOwnAddress(t *testing.T) {
	// A client given the server's tunnel IP does not fail loudly: it collides,
	// and the tunnel behaves erratically for everyone on it.
	p := mustPool(t, "10.66.66.5/24")
	now := time.Now()
	var taken []Reservation
	for i := 0; i < 20; i++ {
		a, err := p.Allocate(taken, now)
		if err != nil {
			t.Fatal(err)
		}
		if a.String() == "10.66.66.5" {
			t.Fatal("the server's own address was allocated to a client")
		}
		taken = append(taken, Reservation{Addr: a})
	}
}

func TestSkipsTheNetworkAndBroadcastAddresses(t *testing.T) {
	// Handing out the broadcast address produces a peer some stacks answer for
	// and others drop — an intermittent fault nobody would trace back to address
	// allocation.
	p := mustPool(t, "10.0.0.1/29") // .0 network, .7 broadcast, .1 server
	now := time.Now()
	var taken []Reservation
	var got []string
	for {
		a, err := p.Allocate(taken, now)
		if err != nil {
			break
		}
		got = append(got, a.String())
		taken = append(taken, Reservation{Addr: a})
	}
	want := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAReleasedAddressIsHeldBackForTheCooldown(t *testing.T) {
	// The failure this prevents: a peer is removed and its address goes straight
	// to someone else, while the fleet and the server's routing table still
	// believe the old owner is there. Packets for the new client match the old
	// peer's AllowedIPs and land on the wrong tunnel.
	p := mustPool(t, "10.66.66.1/24")
	now := time.Now()
	released := Reservation{Addr: addr(t, "10.66.66.2"), ReleasedAt: now.Add(-time.Minute)}

	got, err := p.Allocate([]Reservation{released}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() == "10.66.66.2" {
		t.Fatal("an address released a minute ago was reissued immediately")
	}

	// Past the cooldown it becomes available again — otherwise a busy panel
	// leaks its address space one departed user at a time.
	later := now.Add(ReuseCooldown + time.Minute)
	got, err = p.Allocate([]Reservation{released}, later)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.66.66.2" {
		t.Fatalf("got %s; the address should be reusable after the cooldown", got)
	}
}

func TestAnAddressStillInUseIsNeverReissued(t *testing.T) {
	// ReleasedAt zero means "a live peer holds this". No amount of elapsed time
	// makes it free.
	p := mustPool(t, "10.66.66.1/24")
	live := Reservation{Addr: addr(t, "10.66.66.2")}
	got, err := p.Allocate([]Reservation{live}, time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() == "10.66.66.2" {
		t.Fatal("an address held by a live peer was handed to a second client")
	}
}

func TestAFullPoolSaysSoRatherThanCollidingS(t *testing.T) {
	p := mustPool(t, "10.0.0.1/30") // .0 network, .1 server, .2 usable, .3 broadcast
	now := time.Now()
	first, err := p.Allocate(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Allocate([]Reservation{{Addr: first}}, now)
	if err == nil {
		t.Fatal("a second address was allocated from a range with room for one")
	}
	if err != ErrPoolExhausted {
		t.Fatalf("got %v, want ErrPoolExhausted", err)
	}
}

func TestAPrefixWithNoRoomIsRejectedAtConstruction(t *testing.T) {
	// Returning an empty pool would read as "the server is full" rather than
	// "this inbound was configured with room for nobody".
	for _, bad := range []string{"10.0.0.1/32", "10.0.0.1/31", "fd00::1/128", "fd00::1/127"} {
		if _, err := NewPool(bad); err == nil {
			t.Errorf("%s was accepted as an allocation range", bad)
		}
	}
	for _, ok := range []string{"10.0.0.1/30", "10.66.66.1/24", "fd00::1/64"} {
		if _, err := NewPool(ok); err != nil {
			t.Errorf("%s was rejected: %v", ok, err)
		}
	}
}

func TestABareAddressIsRejected(t *testing.T) {
	// "10.66.66.1" with no prefix carries no range, so there is nothing to
	// allocate from; accepting it and guessing /24 would invent a subnet the
	// operator never agreed to.
	if _, err := NewPool("10.66.66.1"); err == nil {
		t.Fatal("an address with no prefix was accepted")
	}
}

func TestIPv6PoolsWork(t *testing.T) {
	p := mustPool(t, "fd00:66::1/64")
	got, err := p.Allocate(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Is6() {
		t.Fatalf("got %s, want an IPv6 address", got)
	}
	if got.String() == "fd00:66::1" {
		t.Fatal("the server's own address was allocated")
	}
}

func TestHostCIDRPinsASingleAddress(t *testing.T) {
	// /32, not the server's prefix. A client whose Address carries the whole /24
	// claims the tunnel subnet as on-link and stops routing to other peers
	// through the server; on the server side, AllowedIPs wider than one host
	// lets a peer receive its neighbours' traffic.
	if got := HostCIDR(addr(t, "10.66.66.7")); got != "10.66.66.7/32" {
		t.Fatalf("got %q", got)
	}
	if got := HostCIDR(addr(t, "fd00::7")); got != "fd00::7/128" {
		t.Fatalf("got %q", got)
	}
}

func TestAllocationIsStableAcrossCalls(t *testing.T) {
	// Two concurrent allocations that see the same reservations must not both
	// be told the same address is free — the caller serialises, and this pins
	// that the pool itself is deterministic so serialising is sufficient.
	p := mustPool(t, "10.66.66.1/24")
	now := time.Now()
	a1, _ := p.Allocate(nil, now)
	a2, _ := p.Allocate(nil, now)
	if a1 != a2 {
		t.Fatalf("the same inputs gave %s then %s", a1, a2)
	}
}
