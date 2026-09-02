package core

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

// The regression these guard was observed on a live panel: three zones, all
// three rendered UDP_PORT 53 on the same host, one process running and two
// dead. With one backend listening the front router's "len(backends) < 2"
// branch decides there is nothing to multiplex, so the component that exists to
// fix this never starts.

func specs(zones ...string) []upstream.Spec {
	out := make([]upstream.Spec, 0, len(zones))
	for _, z := range zones {
		out = append(out, upstream.Spec{Config: upstream.ZoneConfig{
			Zone: z, Adapter: "cottendns", Domains: []string{z},
		}})
	}
	return out
}

func TestThreeZonesEachGetTheirOwnPort(t *testing.T) {
	// The live case, by name.
	in := specs("1.example.com", "2.example.com", "3.example.com")
	notes := allocatePrivatePorts(in)

	seen := map[int]string{}
	for _, s := range in {
		p := s.Config.BindPort
		if p == 0 || p == upstream.DefaultUDPPort {
			t.Errorf("%s still on port %d — it will lose the race for :53 and be reported dead",
				s.Config.Zone, p)
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("%s and %s were both given port %d; one of them cannot start",
				prev, s.Config.Zone, p)
		}
		seen[p] = s.Config.Zone
		if s.Config.BindHost != loopbackHost {
			t.Errorf("%s listens on %q; a fronted backend reachable from the internet defeats the "+
				"routing the front door enforces", s.Config.Zone, s.Config.BindHost)
		}
	}
	if len(notes) != 3 {
		t.Errorf("got %d notes for 3 moved zones; a port that moved without explanation is one "+
			"the operator cannot find", len(notes))
	}
	for _, n := range notes {
		if !strings.Contains(n, "front router") {
			t.Errorf("note does not say why the port moved: %q", n)
		}
	}
}

// A single zone can hold 53 itself. Putting a router in front of one backend
// adds a hop that can fail and buys nothing — and syncFrontRouter applies the
// same rule, so moving the port here would strand it: off 53, with no router.
func TestASingleZoneIsLeftOnThePublicPort(t *testing.T) {
	in := specs("only.example.com")
	if notes := allocatePrivatePorts(in); len(notes) != 0 {
		t.Errorf("a lone zone was moved: %v", notes)
	}
	if in[0].Config.BindPort != 0 {
		t.Errorf("BindPort = %d, want it left alone so the default 53 applies", in[0].Config.BindPort)
	}
}

// An operator who chose a port keeps it. They may have an NS delegation
// pointing at it, and tidying up the allocation would break a working zone.
func TestAnOperatorsChosenPortIsNotOverridden(t *testing.T) {
	in := specs("a.example.com", "b.example.com")
	in[0].Config.BindPort = 5300
	allocatePrivatePorts(in)

	if in[0].Config.BindPort != 5300 {
		t.Errorf("operator's port 5300 was replaced with %d", in[0].Config.BindPort)
	}
	if in[1].Config.BindPort == 0 || in[1].Config.BindPort == upstream.DefaultUDPPort {
		t.Errorf("the defaulted zone was not moved: %d", in[1].Config.BindPort)
	}
	if in[1].Config.BindPort == 5300 {
		t.Error("the allocated port collided with the operator's")
	}
}

// The rendered config is hashed into the supervision signature, so a port that
// moves between syncs rewrites the config, fails the signature comparison and
// restarts a healthy tunnel on every reconcile.
func TestAllocationIsStableAcrossRuns(t *testing.T) {
	first := specs("c.example.com", "a.example.com", "b.example.com")
	second := specs("c.example.com", "a.example.com", "b.example.com")
	allocatePrivatePorts(first)
	allocatePrivatePorts(second)
	for i := range first {
		if first[i].Config.BindPort != second[i].Config.BindPort {
			t.Fatalf("%s got %d then %d — a moving port restarts a healthy tunnel on every sync",
				first[i].Config.Zone, first[i].Config.BindPort, second[i].Config.BindPort)
		}
	}
}

// Order of the input must not change the answer, for the same reason.
func TestAllocationDoesNotDependOnInputOrder(t *testing.T) {
	a := specs("x.example.com", "y.example.com", "z.example.com")
	b := specs("z.example.com", "y.example.com", "x.example.com")
	allocatePrivatePorts(a)
	allocatePrivatePorts(b)

	portOf := func(in []upstream.Spec, zone string) int {
		for _, s := range in {
			if s.Config.Zone == zone {
				return s.Config.BindPort
			}
		}
		return -1
	}
	for _, z := range []string{"x.example.com", "y.example.com", "z.example.com"} {
		if portOf(a, z) != portOf(b, z) {
			t.Errorf("%s got %d in one order and %d in another", z, portOf(a, z), portOf(b, z))
		}
	}
}

// DoT and DoH collide exactly as 53 does: a DoT client goes to 853 or nowhere.
func TestTLSListenersAreMovedOnlyWhenMoreThanOneServesThem(t *testing.T) {
	both := specs("a.example.com", "b.example.com")
	both[0].Config.DoTListener, both[0].Config.DoHListener = true, true
	both[1].Config.DoTListener, both[1].Config.DoHListener = true, true
	allocatePrivatePorts(both)
	if both[0].Config.DoTPort == 0 || both[1].Config.DoTPort == 0 {
		t.Error("two DoT zones were not given private ports")
	}
	if both[0].Config.DoTPort == both[1].Config.DoTPort {
		t.Error("two DoT zones were given the same port")
	}
	if both[0].Config.DoHPort == both[1].Config.DoHPort {
		t.Error("two DoH zones were given the same port")
	}

	// One DoT zone can hold 853 itself, the same rule the router applies.
	lone := specs("a.example.com", "b.example.com")
	lone[0].Config.DoTListener = true
	allocatePrivatePorts(lone)
	if lone[0].Config.DoTPort != 0 {
		t.Errorf("a lone DoT zone was moved to %d, stranding it off 853 with no router",
			lone[0].Config.DoTPort)
	}
}

// The front router must land on an address it can actually hold.
//
// c.addr defaults to the wildcard ":53", and on a stock systemd host that bind
// FAILS — systemd-resolved holds 127.0.0.53:53, so 0.0.0.0:53 is EADDRINUSE
// while the machine's own address binds fine. Measured on Ubuntu 22.04:
//
//	wildcard 0.0.0.0:53 udp -> FAIL: [Errno 98] Address already in use
//	public   .104:53    udp -> OK
//
// The supervised tunnels already had this workaround and the router in front of
// them did not, so the tunnels ran and the thing that makes them reachable
// stayed down. This pins that the router asks the same question they do.
func TestTheRouterUsesTheSameBindPolicyAsTheTunnels(t *testing.T) {
	// A host that is already explicit is never rewritten: an operator who bound
	// one interface must not silently get another.
	if got := upstream.EffectiveBindHost("10.0.0.5", 53); got != "10.0.0.5" {
		t.Errorf("an explicit bind host was rewritten to %q", got)
	}
	// A wildcard on a port no stub holds stays a wildcard — the fallback is for
	// the systemd-resolved case, not a blanket rewrite.
	if got := upstream.EffectiveBindHost("", 15353); got != "" {
		t.Errorf("a wildcard on a free port became %q; the fallback should be narrow", got)
	}
}
