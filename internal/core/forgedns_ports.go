package core

// Giving each upstream tunnel zone a port of its own.
//
// THE BUG THIS FIXES, observed on a live panel with three zones configured:
//
//	1.example.com   UDP_HOST = "203.0.113.10"  UDP_PORT = 53   <- running
//	2.example.com   UDP_HOST = "203.0.113.10"  UDP_PORT = 53   <- dead
//	3.example.com   UDP_HOST = "203.0.113.10"  UDP_PORT = 53   <- dead
//
// Every upstream zone defaults to UDP_PORT 53 (upstream.DefaultUDPPort). The
// first to start binds it; the rest fail waitPortFree and are reported as
// failed. The panel then has exactly one listening backend, and
// syncFrontRouter's "len(backends) < 2" branch decides there is nothing to
// multiplex — so the front router, which exists precisely to fix this, never
// starts. frontrouter's own package comment describes the outcome exactly: "the
// panel can configure any number of tunnel zones and serve exactly one of them
// to the public internet."
//
// The router was written and the allocation that would engage it was not. This
// is that allocation: with more than one upstream zone, each one moves to its
// own loopback port and the router takes the public one.
//
// WHY LOOPBACK. A backend on a private port on the public interface is still
// reachable from the internet by anyone who guesses the port, which quietly
// undoes the routing the front door is there to enforce. The router dials them
// over loopback, so that is where they should listen.
//
// WHY DETERMINISTIC, not "next free port". The rendered config is hashed into
// the supervision signature, so a port that moves between syncs rewrites the
// config, fails the signature comparison and restarts a healthy tunnel on every
// reconcile. Sorting by zone name and counting gives the same zone the same port
// for as long as the set of zones is unchanged.

import (
	"sort"
	"strconv"

	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

const (
	// privateDNSBase is where per-zone loopback DNS ports start. Above the
	// registered range and clear of the ephemeral range Linux allocates from
	// (32768+), so an outbound connection cannot be handed a port a tunnel is
	// about to want.
	privateDNSBase = 15353
	// privateDoTBase / privateDoHBase do the same for the TLS listeners, kept in
	// separate blocks so a zone's three ports are readable at a glance in ss(8).
	privateDoTBase = 15853
	privateDoHBase = 15443
)

// allocatePrivatePorts moves upstream zones off the public ports when there is
// more than one of them, so the front router can hold the public port and
// forward by queried name.
//
// A SINGLE zone is left exactly as it was: it can hold port 53 itself, which is
// what it already does, and putting a router in front of one backend adds a hop
// that can fail and buys nothing. That is the same rule syncFrontRouter applies.
//
// Returns the notes to surface to the operator, because a port that moved
// without explanation is a port the operator will spend an evening looking for.
func allocatePrivatePorts(specs []upstream.Spec) []string {
	if len(specs) < 2 {
		return nil
	}

	// Stable order → stable ports. Sorting a copy of the index rather than the
	// caller's slice: the order specs are supervised in is not ours to change.
	idx := make([]int, len(specs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return specs[idx[a]].Config.Zone < specs[idx[b]].Config.Zone
	})

	var notes []string
	dotSeen, dohSeen := 0, 0
	for n, i := range idx {
		z := &specs[i].Config

		// An operator who deliberately set a non-default port keeps it. They may
		// be pointing an NS delegation at it, and overriding that would break a
		// working zone to tidy up an allocation.
		if z.BindPort == 0 || z.BindPort == upstream.DefaultUDPPort {
			z.BindPort = privateDNSBase + n
			z.BindHost = loopbackHost
			notes = append(notes, z.Zone+": moved to 127.0.0.1:"+strconv.Itoa(z.BindPort)+
				" so the front router can serve it on port 53")
		}

		// The TLS listeners collide the same way, and for the same reason: a DoT
		// client goes to 853 or nowhere. Only zones that actually enable one are
		// moved, and only when more than one does — a lone DoT zone can hold 853.
		if z.DoTListener {
			dotSeen++
		}
		if z.DoHListener {
			dohSeen++
		}
	}

	if dotSeen > 1 || dohSeen > 1 {
		dotN, dohN := 0, 0
		for _, i := range idx {
			z := &specs[i].Config
			if z.DoTListener && dotSeen > 1 && (z.DoTPort == 0 || z.DoTPort == publicDoTPort) {
				z.DoTPort = privateDoTBase + dotN
				notes = append(notes, z.Zone+": DoT moved to 127.0.0.1:"+strconv.Itoa(z.DoTPort)+
					" so the front router can serve DoT on 853")
			}
			if z.DoTListener {
				dotN++
			}
			if z.DoHListener && dohSeen > 1 && (z.DoHPort == 0 || z.DoHPort == publicDoHPort) {
				z.DoHPort = privateDoHBase + dohN
				notes = append(notes, z.Zone+": DoH moved to 127.0.0.1:"+strconv.Itoa(z.DoHPort)+
					" so the front router can serve DoH on 443")
			}
			if z.DoHListener {
				dohN++
			}
		}
	}
	return notes
}

// loopbackHost is where a fronted backend listens. Named rather than inlined so
// the reason travels with it: see the package comment above.
const loopbackHost = "127.0.0.1"
