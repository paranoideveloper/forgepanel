package core

// Putting the DNS front router in front of the supervised upstream zones.
//
// THE PROBLEM IT SOLVES. Each upstream zone (stormdns / masterdns / cottendns)
// binds its own UDP_HOST:UDP_PORT. Real resolvers only ever query port 53, so
// exactly one zone could be reachable from the internet: the one an operator
// gave port 53. Every other zone bound a private port and answered nobody. The
// panel reported them all as healthy and running, because they were — they just
// had no path from a resolver.
//
// The front router owns port 53 once and forwards each query to the zone that
// owns the queried name, chosen by longest matching suffix. That makes N tunnel
// zones reachable through the single port the DNS system will actually use.
//
// WHY IT IS OFF BY DEFAULT. Binding port 53 is not something to do behind an
// operator's back, and a host running systemd-resolved already has something
// there. It activates only when there is something for it to do — more than one
// upstream zone on private ports — and it never takes a port the native
// in-process server is already using: a double bind would replace a working
// listener with a failing one.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/forgedns/frontrouter"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

// frontRunner owns the router's sockets and the context that stops it.
type frontRunner struct {
	srv    *frontrouter.Server
	udp    net.PacketConn
	tcp    net.Listener
	cancel context.CancelFunc
}

func (r *frontRunner) stop() {
	if r == nil {
		return
	}
	r.cancel()
	if r.udp != nil {
		_ = r.udp.Close()
	}
	if r.tcp != nil {
		_ = r.tcp.Close()
	}
}

// frontBackends turns supervised zone statuses into router backends.
//
// A zone with no listen address or no domains is skipped rather than guessed
// at: routing a name to the wrong tunnel produces a connection that hangs, and
// a query dropped with a reason in the status is far easier to diagnose than
// traffic arriving somewhere unexpected.
func frontBackends(statuses []upstream.ZoneStatus) ([]frontrouter.Backend, []string) {
	var out []frontrouter.Backend
	var skipped []string
	for _, st := range statuses {
		if len(st.Domains) == 0 {
			skipped = append(skipped, fmt.Sprintf("%s: claims no tunnel domain", st.Zone))
			continue
		}
		udp := strings.TrimSpace(st.Listen)
		if udp == "" {
			skipped = append(skipped, fmt.Sprintf("%s: is not listening yet", st.Zone))
			continue
		}
		// A wildcard bind is not a dial target. Send to loopback instead: the
		// supervised process is on this host, and dialling 0.0.0.0 fails.
		if host, port, err := net.SplitHostPort(udp); err == nil {
			if host == "" || host == "0.0.0.0" || host == "::" {
				udp = net.JoinHostPort("127.0.0.1", port)
			}
		}
		out = append(out, frontrouter.Backend{
			Name:     st.Zone,
			Suffixes: st.Domains,
			UDPAddr:  udp,
			// The upstream adapters expose DNS-over-TCP on the same port when
			// they support it at all; an adapter that does not will simply
			// refuse the connection, which the router reports rather than
			// hanging.
			TCPAddr: udp,
		})
	}
	return out, skipped
}

// samePort reports whether two listen addresses would contend for one UDP port.
// Only the port matters: the native server binds the wildcard, so any host on
// the same port collides with it.
func samePort(a, b string) bool {
	pa, err1 := portOf(a)
	pb, err2 := portOf(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return pa == pb
}

func portOf(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}

// syncFrontRouter (re)builds the front router for the current upstream zones.
//
// Callers hold c.mu. It returns a human-readable status line for the API, so an
// operator can see why the router is or is not running rather than inferring it
// from whether their tunnel works.
func (c *ForgeDNSController) syncFrontRouter(nativeZones int) string {
	if c.up == nil {
		return ""
	}
	statuses := c.up.Status()
	backends, skipped := frontBackends(statuses)

	// Nothing to multiplex. One zone can simply own port 53 itself, which is
	// what it already does, and a router in front of it would only add a hop.
	if len(backends) < 2 {
		c.stopFrontLocked()
		if len(backends) == 1 {
			return "front router idle: only one upstream zone, which can serve port 53 directly"
		}
		return ""
	}

	// The native in-process server binds c.addr whenever there are native zones,
	// so the router cannot have it. Taking the port would replace a working
	// listener with a failing one.
	if nativeZones > 0 {
		c.stopFrontLocked()
		return fmt.Sprintf("front router disabled: the native DNS server holds %s. "+
			"Move the native zones to their own port, or serve them through an upstream adapter, "+
			"to multiplex %d upstream zones on one port.", c.addr, len(backends))
	}

	table, err := frontrouter.NewTable(backends)
	if err != nil {
		c.stopFrontLocked()
		// A duplicate suffix is a configuration mistake with no correct
		// resolution, so the router refuses the whole table rather than
		// silently preferring one zone.
		return "front router not started: " + err.Error()
	}

	// An unchanged table means the running router is already correct; rebinding
	// would drop in-flight queries for no reason.
	sig := strings.Join(table.Routes(), "|")
	if c.frontSig == sig && c.front != nil {
		return c.frontStatusLocked(len(backends), skipped)
	}
	c.stopFrontLocked()

	srv, err := frontrouter.New(table, frontrouter.Options{
		// Per-query failures are counted and surfaced through Status() rather
		// than logged per packet: a public DNS port sees enough junk that
		// per-query logging is its own outage.
		OnError: func(stage string, err error) { c.noteFrontErr(stage, err) },
	})
	if err != nil {
		return "front router not started: " + err.Error()
	}
	udp, err := net.ListenPacket("udp", c.addr)
	if err != nil {
		return fmt.Sprintf("front router could not bind %s/udp: %v", c.addr, err)
	}
	tcp, err := net.Listen("tcp", c.addr)
	if err != nil {
		// UDP alone would answer most queries and silently fail the large ones
		// that fall back to TCP, which is the hardest kind of failure to trace.
		_ = udp.Close()
		return fmt.Sprintf("front router could not bind %s/tcp: %v", c.addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &frontRunner{srv: srv, udp: udp, tcp: tcp, cancel: cancel}
	go func() { _ = srv.ServeUDP(ctx, udp) }()
	go func() { _ = srv.ServeTCP(ctx, tcp) }()

	c.front = run
	c.frontSig = sig
	return c.frontStatusLocked(len(backends), skipped)
}

func (c *ForgeDNSController) frontStatusLocked(n int, skipped []string) string {
	s := fmt.Sprintf("front router on %s multiplexing %d upstream zones", c.addr, n)
	if len(skipped) > 0 {
		s += "; not routed: " + strings.Join(skipped, ", ")
	}
	return s
}

// stopFrontLocked shuts the router down if it is running. Callers hold c.mu.
func (c *ForgeDNSController) stopFrontLocked() {
	if c.front != nil {
		c.front.stop()
		c.front = nil
	}
	c.frontSig = ""
}

// noteFrontErr records the most recent per-query failure.
//
// It uses its OWN lock, deliberately. OnError fires from the serving goroutines,
// including as they wind down — and they wind down inside stopFrontLocked, which
// runs with c.mu already held. Taking c.mu here would deadlock the controller
// the first time a zone was reconfigured while a query was in flight.
func (c *ForgeDNSController) noteFrontErr(stage string, err error) {
	c.frontErrMu.Lock()
	c.frontErr = stage + ": " + err.Error()
	c.frontErrMu.Unlock()
}

func (c *ForgeDNSController) lastFrontErr() string {
	c.frontErrMu.Lock()
	defer c.frontErrMu.Unlock()
	return c.frontErr
}

// FrontRouterStatus reports what the front router is doing, for the API.
func (c *ForgeDNSController) FrontRouterStatus() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]any{"running": c.front != nil, "note": c.frontNote}
	if e := c.lastFrontErr(); e != "" {
		out["last_error"] = e
	}
	if c.front != nil {
		st := c.front.srv.Stats()
		out["addr"] = c.addr
		out["stats"] = st
	}
	return out
}
