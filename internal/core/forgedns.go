package core

import (
	"fmt"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	fdnsserver "github.com/forgepanel/forgepanel/internal/forgedns/server"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
)

// ForgeDNSController is the panel-facing manager for the DNS-tunnel subsystem
// (spec §5). The API layer calls SyncZones whenever a zone is created, enabled,
// or deleted; the controller (re)builds the authoritative server's zone table
// and starts the UDP listener on first use. Everything is driven from the panel
// — no terminal, no manual install.
//
// There are two zone implementations behind one controller:
//
//   - native  (adapter `forge` / `native` / empty): the panel's own codec, served
//     in-process by internal/forgedns/server on c.addr;
//   - upstream (adapter `stormdns` / `masterdns` / `cottendns`): the real
//     upstream binary, fetched and supervised per zone by the upstream manager
//     (docs/FORGEDNS_UPSTREAM_SETUP.md §4). Those zones bind their own
//     UDP_HOST/UDP_PORT and never touch the in-process listener.
type ForgeDNSController struct {
	addr string
	up   *upstream.Manager // real-binary zones; nil when no data dir is configured

	mu       sync.Mutex
	server   *fdnsserver.Server
	sessions map[string]*session.Manager // zone -> session manager (persists across resyncs)
	started  bool
	lastErr  string
	upErr    string
}

// NewForgeDNSController builds a controller that will listen on addr (e.g.
// ":53") for native zones and keep upstream zone state under dataDir.
func NewForgeDNSController(addr, dataDir string) *ForgeDNSController {
	c := &ForgeDNSController{addr: addr, sessions: map[string]*session.Manager{}}
	if dataDir != "" {
		c.up = upstream.NewManager(dataDir)
	}
	return c
}

// ZoneSpec is a panel-managed zone the controller should serve. Upstream is set
// only for real-binary adapters and carries everything that path needs.
type ZoneSpec struct {
	Zone     string
	Adapter  string
	Upstream *upstream.Spec
}

// Upstream exposes the real-binary manager (bundles, explicit installs, health).
func (c *ForgeDNSController) Upstream() *upstream.Manager { return c.up }

// Stop shuts down the native listener and every supervised upstream zone.
func (c *ForgeDNSController) Stop() {
	c.mu.Lock()
	srv := c.server
	c.server = nil
	c.started = false
	up := c.up
	c.mu.Unlock()
	if srv != nil {
		_ = srv.Shutdown()
	}
	if up != nil {
		up.StopAll()
	}
}

// SyncZones rebuilds the served zone set from the panel's enabled zones and
// ensures the listener is running if there is at least one native zone. Upstream
// zones are reconciled by their own supervisor. Returns the zone names now
// served (both kinds).
func (c *ForgeDNSController) SyncZones(specs []ZoneSpec) ([]string, error) {
	// Split by implementation: an upstream adapter name must never fall through
	// to the native registry, where the same three names exist as panel-internal
	// wire variants.
	var native, ups []ZoneSpec
	for _, sp := range specs {
		if upstream.IsUpstream(sp.Adapter) {
			ups = append(ups, sp)
			continue
		}
		native = append(native, sp)
	}
	// Reconcile upstream zones BEFORE taking the controller lock: that path may
	// download a release from GitHub, and Status() must stay responsive.
	served := c.syncUpstream(ups)

	c.mu.Lock()
	defer c.mu.Unlock()
	srv := fdnsserver.New()
	for _, sp := range native {
		name := sp.Adapter
		if name == "" || name == "native" {
			name = "forge"
		}
		ad, err := adapter.Get(name)
		if err != nil {
			c.lastErr = err.Error()
			continue
		}
		mgr := c.sessions[sp.Zone]
		if mgr == nil {
			mgr = session.NewManager(60 * time.Second)
			c.sessions[sp.Zone] = mgr
		}
		srv.AddZone(&fdnsserver.Zone{Name: sp.Zone, Adapter: ad, Sessions: mgr})
		served = append(served, sp.Zone)
	}
	// Swap in the new server. (miekg/dns has no live zone-hot-swap, so we run a
	// single mux server and replace its zone table by replacing the server; the
	// UDP socket is re-bound only when starting the first time.)
	old := c.server
	c.server = srv

	if len(native) == 0 {
		if old != nil {
			_ = old.Shutdown()
			c.started = false
		}
		return served, nil
	}
	if !c.started {
		go func() {
			if err := srv.ListenAndServe(c.addr); err != nil {
				c.mu.Lock()
				c.lastErr = err.Error()
				c.started = false
				c.mu.Unlock()
			}
		}()
		c.started = true
	} else if old != nil {
		// Restart the listener bound to the new zone table.
		_ = old.Shutdown()
		go func() { _ = srv.ListenAndServe(c.addr) }()
	}
	return served, nil
}

// Sessions returns live session metrics for a zone (streamed to the UI, §5.3).
func (c *ForgeDNSController) Sessions(zone string) []session.Metrics {
	c.mu.Lock()
	mgr := c.sessions[zone]
	c.mu.Unlock()
	if mgr == nil {
		return nil
	}
	return mgr.Snapshot()
}

// Status reports the listener state and any last error, plus the supervised
// upstream zones so the UI shows one status for both zone kinds.
func (c *ForgeDNSController) Status() map[string]any {
	c.mu.Lock()
	zones := []string{}
	if c.server != nil {
		zones = c.server.Zones()
	}
	out := map[string]any{
		"listening": c.started, "addr": c.addr, "zones": zones,
		"last_error": c.lastErr, "upstream_error": c.upErr,
	}
	up := c.up
	c.mu.Unlock()
	if up != nil {
		out["upstream"] = up.Status()
	} else {
		out["upstream"] = []upstream.ZoneStatus{}
	}
	return out
}

// syncUpstream reconciles the real-binary zones and returns the ones accepted.
// It must NOT be called with c.mu held (it downloads). Failures are recorded
// rather than returned so one bad zone (no delegation yet, :53 held, GitHub
// unreachable) cannot stop the others.
func (c *ForgeDNSController) syncUpstream(specs []ZoneSpec) []string {
	if c.up == nil {
		if len(specs) > 0 {
			c.setUpErr("forgedns: no data directory configured for upstream adapters")
		}
		return nil
	}
	out := make([]upstream.Spec, 0, len(specs))
	served := make([]string, 0, len(specs))
	msg := ""
	for _, sp := range specs {
		if sp.Upstream == nil {
			msg = fmt.Sprintf("forgedns: zone %s has an upstream adapter but no upstream config", sp.Zone)
			continue
		}
		out = append(out, *sp.Upstream)
		served = append(served, sp.Zone)
	}
	if err := c.up.Sync(out); err != nil {
		msg = err.Error()
	}
	c.setUpErr(msg)
	return served
}

func (c *ForgeDNSController) setUpErr(msg string) {
	c.mu.Lock()
	c.upErr = msg
	c.mu.Unlock()
}

// UpstreamTag reports the release tag a supervised zone is running, so the API
// can pin it back into panel state after the first install.
func (c *ForgeDNSController) UpstreamTag(zone string) string {
	c.mu.Lock()
	up := c.up
	c.mu.Unlock()
	if up == nil {
		return ""
	}
	return up.Tag(zone)
}

// EvictIdle sweeps idle sessions across all zones and expires downstream chunks
// the client never acknowledged (called by the scheduler). Expiring an in-flight
// chunk does not discard it — the bytes stay queued and the next poll re-sends
// them; it only releases the retransmission copy for an abandoned session.
func (c *ForgeDNSController) EvictIdle() int {
	c.mu.Lock()
	mgrs := make([]*session.Manager, 0, len(c.sessions))
	for _, m := range c.sessions {
		mgrs = append(mgrs, m)
	}
	c.mu.Unlock()
	n := 0
	for _, m := range mgrs {
		m.ExpireInFlight()
		n += m.EvictIdle()
	}
	return n
}

// SessionCounters returns the transport's failure-mode counters per zone
// (retransmissions, duplicate queries, invalid sequences, expired frames,
// authentication failures and session-table pressure), so the panel can show
// whether the tunnel is healthy rather than only that it is running.
func (c *ForgeDNSController) SessionCounters() map[string]session.Counters {
	c.mu.Lock()
	mgrs := make(map[string]*session.Manager, len(c.sessions))
	for z, m := range c.sessions {
		mgrs[z] = m
	}
	c.mu.Unlock()
	out := make(map[string]session.Counters, len(mgrs))
	for z, m := range mgrs {
		out[z] = m.Counters()
	}
	return out
}

var _ = fmt.Sprintf
