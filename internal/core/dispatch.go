package core

// Reload dispatch, driven by the adapter registry.
//
// WHAT THIS REPLACES. ReloadSpecs used to enumerate the cores by hand: an
// if-block for Xray, another for sing-box, a filter loop for Brook, another for
// AmneziaWG — and EnsureBinaries, StopAll and Status each enumerated them again
// in their own switch. Adding a core meant finding all of them, and missing one
// produced an inbound that generated a config but was never started, or was
// started and never stopped. internal/core/adapter was built to end that, with
// four working adapters and a conformance suite, and then was never imported
// outside its own tests: the panel kept the hand-written switches and the seam
// shipped to nobody.
//
// WHY IT IS SAFE. Splitting one reload across adapters only works if giving
// engine.BuildMulti a subset of the inbounds produces the same bytes as giving
// it all of them and taking one core's half. It does, and
// TestBuildMultiSubsetMatchesTheCombinedBuild pins it — without that property
// this would be a change to what every core is served, not a refactor.
//
// WHAT IS DELIBERATELY PRESERVED. Two behaviours here look like inconsistencies
// and are not:
//
//   - AmneziaWG failures never fail a reload. It is a KERNEL facility; a host
//     without the module cannot run it, and that must not stop every Xray and
//     sing-box inbound on the box from being served. The error is recorded and
//     surfaced through AWGStatus, which is where an operator looks for it.
//   - Status() reports only cores that have something to serve. A core with an
//     empty plan is not "stopped and broken", it is not in use, and listing it
//     would put permanent grey rows in the panel for every core an operator
//     never touched.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/forgepanel/forgepanel/internal/core/adapter"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// bestEffortEngines are cores whose failure must not fail the whole reload.
//
// Only AmneziaWG qualifies, and only because it is the one core whose
// unavailability is a property of the HOST rather than of the configuration: no
// kernel module means it can never run here, and failing the reload would take
// every other inbound down with it for a condition the operator may not be able
// to fix. A config-level failure in any other core is a real failure and is
// reported as one.
var bestEffortEngines = map[string]bool{
	model.EngineAmneziaWG: true,
}

// buildRegistry constructs the adapter registry this controller dispatches
// through. Brook and AmneziaWG are passed as runners because their reconcilers
// live here, in internal/core, which the adapter package must not import.
func (c *Controller) buildRegistry() (*adapter.Registry, error) {
	return adapter.DefaultRegistry(adapter.Options{
		DataDir:     c.dataDir,
		XrayAPIPort: c.xrayAPIPort,
		Bins:        c.bins,
		// GenerateConfig has no Plan to carry a certificate, so it asks here.
		// Apply always uses the Plan's paths instead.
		Certs: func() (string, string) {
			cp, kp, _ := ensureSelfSignedFor(c.dataDir)
			return cp, kp
		},
		// Every line the core writes is offered to the presence tracker. The
		// generated Xray config sends its access log to stdout precisely so this
		// works with no log file to rotate and no connection metadata on disk.
		OnEngineLine: c.presence.ObserveLine(LocalNodeName),
		// Only Xray. A user mutation used to restart BOTH cores and drop every
		// connection on them; where the change is nothing but which users exist,
		// Xray can take it on the running instance instead.
		HotApply: map[string]func(old, next []byte) (bool, error){
			model.EngineXray: c.xrayHotApply,
		},
		// Both supervised cores, because a supervisor that watches only the
		// process table cannot tell a working core from a wedged one — and a
		// wedged one is reported green, restarts nothing, and serves nobody
		// until a human notices. See internal/core/probe.go.
		Probe: map[string]func(context.Context) error{
			model.EngineXray:    c.probeXrayAPI,
			model.EngineSingBox: c.probeSingboxAPI,
		},
		// The geodata that ships in Xray's own archive was being discarded by
		// the installer, so every geosite:/geoip: rule failed with "code not
		// found in geosite.dat" — taking the whole config, and therefore every
		// inbound, down. It is installed now, and pointed at explicitly so the
		// core cannot silently fall back to a stale system-wide copy.
		EngineEnv: map[string][]string{
			model.EngineXray: {"XRAY_LOCATION_ASSET=" + c.bins.GeoAssetDir(binmgr.EngineXray)},
		},
	}, c.brook, c.awg)
}

// dispatch applies each adapter's share of a reload.
//
// Callers hold c.mu. It returns the engines that were given something to serve,
// and the first failure that should fail the reload.
func (c *Controller) dispatch(specs []engine.InboundSpec, certPath, keyPath string) (active map[string]bool, unroutable []adapter.Unroutable, err error) {
	if c.registry == nil {
		// Reached only if the registry failed to build at startup. Serving
		// nothing is the correct outcome, but it must be reported: silently
		// applying no configuration would look like a panel with no inbounds.
		return nil, nil, c.regErr
	}
	plans, unroutable := c.registry.Partition(specs, certPath, keyPath)
	active = make(map[string]bool, len(plans))

	ctx := context.Background()
	var firstErr error
	var bestEffortErrs []string

	for _, ap := range plans {
		if !ap.Plan.Empty() {
			active[ap.Engine] = true
		}
		// EVERY adapter is applied, including one with an empty plan. An
		// adapter whose last inbound was just deleted has to be told, or its
		// core keeps serving inbounds the panel no longer knows about — which
		// is precisely how a deleted inbound stays alive.
		if applyErr := ap.Adapter.Apply(ctx, ap.Plan); applyErr != nil {
			if bestEffortEngines[ap.Engine] {
				bestEffortErrs = append(bestEffortErrs, ap.Engine+": "+applyErr.Error())
				continue
			}
			// Keep reconciling the remaining cores. Returning here would leave
			// them running a configuration the panel has already replaced,
			// which is a worse state than the one failure being reported.
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ap.Engine, applyErr)
			}
		}
	}

	c.lastBestEffortErr = strings.Join(bestEffortErrs, "; ")
	return active, unroutable, firstErr
}

// ensureBinariesLocked downloads the cores the given inbounds actually need.
//
// It asks the registry which adapter serves each inbound rather than switching
// on the engine name, so a core added to the registry is fetched without
// touching this function. Each adapter then decides whether it has anything to
// install: a core that does not implement adapter.Provisionable runs from the
// host — AmneziaWG's kernel module and awg-quick — and that is a normal state
// rather than an error.
//
// An inbound nothing can serve is skipped here and reported by the reload.
// Refusing to fetch anything because one inbound is unroutable would block the
// other twenty from starting.
//
// It takes no lock and needs none: registry, regErr and bins are all set once in
// the constructor and never reassigned, so this is safe both from ReloadSpecs
// (which holds c.mu) and from an external EnsureBinaries call (which does not).
func (c *Controller) ensureBinariesFor(nodes []*model.Node) error {
	if c.registry == nil {
		return c.regErr
	}
	need := map[string]bool{}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		res, err := c.registry.ResolveNode(n)
		if err != nil {
			continue // reported by the reload, not fatal to the fetch step
		}
		need[res.Engine] = true
	}
	// Deterministic order, so a failure reproduces the same way twice.
	names := make([]string, 0, len(need))
	for name := range need {
		names = append(names, name)
	}
	sort.Strings(names)
	ctx := context.Background()
	for _, name := range names {
		a, ok := c.registry.Lookup(name)
		if !ok {
			continue
		}
		p, ok := a.(adapter.Provisionable)
		if !ok {
			// Nothing to fetch — AmneziaWG's kernel module. A normal state.
			continue
		}
		if err := p.Provision(ctx); err != nil {
			return err
		}
	}
	return nil
}

// adapterStatuses maps adapter health onto the supervisor status shape the API
// has always returned, so this refactor is invisible to every consumer.
//
// Only engines with something to serve are reported; see the package note.
func (c *Controller) adapterStatuses(active map[string]bool) []supervisor.Status {
	if c.registry == nil {
		return nil
	}
	ctx := context.Background()
	var out []supervisor.Status
	for _, a := range c.registry.All() {
		if !active[a.Name()] {
			continue
		}
		h, err := a.HealthCheck(ctx)
		if err != nil {
			out = append(out, supervisor.Status{
				Engine: a.Name(), State: supervisor.StateCrashed, LastError: err.Error(),
			})
			continue
		}
		out = append(out, supervisor.Status{
			Engine:     h.Engine,
			State:      supervisor.State(h.State),
			PID:        h.PID,
			Restarts:   h.Restarts,
			LastError:  h.LastError,
			RecentLogs: h.RecentLogs,
			// Forwarded so the probe's verdict reaches /api/admin/engines/status
			// too. Without this the only place a wedged core showed up would be
			// the state string, with no reason attached.
			Responsive:     h.Responsive,
			LastProbeError: h.LastProbeError,
		})
	}
	return out
}
