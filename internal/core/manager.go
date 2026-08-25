// Package core ties the binary manager, config aggregator and supervisor
// together into the panel-facing engine controller (spec §6). The API layer
// calls Reload whenever inbounds change; the controller regenerates each engine
// config, validates it with the engine's own `-test`/`check`, and hot-applies it
// only if valid.
package core

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/core/adapter"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/core/porthop"
	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Controller supervises the proxy cores for a panel instance.
type Controller struct {
	dataDir     string
	xrayAPIPort int
	bins        *binmgr.Manager

	// mMalformedStats counts engine traffic counters that failed to parse, so
	// degraded accounting is visible rather than looking like flat usage.
	mMalformedStats atomic.Int64

	// certFor resolves a real certificate for an inbound's SNI. Nil means "no
	// certificate store wired", and every TLS inbound then falls back to the
	// self-signed pair -- which is exactly what happened for every inbound
	// before this existed, even when the panel held a valid Let's Encrypt
	// certificate for the same name.
	certFor func(sni string) (certPath, keyPath string, ok bool)

	// registry is the single dispatch table: which core serves which inbound.
	// It replaces the per-core if-blocks that ReloadSpecs, EnsureBinaries,
	// StopAll and Status each maintained separately. regErr records a registry
	// that could not be built, so the failure surfaces at the next reload rather
	// than as a nil dereference.
	registry *adapter.Registry
	regErr   error

	// sing-box per-user metering depends on how the installed binary was built,
	// so it is detected once from the binary itself rather than assumed.
	sbStatsOnce sync.Once
	sbStats     SingboxStatsSupport
	// sbAPIPort is the loopback port the generated sing-box config exposes its
	// v2ray stats API on. Zero disables it, which is what happens when the
	// binary cannot report counters anyway.
	sbAPIPort    int
	sbStatsErrMu sync.Mutex
	sbStatsErr   string

	mu      sync.Mutex
	brook   *BrookManager
	awg     *AWGManager
	porthop *porthop.Manager
	// active is the set of engines the last reload gave something to serve, so
	// Status() reports exactly the cores in use — as it always has.
	active            map[string]bool
	lastPortHopErr    string
	lastBestEffortErr string
	lastBundle        *engine.Bundle
}

// NewController builds a controller rooted at dataDir. Binaries are resolved
// lazily on first Reload so a panel with no inbounds never downloads a core.
func NewController(dataDir string, xrayAPIPort int) *Controller {
	bins := binmgr.New(dataDir)
	// Reap orphaned engine processes left by a previously-killed panel instance:
	// they still hold their listen ports and would make the fresh start fail to
	// bind ("address already in use"). Safe at startup — none of our engines are
	// running yet, so anything under our bin dir is a stray.
	reapStrayEngines(bins.BinDir)
	c := &Controller{
		dataDir: dataDir, xrayAPIPort: xrayAPIPort, bins: bins,
		brook: NewBrookManager(bins), awg: NewAWGManager(dataDir), porthop: porthop.New(),
	}
	// Built once. A failure here is stored rather than panicked on: the panel
	// still has to start so an operator can reach the UI and see why.
	// Per-user metering for the sing-box protocols is only possible when the
	// installed binary was built with with_v2ray_api. Enabling the config
	// section on a binary that cannot serve it is a STARTUP failure, which would
	// take every sing-box inbound down rather than merely leaving them
	// unmetered — so the port is only published when the capability is real.
	if c.SingboxStatsSupported().Supported {
		c.sbAPIPort = xrayAPIPort + 1
	}
	engine.SingboxAPIPort = c.sbAPIPort
	c.registry, c.regErr = c.buildRegistry()
	return c
}

// ensureSelfSignedFor returns the panel's self-signed pair under a data dir. It
// exists so the registry's Certs hook and ReloadSpecs cannot disagree about
// where that certificate lives.
func ensureSelfSignedFor(dataDir string) (string, string, error) {
	return cert.EnsureSelfSigned(filepath.Join(dataDir, "certs"))
}

// Registry exposes the adapter registry, so the API can report which core
// serves which protocol instead of the panel and the operator guessing.
func (c *Controller) Registry() *adapter.Registry { return c.registry }

// SetCertResolver wires the certificate store into config generation, so an
// inbound whose SNI the panel holds a real certificate for is served with that
// certificate instead of the self-signed fallback.
//
// It is a function rather than a store handle to keep internal/core from
// depending on internal/cert's shape, and so a build can never block on
// issuance: the resolver is a pure cache read.
func (c *Controller) SetCertResolver(fn func(sni string) (string, string, bool)) {
	c.mu.Lock()
	c.certFor = fn
	c.mu.Unlock()
}

// applyCerts fills in each spec's real certificate where one exists. Specs with
// no match keep empty paths and fall through to the self-signed pair.
//
// Callers hold c.mu, so this reads c.certFor directly.
func (c *Controller) applyCerts(specs []engine.InboundSpec) {
	if c.certFor == nil {
		return
	}
	for i := range specs {
		n := specs[i].Node
		if n == nil {
			continue
		}
		// Only a TLS-terminating inbound has a certificate to serve. REALITY
		// deliberately has none -- it borrows another site's -- and handing it
		// one would be meaningless.
		if !(n.Security.Type == model.SecTLS || n.Protocol.IsQUICBased() || n.Protocol == model.ProtoAnyTLS) {
			continue
		}
		if cp, kp, ok := c.certFor(n.SNI()); ok {
			specs[i].CertPath, specs[i].KeyPath = cp, kp
		}
	}
}

// reapStrayEngines SIGKILLs any process whose executable lives under binDir.
func reapStrayEngines(binDir string) {
	if binDir == "" {
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		if strings.HasPrefix(exe, binDir) {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(syscall.SIGKILL)
			}
		}
	}
}

// EnsureBinaries downloads+verifies whichever cores the given inbounds require.
// SingboxBinary resolves — downloading and verifying if necessary — the exact
// sing-box binary this supervisor runs, under <dataDir>/bin. Callers such as the
// §3 live-Verify diagnostic use it so they exercise the same core the panel
// serves with, instead of hoping one happens to be on $PATH (it is not, on a
// clean install where binmgr fetched the core into its own cache).
func (c *Controller) SingboxBinary() (string, error) {
	return c.bins.Ensure(binmgr.EngineSingbox)
}

func (c *Controller) EnsureBinaries(nodes []*model.Node) error {
	return c.ensureBinariesFor(nodes)
}

// Reload regenerates and hot-applies configs for the given inbounds with no
// per-user client expansion (bare templates). Prefer ReloadSpecs for multi-user.
func (c *Controller) Reload(nodes []*model.Node) (*engine.Bundle, error) {
	specs := make([]engine.InboundSpec, 0, len(nodes))
	for _, n := range nodes {
		specs = append(specs, engine.InboundSpec{Node: n})
	}
	return c.ReloadSpecs(specs)
}

// ReloadSpecs regenerates and hot-applies configs for inbound specs, expanding
// each inbound to carry a client per bound user (spec §11 multi-user). Cores
// with zero inbounds are stopped; the rest are validated then (re)started.
func (c *Controller) ReloadSpecs(specs []engine.InboundSpec) (*engine.Bundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nodes := make([]*model.Node, 0, len(specs))
	for _, sp := range specs {
		nodes = append(nodes, sp.Node)
	}
	if err := c.EnsureBinaries(nodes); err != nil {
		return nil, err
	}
	cp, kp, _ := cert.EnsureSelfSigned(filepath.Join(c.dataDir, "certs"))
	c.applyCerts(specs)
	bundle, err := engine.BuildMulti(specs, c.xrayAPIPort, cp, kp)
	if err != nil {
		return nil, err
	}
	// Route each inbound to the one core that will serve it, and tell EVERY
	// adapter its share — including an empty one. An adapter whose last inbound
	// was just deleted has to be told, or its core keeps serving inbounds the
	// panel no longer knows about.
	active, unroutable, dispatchErr := c.dispatch(specs, cp, kp)
	c.active = active

	// An inbound no core can serve must be REPORTED, never dropped. An inbound
	// that silently vanishes from the generated config is the failure operators
	// cannot debug, and the old hand-written dispatch simply skipped anything
	// its switch did not recognise.
	for _, u := range unroutable {
		bundle.Skipped = append(bundle.Skipped, engine.SkippedInbound{
			Remark: u.Remark,
			Reason: u.Reason,
		})
	}
	c.lastBundle = bundle
	if dispatchErr != nil {
		return bundle, dispatchErr
	}

	// Hysteria2 port-hopping: install/refresh the UDP-range firewall redirects for
	// every hy2 inbound that requested one, and tear down rules for those removed.
	// Best-effort — a missing CAP_NET_ADMIN surfaces via PortHopStatus, not a reload
	// failure (the inbound still serves on its base port).
	want := map[int]string{}
	for _, sp := range specs {
		if sp.Node.Protocol == model.ProtoHysteria2 && sp.Node.Hysteria2 != nil && sp.Node.Hysteria2.PortHopping != "" {
			want[sp.Node.Port] = sp.Node.Hysteria2.PortHopping
		}
	}
	c.lastPortHopErr = ""
	if err := c.porthop.Sync(want); err != nil {
		c.lastPortHopErr = err.Error()
	}
	return bundle, nil
}

// Validate generates the bundle and runs each engine's own validator WITHOUT
// applying it — used by Config Doctor / the "show generated config" drawer.
func (c *Controller) Validate(nodes []*model.Node) (*engine.Bundle, map[string]string) {
	cp, kp, _ := cert.EnsureSelfSigned(filepath.Join(c.dataDir, "certs"))
	specs := make([]engine.InboundSpec, 0, len(nodes))
	for _, n := range nodes {
		specs = append(specs, engine.InboundSpec{Node: n})
	}
	// The preview must show the certificate the inbound would actually be served
	// with. Skipping this made Config Doctor and the "generated config" drawer
	// display a self-signed path for an inbound that runs with a real one.
	c.mu.Lock()
	c.applyCerts(specs)
	c.mu.Unlock()
	bundle, err := engine.BuildMulti(specs, c.xrayAPIPort, cp, kp)
	results := map[string]string{}
	if err != nil {
		results["build"] = err.Error()
		return bundle, results
	}
	if c.registry == nil {
		if c.regErr != nil {
			results["registry"] = c.regErr.Error()
		}
		return bundle, results
	}

	// Validate through the adapters, so every core is checked with its OWN
	// validator. The hand-written version only ever checked Xray and sing-box:
	// a Brook or AmneziaWG inbound was never validated at all, and its first
	// sign of trouble was the core refusing to start.
	plans, unroutable := c.registry.Partition(specs, cp, kp)
	for _, u := range unroutable {
		// Report by remark, since an unroutable inbound has no engine to key on.
		name := u.Remark
		if name == "" {
			name = "inbound"
		}
		results[name] = u.Reason
		bundle.Skipped = append(bundle.Skipped, engine.SkippedInbound{Remark: u.Remark, Reason: u.Reason})
	}
	for _, ap := range plans {
		if ap.Plan.Empty() {
			continue
		}
		cfg, genErr := ap.Adapter.GenerateConfig(ap.Plan.Nodes())
		if genErr != nil {
			results[ap.Engine] = "generate: " + genErr.Error()
			continue
		}
		results[ap.Engine] = validateResult(ap.Adapter.ValidateConfig(cfg))
	}
	return bundle, results
}

// Status returns each engine's supervised status.
func (c *Controller) Status() []supervisor.Status {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	// Health is read outside the controller lock: a core's status probe can
	// block on the process, and holding c.mu through it would stall every
	// reload behind a wedged engine.
	return c.adapterStatuses(active)
}

// PortHopStatus reports the port-hopping firewall backend, whether the panel can
// manage rules, the effective rules, the last sync error, and (when it lacks
// permission) the manual commands for the given listener/spec — for the UI and
// Config Doctor. A zero listen/empty spec omits the manual commands.
func (c *Controller) PortHopStatus(listen int, spec string) map[string]any {
	c.mu.Lock()
	lastErr := c.lastPortHopErr
	c.mu.Unlock()
	out := map[string]any{
		"backend":    string(c.porthop.Backend()),
		"can_manage": porthop.HasNetAdmin() && c.porthop.Backend() != porthop.BackendNone,
		"net_admin":  porthop.HasNetAdmin(),
		"rules":      c.porthop.Rules(),
		"last_error": lastErr,
	}
	if !porthop.HasNetAdmin() && listen > 0 && spec != "" {
		out["manual_commands"] = porthop.ManualCommands(c.porthop.Backend(), listen, spec)
	}
	return out
}

// BrookStatus returns running Brook process info.
func (c *Controller) BrookStatus() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.brook.Status()
}

// AWGStatus returns the managed AmneziaWG interfaces.
func (c *Controller) AWGStatus() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.awg.Status()
}

// AWGKernelStatus reports AmneziaWG kernel-mode readiness (tools + module).
func (c *Controller) AWGKernelStatus() map[string]any { return c.awg.KernelStatus() }

// LastBundle returns the most recently generated engine bundle (for the "show
// generated config" drawer, spec §6).
func (c *Controller) LastBundle() *engine.Bundle {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastBundle
}

// StopAll stops every supervised core (graceful shutdown).
func (c *Controller) StopAll() {
	c.mu.Lock()
	reg := c.registry
	c.active = nil
	c.mu.Unlock()
	if reg == nil {
		// No registry means no core was ever dispatched through one; stop the
		// reconcilers directly so a failed startup still tears down cleanly.
		c.brook.StopAll()
		c.awg.StopAll()
		return
	}
	// Every adapter, so a core added to the registry is stopped without editing
	// this function — the omission that used to leave a core running after the
	// panel had forgotten about it.
	ctx := context.Background()
	for _, a := range reg.All() {
		_ = a.Stop(ctx)
	}
}

func validateResult(err error) string {
	if err != nil {
		return err.Error()
	}
	return "valid"
}
