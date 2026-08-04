// Package core ties the binary manager, config aggregator and supervisor
// together into the panel-facing engine controller (spec §6). The API layer
// calls Reload whenever inbounds change; the controller regenerates each engine
// config, validates it with the engine's own `-test`/`check`, and hot-applies it
// only if valid.
package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/forgepanel/forgepanel/internal/cert"
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

	mu             sync.Mutex
	xray           *supervisor.Process
	singbox        *supervisor.Process
	brook          *BrookManager
	porthop        *porthop.Manager
	lastPortHopErr string
	lastBundle     *engine.Bundle
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
	return &Controller{dataDir: dataDir, xrayAPIPort: xrayAPIPort, bins: bins, brook: NewBrookManager(bins), porthop: porthop.New()}
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
func (c *Controller) EnsureBinaries(nodes []*model.Node) error {
	needXray, needSB, needBrook := false, false, false
	for _, n := range nodes {
		switch engineFor(n) {
		case "xray":
			needXray = true
		case "sing-box":
			needSB = true
		case "brook":
			needBrook = true
		}
	}
	if needBrook {
		if _, err := c.bins.Ensure(binmgr.EngineBrook); err != nil {
			return err
		}
	}
	if needXray {
		if _, err := c.bins.Ensure(binmgr.EngineXray); err != nil {
			return err
		}
	}
	if needSB {
		if _, err := c.bins.Ensure(binmgr.EngineSingbox); err != nil {
			return err
		}
	}
	return nil
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
	bundle, err := engine.BuildMulti(specs, c.xrayAPIPort, cp, kp)
	if err != nil {
		return nil, err
	}
	c.lastBundle = bundle

	// Xray
	if bundle.XrayN > 0 {
		if c.xray == nil {
			c.xray = supervisor.NewProcess(c.xraySpec())
		}
		if err := c.xray.Apply(bundle.Xray); err != nil {
			return bundle, err
		}
	} else if c.xray != nil {
		c.xray.Stop()
	}

	// sing-box
	if bundle.SingboxN > 0 {
		if c.singbox == nil {
			c.singbox = supervisor.NewProcess(c.singboxSpec())
		}
		if err := c.singbox.Apply(bundle.Singbox); err != nil {
			return bundle, err
		}
	} else if c.singbox != nil {
		c.singbox.Stop()
	}

	// Brook inbounds are external processes (one per inbound, CLI-driven).
	var brookNodes []*model.Node
	for _, sp := range specs {
		if engineFor(sp.Node) == "brook" {
			brookNodes = append(brookNodes, sp.Node)
		}
	}
	if err := c.brook.Sync(brookNodes, cp, kp); err != nil {
		return bundle, err
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
	bundle, err := engine.BuildMulti(specs, c.xrayAPIPort, cp, kp)
	results := map[string]string{}
	if err != nil {
		results["build"] = err.Error()
		return bundle, results
	}
	if bundle.XrayN > 0 {
		if _, e := c.bins.Ensure(binmgr.EngineXray); e != nil {
			results["xray"] = "binary: " + e.Error()
		} else {
			p := supervisor.NewProcess(c.xraySpec())
			results["xray"] = validateResult(p.ValidateBytes(bundle.Xray, filepath.Join(c.dataDir, "engines", "xray.candidate.json")))
		}
	}
	if bundle.SingboxN > 0 {
		if _, e := c.bins.Ensure(binmgr.EngineSingbox); e != nil {
			results["sing-box"] = "binary: " + e.Error()
		} else {
			p := supervisor.NewProcess(c.singboxSpec())
			results["sing-box"] = validateResult(p.ValidateBytes(bundle.Singbox, filepath.Join(c.dataDir, "engines", "singbox.candidate.json")))
		}
	}
	return bundle, results
}

// Status returns each engine's supervised status.
func (c *Controller) Status() []supervisor.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []supervisor.Status
	if c.xray != nil {
		out = append(out, c.xray.Status())
	}
	if c.singbox != nil {
		out = append(out, c.singbox.Status())
	}
	_ = c.brook // brook status is a separate shape; surfaced via BrookStatus()
	return out
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
	defer c.mu.Unlock()
	if c.xray != nil {
		c.xray.Stop()
	}
	if c.singbox != nil {
		c.singbox.Stop()
	}
	c.brook.StopAll()
}

func (c *Controller) xraySpec() supervisor.EngineSpec {
	return supervisor.EngineSpec{
		Name: "xray", BinPath: c.bins.Path(binmgr.EngineXray),
		RunArgs: []string{"run", "-c"}, TestArgs: []string{"run", "-test", "-c"},
		ConfigPath: filepath.Join(c.dataDir, "engines", "xray.json"),
	}
}

func (c *Controller) singboxSpec() supervisor.EngineSpec {
	return supervisor.EngineSpec{
		Name: "sing-box", BinPath: c.bins.Path(binmgr.EngineSingbox),
		RunArgs: []string{"run", "-c"}, TestArgs: []string{"check", "-c"},
		ConfigPath: filepath.Join(c.dataDir, "engines", "singbox.json"),
	}
}

func engineFor(n *model.Node) string {
	// Mirror render.EngineFor without importing render here (avoids a cycle if
	// render ever needs core). Kept in sync deliberately.
	switch n.Protocol {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks,
		model.ProtoSOCKS, model.ProtoHTTP:
		return "xray"
	case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoAnyTLS, model.ProtoShadowTLS, model.ProtoSSH, model.ProtoWireGuard:
		return "sing-box"
	case model.ProtoBrook:
		return "brook"
	default:
		return ""
	}
}

func validateResult(err error) string {
	if err != nil {
		return err.Error()
	}
	return "valid"
}
