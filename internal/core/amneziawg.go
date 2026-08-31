package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// AWGManager runs AmneziaWG inbounds in KERNEL mode: it writes an awg-quick
// config per inbound and drives the `amneziawg` kernel module + awg-quick to
// bring the interface up/down. Unlike the userspace path (sing-box), this is a
// real kernel WireGuard interface with AmneziaWG obfuscation, so it needs root +
// the loaded module. When the module or tools are absent the engine still writes
// the configs and reports the shortfall via Status (best-effort, like porthop) —
// a reload never fails just because the kernel module is missing.
type AWGManager struct {
	confDir string
	fl      wgFlavour

	mu      sync.Mutex
	ifaces  map[string]string // iface name -> config signature
	lastErr string
}

// wgFlavour is the small set of facts that differ between the two kernel
// WireGuard datapaths this manager drives.
//
// The reconciliation is identical for both — write a conf per inbound, bring
// changed interfaces up, tear down removed ones — and the only differences are
// which module and tools are involved and how the config is rendered. Keeping
// them in one struct is why there is one reconciler rather than two that drift.
type wgFlavour struct {
	engine   string   // model.Engine* name, reported in Status
	dir      string   // subdirectory of the data dir holding the confs
	ifPrefix string   // interface-name prefix; must keep the name <= 15 chars
	module   string   // kernel module to require
	tools    []string // userspace tools that must be on PATH
	quick    string   // the wg-quick-equivalent binary
	// render produces the server config for one inbound.
	render func(n *model.Node) (string, error)
}

var awgFlavour = wgFlavour{
	engine: model.EngineAmneziaWG, dir: "amneziawg", ifPrefix: "awg",
	module: "amneziawg", tools: []string{"awg", "awg-quick"}, quick: "awg-quick",
	render: func(n *model.Node) (string, error) {
		return export.AmneziaWGServerConf(n, []*model.Node{n})
	},
}

// wgKernelFlavour is plain WireGuard on the kernel datapath. Measured on one
// box with the same client and destination, it carries 2.24-2.49 Gbit/s where
// the sing-box userspace endpoint carries 0.74-0.83 — about three times the
// throughput, which is why serving WireGuard here is worth a second flavour.
var wgKernelFlavour = wgFlavour{
	engine: model.EngineKernelWG, dir: "wireguard", ifPrefix: "wg",
	module: "wireguard", tools: []string{"wg", "wg-quick"}, quick: "wg-quick",
	render: func(n *model.Node) (string, error) {
		return export.WireGuardServerConf(n, []*model.Node{n})
	},
}

// NewAWGManager builds an AmneziaWG manager writing its configs under dataDir.
func NewAWGManager(dataDir string) *AWGManager { return newWGManager(dataDir, awgFlavour) }

// NewKernelWGManager builds a manager serving plain WireGuard inbounds on the
// kernel datapath instead of the sing-box userspace endpoint.
func NewKernelWGManager(dataDir string) *AWGManager { return newWGManager(dataDir, wgKernelFlavour) }

func newWGManager(dataDir string, fl wgFlavour) *AWGManager {
	dir := filepath.Join(dataDir, fl.dir)
	_ = os.MkdirAll(dir, 0o700)
	return &AWGManager{confDir: dir, fl: fl, ifaces: map[string]string{}}
}

// flavour returns the manager's flavour, defaulting to AmneziaWG so a
// zero-value manager built by an older caller behaves exactly as before.
func (m *AWGManager) flavour() wgFlavour {
	if m.fl.engine == "" {
		return awgFlavour
	}
	return m.fl
}

// awgIface derives a stable, ≤15-char interface name for an inbound.
func awgIface(n *model.Node) string { return awgFlavour.iface(n) }

func (f wgFlavour) iface(n *model.Node) string { return f.ifPrefix + strconv.Itoa(n.Port) }

// awgConfPath is the on-disk awg-quick config for an interface.
func (m *AWGManager) awgConfPath(iface string) string {
	return filepath.Join(m.confDir, iface+".conf")
}

// awgToolsAvailable reports whether awg + awg-quick are installed.
func awgToolsAvailable() bool { return awgFlavour.toolsAvailable() }

func (f wgFlavour) toolsAvailable() bool {
	for _, t := range f.tools {
		if _, err := exec.LookPath(t); err != nil {
			return false
		}
	}
	return true
}

// awgModuleReady loads/loads-checks the amneziawg kernel module (the whole point
// of kernel mode). Returns nil when the module is available.
func awgModuleReady() error { return awgFlavour.moduleReady() }

func (f wgFlavour) moduleReady() error {
	// Already loaded?
	if _, err := os.Stat("/sys/module/" + f.module); err == nil {
		return nil
	}
	if data, err := os.ReadFile("/proc/modules"); err == nil && strings.Contains(string(data), f.module) {
		return nil
	}
	if _, err := exec.LookPath("modprobe"); err != nil {
		return fmt.Errorf("modprobe not found")
	}
	if out, err := exec.Command("modprobe", f.module).CombinedOutput(); err != nil {
		return fmt.Errorf("modprobe %s: %v: %s", f.module, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Sync reconciles kernel AmneziaWG interfaces with the desired awg inbounds:
// (re)writes each config, brings new/changed interfaces up, and tears down
// removed ones. Each inbound is one interface with the single client peer stored
// on the node (mirrors the panel's WireGuard model).
func (m *AWGManager) Sync(nodes []*model.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = ""

	fl := m.flavour()
	want := map[string]string{} // iface -> signature
	kernel := fl.toolsAvailable()
	if kernel {
		if err := fl.moduleReady(); err != nil {
			kernel = false
			m.lastErr = fl.module + " kernel module unavailable: " + err.Error()
		}
	} else if len(nodes) > 0 {
		m.lastErr = strings.Join(fl.tools, "/") + " tools not installed"
	}

	for _, n := range nodes {
		iface := fl.iface(n)
		conf, err := fl.render(n)
		if err != nil {
			m.lastErr = err.Error()
			continue
		}
		sig := sigOf(conf)
		want[iface] = sig
		path := m.awgConfPath(iface)
		if werr := os.WriteFile(path, []byte(conf), 0o600); werr != nil {
			m.lastErr = werr.Error()
			continue
		}
		prevSig, tracked := m.ifaces[iface]
		m.ifaces[iface] = sig // track the config so teardown can clean it up
		if !kernel {
			continue // config written; interface brought up once the module is present
		}
		if tracked && prevSig == sig && ifaceUp(iface) {
			continue // already up with this exact config
		}
		if ifaceUp(iface) {
			_ = runAWG(fl.quick, "down", path)
		}
		if out, uerr := exec.Command(fl.quick, "up", path).CombinedOutput(); uerr != nil {
			m.lastErr = fmt.Sprintf("%s up %s: %v: %s", fl.quick, iface, uerr, strings.TrimSpace(string(out)))
			continue
		}
	}

	// Tear down interfaces for removed inbounds.
	for iface := range m.ifaces {
		if _, keep := want[iface]; keep {
			continue
		}
		path := m.awgConfPath(iface)
		if kernel && ifaceUp(iface) {
			_ = runAWG(fl.quick, "down", path)
		}
		_ = os.Remove(path)
		delete(m.ifaces, iface)
	}
	return nil
}

// StopAll brings every managed AmneziaWG interface down.
func (m *AWGManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	quick := m.flavour().quick
	for iface := range m.ifaces {
		if ifaceUp(iface) {
			_ = runAWG(quick, "down", m.awgConfPath(iface))
		}
		delete(m.ifaces, iface)
	}
}

// Status reports each managed interface and whether kernel mode is active.
func (m *AWGManager) Status() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]any{}
	for iface := range m.ifaces {
		out = append(out, map[string]any{
			"engine": m.flavour().engine, "interface": iface, "up": ifaceUp(iface),
		})
	}
	return out
}

// KernelStatus summarizes AmneziaWG kernel-mode readiness for the UI/Doctor.
func (m *AWGManager) KernelStatus() map[string]any {
	m.mu.Lock()
	lastErr := m.lastErr
	m.mu.Unlock()
	fl := m.flavour()
	tools := fl.toolsAvailable()
	modErr := fl.moduleReady()
	return map[string]any{
		"tools_installed": tools,
		"module_loaded":   modErr == nil,
		"kernel_ready":    tools && modErr == nil,
		"last_error":      lastErr,
	}
}

// ifaceUp reports whether a network interface currently exists (is up).
func ifaceUp(iface string) bool {
	return exec.Command("ip", "link", "show", iface).Run() == nil
}

// runAWG runs an awg-quick/awg command, discarding output (best-effort teardown).
func runAWG(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func sigOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// AmneziaWGReady reports whether this box can actually serve AmneziaWG, and why
// not when it cannot.
//
// The panel will happily create an AmneziaWG inbound on a host with no awg
// tooling and no kernel module: the row is written, the inbound is enabled, and
// nothing ever listens on its port. Callers that are about to tell an operator
// "created" need to be able to say "…but this server cannot serve it".
func AmneziaWGReady() (bool, string) {
	if !awgToolsAvailable() {
		return false, "awg/awg-quick tools are not installed on this server"
	}
	if err := awgModuleReady(); err != nil {
		return false, "amneziawg kernel module unavailable: " + err.Error()
	}
	return true, ""
}
