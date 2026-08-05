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

	mu      sync.Mutex
	ifaces  map[string]string // iface name -> config signature
	lastErr string
}

// NewAWGManager builds an AmneziaWG manager writing its configs under dataDir.
func NewAWGManager(dataDir string) *AWGManager {
	dir := filepath.Join(dataDir, "amneziawg")
	_ = os.MkdirAll(dir, 0o700)
	return &AWGManager{confDir: dir, ifaces: map[string]string{}}
}

// awgIface derives a stable, ≤15-char interface name for an inbound.
func awgIface(n *model.Node) string { return "awg" + strconv.Itoa(n.Port) }

// awgConfPath is the on-disk awg-quick config for an interface.
func (m *AWGManager) awgConfPath(iface string) string {
	return filepath.Join(m.confDir, iface+".conf")
}

// awgToolsAvailable reports whether awg + awg-quick are installed.
func awgToolsAvailable() bool {
	for _, t := range []string{"awg", "awg-quick"} {
		if _, err := exec.LookPath(t); err != nil {
			return false
		}
	}
	return true
}

// awgModuleReady loads/loads-checks the amneziawg kernel module (the whole point
// of kernel mode). Returns nil when the module is available.
func awgModuleReady() error {
	// Already loaded?
	if _, err := os.Stat("/sys/module/amneziawg"); err == nil {
		return nil
	}
	if data, err := os.ReadFile("/proc/modules"); err == nil && strings.Contains(string(data), "amneziawg") {
		return nil
	}
	if _, err := exec.LookPath("modprobe"); err != nil {
		return fmt.Errorf("modprobe not found")
	}
	if out, err := exec.Command("modprobe", "amneziawg").CombinedOutput(); err != nil {
		return fmt.Errorf("modprobe amneziawg: %v: %s", err, strings.TrimSpace(string(out)))
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

	want := map[string]string{} // iface -> signature
	kernel := awgToolsAvailable()
	if kernel {
		if err := awgModuleReady(); err != nil {
			kernel = false
			m.lastErr = "amneziawg kernel module unavailable: " + err.Error()
		}
	} else if len(nodes) > 0 {
		m.lastErr = "awg/awg-quick tools not installed"
	}

	for _, n := range nodes {
		iface := awgIface(n)
		conf, err := export.AmneziaWGServerConf(n, []*model.Node{n})
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
			_ = runAWG("awg-quick", "down", path)
		}
		if out, uerr := exec.Command("awg-quick", "up", path).CombinedOutput(); uerr != nil {
			m.lastErr = fmt.Sprintf("awg-quick up %s: %v: %s", iface, uerr, strings.TrimSpace(string(out)))
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
			_ = runAWG("awg-quick", "down", path)
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
	for iface := range m.ifaces {
		if ifaceUp(iface) {
			_ = runAWG("awg-quick", "down", m.awgConfPath(iface))
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
			"engine": "amneziawg", "interface": iface, "up": ifaceUp(iface),
		})
	}
	return out
}

// KernelStatus summarizes AmneziaWG kernel-mode readiness for the UI/Doctor.
func (m *AWGManager) KernelStatus() map[string]any {
	m.mu.Lock()
	lastErr := m.lastErr
	m.mu.Unlock()
	tools := awgToolsAvailable()
	modErr := awgModuleReady()
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
