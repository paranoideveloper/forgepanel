package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func awgTestNode(port int) *model.Node {
	n := &model.Node{
		Protocol: model.ProtoAmneziaWG, Address: "1.2.3.4", Port: port,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "SRVPRIV", PublicKey: "SRVPUB",
			PeerPrivateKey: "CLIPRIV", PeerPublicKey: "CLIPUB",
			ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"},
		}},
	}
	n.Normalize()
	return n
}

// Sync must always write the config and never fail, even when the kernel module
// / tools are unavailable (the common CI + non-root case) — the interface is
// brought up later once the module is present.
func TestAWGSyncWritesConfigGracefully(t *testing.T) {
	dir := t.TempDir()
	m := NewAWGManager(dir)
	n := awgTestNode(51888)
	if err := m.Sync([]*model.Node{n}); err != nil {
		t.Fatalf("Sync must not fail when kernel is absent: %v", err)
	}
	conf := filepath.Join(dir, "amneziawg", "awg51888.conf")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	s := string(data)
	for _, want := range []string{"[Interface]", "PrivateKey = SRVPRIV", "ListenPort = 51888", "[Peer]", "PublicKey = CLIPUB", "Jc = "} {
		if !strings.Contains(s, want) {
			t.Fatalf("config missing %q:\n%s", want, s)
		}
	}
	// Removing the inbound removes its config.
	if err := m.Sync(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("config should be removed when the inbound is gone")
	}
}

func TestAWGKernelStatusShape(t *testing.T) {
	m := NewAWGManager(t.TempDir())
	st := m.KernelStatus()
	for _, k := range []string{"tools_installed", "module_loaded", "kernel_ready", "last_error"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("KernelStatus missing %q: %v", k, st)
		}
	}
}

func TestAWGEngineForRouting(t *testing.T) {
	if model.EngineForNode(awgTestNode(51820)) != "amneziawg" {
		t.Fatal("awg must route to the amneziawg engine, not sing-box")
	}
}

func TestAWGModuleReadyCheck(t *testing.T) {
	// awgModuleReady should safely run without panicking on any environment
	err := awgModuleReady()
	// st check should return boolean flags
	m := NewAWGManager(t.TempDir())
	st := m.KernelStatus()
	if _, ok := st["module_loaded"].(bool); !ok {
		t.Fatal("module_loaded should be a boolean")
	}
	_ = err
}
