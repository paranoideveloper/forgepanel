package xrayapi

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"strings"
	"testing"
	"time"
)

// Hot apply against a REAL Xray.
//
// Everything else in hotuser_test.go tests the diff, which is pure. This is the
// only test that proves the other half: that `xray api adu`/`rmu` actually
// change a RUNNING core, in the document shape this code sends, on the version
// the panel pins. The shape was found by measurement — a tag-plus-clients
// document is accepted and silently adds nothing — and a test that mocks the CLI
// would have happily passed against that wrong shape forever.

const liveAPIPort = 25690

func liveXrayConfig(t *testing.T, port int, clients []any) map[string]any {
	t.Helper()
	return map[string]any{
		"log":    map[string]any{"loglevel": "warning", "access": ""},
		"api":    map[string]any{"tag": "api", "services": []string{"HandlerService", "StatsService"}},
		"stats":  map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds": []any{
			map[string]any{"tag": "api", "listen": "127.0.0.1", "port": liveAPIPort,
				"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
			map[string]any{"tag": "in-1", "listen": "127.0.0.1", "port": port, "protocol": "vless",
				"settings":       map[string]any{"clients": clients, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp"}},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		}},
	}
}

func userCount(t *testing.T, bin, tag string) int {
	t.Helper()
	out, err := runXrayAPI(bin, "inboundusercount", "--server=127.0.0.1:"+strconv.Itoa(liveAPIPort), "-tag="+tag)
	if err != nil {
		t.Fatalf("inboundusercount: %v: %s", err, out)
	}
	var res struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("inboundusercount output %q: %v", out, err)
	}
	return res.Count
}

func TestHotApplyAgainstRealXray(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real Xray")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	write := func(v any) []byte {
		b, err := json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return b
	}

	oldCfg := write(liveXrayConfig(t, 25693, []any{
		map[string]any{"id": "36fc4a5b-4e79-451a-bd45-f0a1bca66443", "email": "u.1"},
	}))

	cmd := exec.Command(bin, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(2 * time.Second)

	if got := userCount(t, bin, "in-1"); got != 1 {
		t.Fatalf("starting user count = %d, want 1", got)
	}

	// The REAL binary, against a REAL running core. A stub here would prove
	// nothing about whether `xray api adu` accepts the document this code sends.
	server := "127.0.0.1:" + strconv.Itoa(liveAPIPort)
	workDir := filepath.Join(dir, "hot")

	// --- add ---------------------------------------------------------------
	newCfg, err := json.MarshalIndent(liveXrayConfig(t, 25693, []any{
		map[string]any{"id": "36fc4a5b-4e79-451a-bd45-f0a1bca66443", "email": "u.1"},
		map[string]any{"id": "ee0362fe-9909-40b9-a4a5-8f4c2026fc80", "email": "u.2"},
	}), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := hotApplyForTest(bin, server, workDir, oldCfg, newCfg)
	if err != nil {
		t.Fatalf("hot add: %v", err)
	}
	if !applied {
		t.Fatal("a pure user addition was not hot-applied; every such edit would restart the core and drop every connection")
	}
	if got := userCount(t, bin, "in-1"); got != 2 {
		t.Fatalf("user count after add = %d, want 2 — the CLI reported success", got)
	}

	// --- remove ------------------------------------------------------------
	applied, err = hotApplyForTest(bin, server, workDir, newCfg, oldCfg)
	if err != nil {
		t.Fatalf("hot remove: %v", err)
	}
	if !applied {
		t.Fatal("a pure user removal was not hot-applied")
	}
	if got := userCount(t, bin, "in-1"); got != 1 {
		t.Fatalf("user count after remove = %d, want 1", got)
	}

	// --- a non-user change declines, rather than half-applying -------------
	portChanged, err := json.Marshal(liveXrayConfig(t, 25694, []any{
		map[string]any{"id": "36fc4a5b-4e79-451a-bd45-f0a1bca66443", "email": "u.1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	applied, err = hotApplyForTest(bin, server, workDir, oldCfg, portChanged)
	if err != nil {
		t.Fatalf("port change should decline quietly, not error: %v", err)
	}
	if applied {
		t.Fatal("a port change was hot-applied; the listener would still be on the old port while the config said otherwise")
	}

	// --- the credentials file does not survive the call --------------------
	// It carries the UUIDs of the users being added.
	leftovers, _ := filepath.Glob(filepath.Join(workDir, "*"))
	if len(leftovers) != 0 {
		t.Errorf("credential documents left on disk: %v", leftovers)
	}
}

func TestHotApplyReportsTheCoresOwnZeroAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real Xray")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	// `adu` against a core that is not listening must FAIL, not quietly report
	// success. This is the guard on the silent-zero-add behaviour: the CLI exits
	// zero and prints "Added 0 user(s)" for a document it cannot apply.
	err := AddUsers(bin, "127.0.0.1:1", t.TempDir(), UserDelta{
		Tag:   "in-1",
		Add:   []json.RawMessage{json.RawMessage(`{"id":"x","email":"u.9"}`)},
		Entry: map[string]json.RawMessage{"tag": json.RawMessage(`"in-1"`)},
	})
	if err == nil {
		t.Fatal("adding a user against a dead API reported success; the panel would then believe a user exists that the core has never heard of")
	}
	if !strings.Contains(err.Error(), "u.9") && !strings.Contains(err.Error(), "in-1") {
		t.Errorf("error does not say what failed: %v", err)
	}
}

// hotApplyForTest drives HotApply with a stub binary path, standing in for the
// Controller wiring that lives in internal/core.
func hotApplyForTest(bin, server, workDir string, oldCfg, newCfg []byte) (bool, error) {
	return HotApply(HotApplyOptions{Bin: bin, Server: server, WorkDir: workDir}, oldCfg, newCfg)
}
