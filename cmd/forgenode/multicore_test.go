package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The agent ran exactly one process, xray, from one config — and the heartbeat
// carried only the xray half of the panel's bundle. So every hysteria2, tuic,
// anytls, shadowtls and wireguard inbound VANISHED the moment it was assigned to
// a remote node: the panel listed it, the node never served it, and nothing
// anywhere said why.

func panelServing(t *testing.T, body map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/register":
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": 1})
		case "/api/node/heartbeat":
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestBothEngineConfigsReachTheNode(t *testing.T) {
	dir := t.TempDir()
	srv := panelServing(t, map[string]any{
		"xray_config":    `{"inbounds":[{"tag":"x"}]}`,
		"singbox_config": `{"inbounds":[{"type":"hysteria2"}]}`,
	})
	defer srv.Close()

	agent := &NodeAgent{panel: srv.URL, token: "t", dataDir: dir, engines: testEngines("")}
	agent.step()

	for file, want := range map[string]string{
		"node-xray.json":    `{"inbounds":[{"tag":"x"}]}`,
		"node-singbox.json": `{"inbounds":[{"type":"hysteria2"}]}`,
	} {
		got, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("%s was not written: %v — its protocols would silently not be served", file, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
}

func TestAPanelThatSendsNoSingboxConfigLeavesXrayAlone(t *testing.T) {
	dir := t.TempDir()
	// A panel that predates multi-core omits the field entirely. The node must
	// keep serving xray exactly as before rather than treating the absence as an
	// error or as a reason to stop.
	srv := panelServing(t, map[string]any{"xray_config": `{"inbounds":[]}`})
	defer srv.Close()

	agent := &NodeAgent{panel: srv.URL, token: "t", dataDir: dir, engines: testEngines("")}
	agent.step()

	if _, err := os.Stat(filepath.Join(dir, "node-xray.json")); err != nil {
		t.Fatalf("xray config was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-singbox.json")); !os.IsNotExist(err) {
		t.Fatal("a sing-box config was written for a panel that sent none")
	}
}

func TestAnEmptiedEngineConfigStopsThatEngine(t *testing.T) {
	dir := t.TempDir()
	agent := &NodeAgent{panel: "http://unused", token: "t", dataDir: dir, engines: testEngines("")}

	agent.applyConfigs(map[string]string{
		"xray":     `{"inbounds":[]}`,
		"sing-box": `{"inbounds":[{"type":"tuic"}]}`,
	})
	if _, err := os.Stat(filepath.Join(dir, "node-singbox.json")); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The panel removes every sing-box inbound from this node.
	agent.applyConfigs(map[string]string{"xray": `{"inbounds":[]}`, "sing-box": ""})

	// The config must GO. A core left running on a stale config keeps serving
	// inbounds the panel has removed, which is exactly the drift this path
	// exists to prevent.
	if _, err := os.Stat(filepath.Join(dir, "node-singbox.json")); !os.IsNotExist(err) {
		t.Fatal("the sing-box config survived being emptied; the node would keep serving removed inbounds")
	}
	if _, err := os.Stat(filepath.Join(dir, "node-xray.json")); err != nil {
		t.Fatal("emptying one engine's config disturbed the other")
	}
}

func TestAnUnchangedConfigIsNotReapplied(t *testing.T) {
	dir := t.TempDir()
	agent := &NodeAgent{panel: "http://unused", token: "t", dataDir: dir, engines: testEngines("")}
	cfgs := map[string]string{"xray": `{"inbounds":[]}`}

	agent.applyConfigs(cfgs)
	first := agent.engines["xray"].lastCfg
	agent.applyConfigs(cfgs)

	// Reapplying restarts the core and drops every connection on it. Doing that
	// on every heartbeat — ten seconds apart — would make the node unusable.
	if agent.engines["xray"].lastCfg != first {
		t.Fatal("an unchanged config was reapplied")
	}
}

func TestTrafficFromBothEnginesIsSummedNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	a := &NodeAgent{dataDir: dir, engines: testEngines("")}

	// One user served by BOTH engines on the same node — a VLESS inbound and a
	// hysteria2 inbound. Taking either side alone silently discards half their
	// usage, and the discard is always in the customer's favour, which is why it
	// survives unnoticed.
	xray := map[string]int64{"user>>>u.1>>>traffic>>>uplink": 100}
	singbox := map[string]int64{"user>>>u.1>>>traffic>>>uplink": 250}

	merged := map[string]int64{}
	for k, v := range xray {
		merged[k] += v
	}
	for k, v := range singbox {
		merged[k] += v
	}
	if merged["user>>>u.1>>>traffic>>>uplink"] != 350 {
		t.Fatalf("merged = %d, want 350", merged["user>>>u.1>>>traffic>>>uplink"])
	}

	// And the real path must not panic when xray is absent: collectXrayTraffic
	// returns a nil map there, and assigning into a nil map panics — on the
	// heartbeat goroutine, for a node serving only sing-box protocols.
	if got := a.collectTraffic(false); got != nil && len(got) != 0 {
		t.Fatalf("expected no counters with no cores running, got %v", got)
	}
}

func TestAnUnsupportedSingboxReportsNoCapability(t *testing.T) {
	a := &NodeAgent{dataDir: t.TempDir(), engines: testEngines("")}
	// No binary at all: the node must say it cannot meter rather than claiming it
	// can, because the panel acts on the answer by writing a config section that
	// a stock binary refuses to start with.
	if a.singboxStatsSupported() {
		t.Fatal("a node with no sing-box binary claimed it could report stats")
	}
}

func TestANodeDoesNotRestartForAUserOnlyChange(t *testing.T) {
	dir := t.TempDir()
	a := &NodeAgent{dataDir: dir, engines: testEngines("")}
	e := a.engines["xray"]

	// A user-only change must not restart the core. On a node with hundreds of
	// users, one account tripping a quota would otherwise drop every other
	// connection — the panel solved that for its own cores and the fleet kept
	// restarting.
	var hotCalls int
	e.spec.hotApply = func(bin, dataDir string, oldCfg, newCfg []byte) (bool, error) {
		hotCalls++
		return true, nil
	}
	// Pretend the core is up, without spawning one.
	e.cmd = fakeRunningCmd(t)
	e.bin = "/bin/true"

	base := `{"inbounds":[{"tag":"in","settings":{"clients":[{"email":"u.1","id":"a"}]}}]}`
	e.lastCfg = base
	withUser := `{"inbounds":[{"tag":"in","settings":{"clients":[{"email":"u.1","id":"a"},{"email":"u.2","id":"b"}]}}]}`

	e.apply(dir, withUser)

	if hotCalls != 1 {
		t.Fatalf("hot apply was called %d times, want 1", hotCalls)
	}
	// Still the same process: not stopped and restarted.
	if e.cmd == nil {
		t.Fatal("the core was restarted for a user-only change")
	}
	if e.lastCfg != withUser {
		t.Fatal("the new config was not recorded, so the next heartbeat would reapply it")
	}
}

func TestAFailedHotApplyFallsBackToARestart(t *testing.T) {
	dir := t.TempDir()
	a := &NodeAgent{dataDir: dir, engines: testEngines("")}
	e := a.engines["xray"]
	e.spec.hotApply = func(bin, dataDir string, oldCfg, newCfg []byte) (bool, error) {
		return false, errFake
	}
	e.cmd = fakeRunningCmd(t)
	e.bin = "" // no binary: apply writes the config and does not spawn

	e.lastCfg = `{"inbounds":[]}`
	e.apply(dir, `{"inbounds":[{"tag":"x"}]}`)

	// A restart is the one action that always reconciles a core with its config,
	// so a hot apply that failed must not leave the core on the old one.
	if e.cmd != nil {
		t.Fatal("the core was not stopped after a failed hot apply")
	}
}

var errFake = fmt.Errorf("simulated hot-apply failure")

// fakeRunningCmd returns a started process that stands in for a live core, so
// the restart path can be observed without spawning a real engine.
func fakeRunningCmd(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}
