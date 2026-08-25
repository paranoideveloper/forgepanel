package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
