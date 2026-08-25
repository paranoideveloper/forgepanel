package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeAgentHeartbeatAndApplyConfig(t *testing.T) {
	dir := t.TempDir()
	registered := false
	heartbeatCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/register":
			registered = true
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"node_id": 1})
		case "/api/node/heartbeat":
			heartbeatCount++
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"xray_config": `{"inbounds":[]}`})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	agent := &NodeAgent{
		panel:   server.URL,
		token:   "test-token",
		dataDir: dir,
		// No binary: the config is still written and validated-by-skipping, which
		// is the state of a node whose core has not downloaded yet.
		engines: testEngines(""),
	}

	if err := agent.register(); err != nil {
		t.Fatalf("agent.register failed: %v", err)
	}
	if !registered {
		t.Fatal("expected agent to register with panel")
	}

	cfgs, err := agent.heartbeat()
	if err != nil {
		t.Fatalf("agent.heartbeat failed: %v", err)
	}
	if cfgs["xray"] != `{"inbounds":[]}` {
		t.Fatalf("expected xray config, got %q", cfgs["xray"])
	}

	// Test config application
	agent.applyConfigs(cfgs)

	writtenConfigPath := filepath.Join(dir, "node-xray.json")
	data, err := os.ReadFile(writtenConfigPath)
	if err != nil {
		t.Fatalf("failed to read written config: %v", err)
	}
	if string(data) != cfgs["xray"] {
		t.Fatalf("expected written config %q, got %q", cfgs["xray"], string(data))
	}
}

func TestNodeAgentRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()

	// Create a dummy failing binary for xray test failure simulation
	dummyBin := filepath.Join(dir, "fake-xray")
	script := "#!/bin/sh\nif [ \"$1\" = \"run\" ] && [ \"$2\" = \"-test\" ]; then\n  echo \"invalid config schema\" >&2\n  exit 1\nfi\nexit 0\n"
	if err := os.WriteFile(dummyBin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	agent := &NodeAgent{
		panel:   "http://localhost:8080",
		token:   "test-token",
		dataDir: dir,
		engines: testEngines(dummyBin),
	}

	// Apply invalid config
	agent.applyConfigs(map[string]string{"xray": "bad-config"})

	writtenConfigPath := filepath.Join(dir, "node-xray.json")
	if _, err := os.Stat(writtenConfigPath); !os.IsNotExist(err) {
		t.Fatalf("expected node-xray.json NOT to exist after invalid config rejection")
	}

	// A rejected config must not be recorded as applied, or the next heartbeat
	// carrying the SAME bad config would be skipped as unchanged and the node
	// would sit on the old one forever without retrying.
	if got := agent.engines["xray"].lastCfg; got != "" {
		t.Fatalf("a rejected config was recorded as applied: %q", got)
	}
}

func TestNodeAgentRegisterAndHeartbeatErrors(t *testing.T) {
	dir := t.TempDir()

	// Server returning HTTP 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	agent := &NodeAgent{
		panel:   server.URL,
		token:   "test-token",
		dataDir: dir,
	}

	if err := agent.register(); err == nil {
		t.Fatal("expected error on 500 status code for register")
	}

	if _, err := agent.heartbeat(); err == nil {
		t.Fatal("expected error on 500 status code for heartbeat")
	}

	// Invalid URL test
	invalidAgent := &NodeAgent{
		panel:   "http://invalid.localhost.nonexistent:9999",
		token:   "test-token",
		dataDir: dir,
	}
	if err := invalidAgent.register(); err == nil {
		t.Fatal("expected network error for invalid panel URL")
	}
}

func TestNodeAgentStepAndProcessLifecycle(t *testing.T) {
	dir := t.TempDir()
	var heartbeatCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heartbeatCalled = true
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"xray_config": `{"inbounds":[]}`})
	}))
	defer server.Close()

	dummyBin := filepath.Join(dir, "fake-xray-ok")
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(dummyBin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	agent := &NodeAgent{
		panel:   server.URL,
		token:   "test-token",
		dataDir: dir,
		engines: testEngines(dummyBin),
	}

	agent.step()
	if !heartbeatCalled {
		t.Fatal("expected step to invoke heartbeat")
	}

	// Re-applying same config should skip restart
	agent.applyConfigs(map[string]string{"xray": `{"inbounds":[]}`})
}

// testEngines builds the supervised-engine map with a stub binary, mirroring
// what the constructor does without downloading a real core.
func testEngines(bin string) map[string]*engineProc {
	out := map[string]*engineProc{}
	for _, spec := range engineSpecs() {
		out[spec.name] = &engineProc{spec: spec, bin: bin}
	}
	return out
}
