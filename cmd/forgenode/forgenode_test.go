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
	}

	if err := agent.register(); err != nil {
		t.Fatalf("agent.register failed: %v", err)
	}
	if !registered {
		t.Fatal("expected agent to register with panel")
	}

	cfg, err := agent.heartbeat()
	if err != nil {
		t.Fatalf("agent.heartbeat failed: %v", err)
	}
	if cfg != `{"inbounds":[]}` {
		t.Fatalf("expected xray config, got %q", cfg)
	}

	// Test config application
	agent.applyConfig(cfg)

	writtenConfigPath := filepath.Join(dir, "node-xray.json")
	data, err := os.ReadFile(writtenConfigPath)
	if err != nil {
		t.Fatalf("failed to read written config: %v", err)
	}
	if string(data) != cfg {
		t.Fatalf("expected written config %q, got %q", cfg, string(data))
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
		xrayBin: dummyBin,
	}

	// Apply invalid config
	agent.applyConfig("bad-config")

	writtenConfigPath := filepath.Join(dir, "node-xray.json")
	if _, err := os.Stat(writtenConfigPath); !os.IsNotExist(err) {
		t.Fatalf("expected node-xray.json NOT to exist after invalid config rejection")
	}

	if agent.lastCfg != "" {
		t.Fatalf("expected lastCfg to be empty, got %q", agent.lastCfg)
	}
}
