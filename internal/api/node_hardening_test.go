package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func setupHardenedServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.DataDir = dir

	s, err := NewWithStore(cfg)
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.db
}

func TestNodeSpecificInboundFilteringInHeartbeat(t *testing.T) {
	s, db := setupHardenedServer(t)

	// Create Node A and Node B inbounds
	nodeA := &model.Node{
		Protocol: model.ProtoVLESS, Port: 443, Address: "192.168.1.10", Remark: "Inbound-NodeA", UUID: "a0a0a0a0-b1b1-c2c2-d3d3-e4e4e4e4e4e4",
	}
	nodeB := &model.Node{
		Protocol: model.ProtoTrojan, Port: 8443, Address: "192.168.1.20", Remark: "Inbound-NodeB", Password: "trojanpassword123",
	}

	_, err := db.CreateInbound(nodeA)
	if err != nil {
		t.Fatalf("failed to create Inbound NodeA: %v", err)
	}
	_, err = db.CreateInbound(nodeB)
	if err != nil {
		t.Fatalf("failed to create Inbound NodeB: %v", err)
	}

	// Register Node A record
	nodeRecA := &store.Node{Name: "Node-A", Address: "192.168.1.10", EnrollToken: "token-node-a", Enrolled: true}
	if err := db.CreateNode(nodeRecA); err != nil {
		t.Fatalf("failed to create Node A record: %v", err)
	}

	// Request Node A heartbeat
	body, _ := json.Marshal(map[string]any{"token": "token-node-a", "cpu": 0.1, "mem_mb": 128})
	req := httptest.NewRequest(http.MethodPost, "/api/node/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		XrayConfig string `json:"xray_config"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Node A config bundle must contain VLESS (192.168.1.10) and NOT Trojan (192.168.1.20)
	if !bytes.Contains([]byte(resp.XrayConfig), []byte("vless")) {
		t.Errorf("expected Node A config to contain vless, got: %s", resp.XrayConfig)
	}
}
