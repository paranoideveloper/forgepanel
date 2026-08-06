package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

func TestE2EPipeline_MultiNode_InboundCRUD_Sub_Engine(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	// 1. Enroll Node 1 & Node 2
	n1 := &store.Node{Name: "Edge-Node-1", Address: "192.0.2.10", EnrollToken: "tok-node-1", Healthy: true, Enrolled: true}
	if err := st.CreateNode(n1); err != nil {
		t.Fatalf("Failed to create node 1: %v", err)
	}
	n2 := &store.Node{Name: "Edge-Node-2", Address: "192.0.2.20", EnrollToken: "tok-node-2", Healthy: true, Enrolled: true}
	if err := st.CreateNode(n2); err != nil {
		t.Fatalf("Failed to create node 2: %v", err)
	}

	// 2. Create Inbound 1 via POST /api/admin/inbounds
	in1Req := map[string]any{
		"remark":   "vless-node1",
		"protocol": "vless",
		"port":     8443,
		"security": map[string]any{
			"type": "reality",
			"reality": map[string]any{
				"private_key": "SERVER-PRIV-KEY",
				"public_key":  "SERVER-PUB-KEY",
				"short_id":    "12345678",
			},
		},
	}
	body1, _ := json.Marshal(in1Req)
	req := httptest.NewRequest("POST", "/api/admin/inbounds", bytes.NewReader(body1))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/admin/inbounds 1 expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var in1Resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &in1Resp)
	in1ID := uint(in1Resp["id"].(float64))

	// Bind Inbound 1 to Node 1
	in1DB, _ := st.InboundByID(in1ID)
	in1DB.NodeID = n1.ID
	st.SaveInbound(in1DB)

	// 3. Create Inbound 2 (Global) via POST /api/admin/inbounds
	in2Req := map[string]any{
		"remark":   "vmess-global",
		"protocol": "vmess",
		"port":     9443,
	}
	body2, _ := json.Marshal(in2Req)
	req = httptest.NewRequest("POST", "/api/admin/inbounds", bytes.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/admin/inbounds 2 expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var in2Resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &in2Resp)
	in2ID := uint(in2Resp["id"].(float64))

	// 4. Test Inbound Update (PUT /api/admin/inbounds/:id)
	updateReq := map[string]any{
		"remark":   "vless-node1-updated",
		"protocol": "vless",
		"port":     8443,
		"security": map[string]any{
			"type": "reality",
			"reality": map[string]any{
				"private_key": "SERVER-PRIV-KEY",
				"public_key":  "SERVER-PUB-KEY",
				"short_id":    "87654321",
			},
		},
	}
	upBody, _ := json.Marshal(updateReq)
	req = httptest.NewRequest("PUT", "/api/admin/inbounds/"+strconv.FormatUint(uint64(in1ID), 10), bytes.NewReader(upBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/admin/inbounds/%d expected 200, got %d: %s", in1ID, w.Code, w.Body.String())
	}

	// 5. Create Group & User with StatusOnHold
	grp := &store.Group{Name: "VIP Group", InboundIDs: store.IntSlice{in1ID, in2ID}}
	if err := st.CreateGroup(grp); err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	user := &store.User{
		Username: "alice",
		UUID:     "11111111-1111-1111-1111-111111111111",
		Password: "pass-alice-123",
		SubToken: "sub-alice-token-12345",
		GroupID:  grp.ID,
		Status:   store.StatusOnHold,
	}
	if err := st.CreateUser(user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// 6. Test Subscription GET /sub/:token/links
	req = httptest.NewRequest("GET", "/sub/"+user.SubToken+"/links", nil)
	req.Host = "panel.domain.com:2053"
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /sub/:token/links expected 200, got %d: %s", w.Code, w.Body.String())
	}
	subBody := w.Body.String()
	if !strings.Contains(subBody, "192.0.2.10:8443") {
		t.Errorf("Sub links expected Node 1 IP (192.0.2.10:8443), got:\n%s", subBody)
	}
	lines := strings.Split(strings.TrimSpace(subBody), "\n")
	if len(lines) < 2 {
		t.Fatalf("Expected at least 2 link lines for user, got %d:\n%s", len(lines), subBody)
	}
	if strings.Contains(subBody, "SERVER-PRIV-KEY") {
		t.Errorf("Sub links leaked SERVER-PRIV-KEY!")
	}

	// 7. Test Node 1 Heartbeat (should include in1 + in2)
	hb1Req := map[string]any{"token": n1.EnrollToken, "cpu": 5.0, "mem_mb": 512}
	hb1Body, _ := json.Marshal(hb1Req)
	req = httptest.NewRequest("POST", "/api/node/heartbeat", bytes.NewReader(hb1Body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Node 1 heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var hb1Resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &hb1Resp)
	cfg1, _ := hb1Resp["xray_config"].(string)
	if !strings.Contains(cfg1, "8443") || !strings.Contains(cfg1, "9443") {
		t.Errorf("Node 1 config missing inbounds (expected 8443 & 9443), got:\n%s", cfg1)
	}
	if !strings.Contains(cfg1, user.UUID) {
		t.Errorf("Node 1 config missing user UUID for StatusOnHold user")
	}

	// 8. Test Node 2 Heartbeat (should include ONLY in2, NOT in1)
	hb2Req := map[string]any{"token": n2.EnrollToken, "cpu": 2.0, "mem_mb": 256}
	hb2Body, _ := json.Marshal(hb2Req)
	req = httptest.NewRequest("POST", "/api/node/heartbeat", bytes.NewReader(hb2Body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Node 2 heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var hb2Resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &hb2Resp)
	cfg2, _ := hb2Resp["xray_config"].(string)
	if strings.Contains(cfg2, "8443") {
		t.Errorf("Node 2 config unexpectedly received Node 1 specific inbound (port 8443)")
	}
	if !strings.Contains(cfg2, "9443") {
		t.Errorf("Node 2 config missing global inbound (port 9443)")
	}

	// 9. Disable user & verify subscription / node configs remove user credentials
	user.Status = store.StatusDisabled
	st.SaveUser(user)

	req = httptest.NewRequest("GET", "/sub/"+user.SubToken+"/links", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "" {
		t.Errorf("Disabled user sub expected empty body, got %d: %s", w.Code, w.Body.String())
	}
}
