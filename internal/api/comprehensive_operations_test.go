package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func createComprehensiveTestServer(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	// Detach from the host's live socket table. The port-collision guard now runs
	// on the real inbound routes, and these tests create inbounds on 443/8443 —
	// ports a developer machine or CI box very often already serves. Without this
	// the suite would pass or fail depending on what else the host happens to be
	// running, which tests the box rather than the code. Inbound-vs-inbound
	// collision detection is unaffected and still exercised here; the host-holder
	// branch has its own tests in portcheck_test.go.
	oldListeners := hostListeners
	hostListeners = func() []firewall.Listener { return nil }
	t.Cleanup(func() { hostListeners = oldListeners })

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

	admin := &store.Admin{
		Username:     "admin",
		PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$dummyhash",
		Role:         store.RoleOwner,
	}
	if err := s.db.CreateAdmin(admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	token, _, err := s.signer.Issue(admin.ID, "admin", string(admin.Role))
	if err != nil {
		t.Fatalf("Issue token: %v", err)
	}

	return s, s.db, token
}

func TestAPI_ClientManagementFlow(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	// 1. Add Client (Create User)
	createUserReq := map[string]any{
		"username":      "alice",
		"data_limit_gb": 10, // 10 GB
	}
	body, _ := json.Marshal(createUserReq)
	req := httptest.NewRequest("POST", "/api/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create user expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var userResp store.User
	json.Unmarshal(w.Body.Bytes(), &userResp)
	if userResp.ID == 0 {
		t.Fatalf("user object missing or ID 0: %s", w.Body.String())
	}
	userID := userResp.ID

	// 2. Change Client (Patch User)
	patchReq := map[string]any{
		"data_limit":     21474836480, // 20 GB
		"status":         "active",
		"reset_strategy": "month",
		"note":           "VIP user",
	}
	body, _ = json.Marshal(patchReq)
	req = httptest.NewRequest("PATCH", "/api/admin/users/"+strconv.FormatUint(uint64(userID), 10), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Patch user expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify in DB
	u, err := st.UserByID(userID)
	if err != nil || u.DataLimit != 21474836480 || u.Note != "VIP user" {
		t.Fatalf("User patch not reflected in DB: %+v, err: %v", u, err)
	}

	// 3. Remove Client (Delete User)
	req = httptest.NewRequest("DELETE", "/api/admin/users/"+strconv.FormatUint(uint64(userID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete user expected 200, got %d: %s", w.Code, w.Body.String())
	}

	_, err = st.UserByID(userID)
	if err == nil {
		t.Fatalf("User should be deleted from DB")
	}
}

func TestAPI_InboundAndAssignmentsFlow(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	// 1. Add Inbound
	createInboundReq := map[string]any{
		"tag":      "vless-main",
		"protocol": "vless",
		"port":     443,
		"flow":     "xtls-rprx-vision",
	}
	body, _ := json.Marshal(createInboundReq)
	req := httptest.NewRequest("POST", "/api/admin/inbounds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create inbound expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var inResp store.Inbound
	json.Unmarshal(w.Body.Bytes(), &inResp)
	if inResp.ID == 0 {
		t.Fatalf("Inbound ID zero")
	}

	// 1b. Update Inbound
	updateInboundReq := map[string]any{
		"remark":   "vless-updated",
		"protocol": "vless",
		"port":     8443,
		"flow":     "xtls-rprx-vision",
	}
	upBody, _ := json.Marshal(updateInboundReq)
	// The port changes (443 → 8443), which the safe-edit guard (BUG-4) treats as
	// a breaking change; confirm it explicitly.
	upReq := httptest.NewRequest("PUT", "/api/admin/inbounds/"+strconv.FormatUint(uint64(inResp.ID), 10)+"?confirm=true", bytes.NewReader(upBody))
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Authorization", "Bearer "+token)
	upW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(upW, upReq)
	if upW.Code != http.StatusOK {
		t.Fatalf("Update inbound expected 200, got %d: %s", upW.Code, upW.Body.String())
	}

	// 2. List Inbounds
	req = httptest.NewRequest("GET", "/api/admin/inbounds", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List inbounds expected 200, got %d", w.Code)
	}

	// 3. Create User & Assign Inbound
	user := &store.User{Username: "bob", Status: store.StatusActive, SubToken: "subbob"}
	st.CreateUser(user)

	setInboundReq := map[string]any{
		"inbound_ids": []uint{inResp.ID},
	}
	body, _ = json.Marshal(setInboundReq)
	req = httptest.NewRequest("PUT", "/api/admin/users/"+strconv.FormatUint(uint64(user.ID), 10)+"/inbounds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Set user inbounds expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Delete Inbound
	req = httptest.NewRequest("DELETE", "/api/admin/inbounds/"+strconv.FormatUint(uint64(inResp.ID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete inbound expected 200, got %d", w.Code)
	}
}

func TestAPI_NodeManagementFlow(t *testing.T) {
	srv, _, token := createComprehensiveTestServer(t)

	// 1. Enroll Node
	enrollReq := map[string]any{
		"name":    "node-sg-1",
		"address": "128.199.1.1",
	}
	body, _ := json.Marshal(enrollReq)
	req := httptest.NewRequest("POST", "/api/admin/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Enroll node expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var enrollResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &enrollResp)
	nodeID := uint(enrollResp["id"].(float64))
	enrollToken := enrollResp["token"].(string)

	// 2. Node Register Agent
	regReq := map[string]any{
		"token":        enrollToken,
		"core_version": "Xray 1.8.4",
	}
	body, _ = json.Marshal(regReq)
	req = httptest.NewRequest("POST", "/api/node/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Node register expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Node Heartbeat
	hbReq := map[string]any{
		"token":  enrollToken,
		"cpu":    15.5,
		"mem_mb": 512,
	}
	body, _ = json.Marshal(hbReq)
	req = httptest.NewRequest("POST", "/api/node/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Node heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. List Nodes
	req = httptest.NewRequest("GET", "/api/admin/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List nodes expected 200, got %d", w.Code)
	}

	// 5. Delete Node
	req = httptest.NewRequest("DELETE", "/api/admin/nodes/"+strconv.FormatUint(uint64(nodeID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete node expected 200, got %d", w.Code)
	}
}

func TestAPI_TrafficAndStats(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	// Create user & inbound
	u := &store.User{Username: "charlie", Status: store.StatusActive, DataLimit: 1000}
	st.CreateUser(u)
	n := &model.Node{Tag: "in-1", Protocol: model.ProtoVLESS, Port: 443}
	st.CreateInbound(n)

	// Get Stats
	req := httptest.NewRequest("GET", "/api/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Get stats expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check Quota
	req = httptest.NewRequest("GET", "/api/admin/quota", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Get quota expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
