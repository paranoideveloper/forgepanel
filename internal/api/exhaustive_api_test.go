package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func TestAPI_GroupEndpoints(t *testing.T) {
	srv, _, token := createComprehensiveTestServer(t)

	// Create Group
	createReq := map[string]any{
		"name":        "Group A",
		"description": "First group",
		"is_default":  true,
	}
	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest("POST", "/api/admin/groups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create group expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var grp store.Group
	json.Unmarshal(w.Body.Bytes(), &grp)
	if grp.ID == 0 {
		t.Fatalf("Group ID zero")
	}

	// List Groups
	req = httptest.NewRequest("GET", "/api/admin/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List groups expected 200, got %d", w.Code)
	}

	// Get Group
	req = httptest.NewRequest("GET", "/api/admin/groups/"+strconv.FormatUint(uint64(grp.ID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Get group expected 200, got %d", w.Code)
	}

	// Update Group
	patchReq := map[string]any{
		"name": "Group A Updated",
	}
	body, _ = json.Marshal(patchReq)
	req = httptest.NewRequest("PATCH", "/api/admin/groups/"+strconv.FormatUint(uint64(grp.ID), 10), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Update group expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Delete Group
	req = httptest.NewRequest("DELETE", "/api/admin/groups/"+strconv.FormatUint(uint64(grp.ID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete group expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_InboundConfigAndPortHop(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	n := &model.Node{Tag: "tag1", Protocol: model.ProtoVLESS, Port: 443}
	in, err := st.CreateInbound(n)
	if err != nil {
		t.Fatalf("CreateInbound: %v", err)
	}

	// Inbound Config
	req := httptest.NewRequest("GET", "/api/admin/inbounds/"+strconv.FormatUint(uint64(in.ID), 10)+"/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Inbound config expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Port Hop
	req = httptest.NewRequest("GET", "/api/admin/inbounds/"+strconv.FormatUint(uint64(in.ID), 10)+"/porthop", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Port hop expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_UserGetAndList(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	u := &store.User{Username: "testuser", Status: store.StatusActive, SubToken: "subtoken99"}
	st.CreateUser(u)

	// List Users
	req := httptest.NewRequest("GET", "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List users expected 200, got %d", w.Code)
	}

	// Get User
	req = httptest.NewRequest("GET", "/api/admin/users/"+strconv.FormatUint(uint64(u.ID), 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Get user expected 200, got %d", w.Code)
	}
}

func TestAPI_CapabilitiesAndDeployCompose(t *testing.T) {
	srv, _, _ := createComprehensiveTestServer(t)

	// Capabilities
	req := httptest.NewRequest("GET", "/api/capabilities", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Capabilities expected 200, got %d", w.Code)
	}

	// Deploy Compose
	req = httptest.NewRequest("GET", "/api/deploy/compose?profiles=xray", nil)
	w = httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Deploy compose expected 200, got %d", w.Code)
	}
}
