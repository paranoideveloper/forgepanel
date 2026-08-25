package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// End-to-end through the real router: creating a reseller was impossible, so
// every quota check in the repository layer guarded a case that could not occur.

func adminAPI(t *testing.T) (*Server, string) {
	t.Helper()
	s, _, token := createComprehensiveTestServer(t)
	return s, token
}

func TestCreateAndListResellerThroughTheAPI(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "reseller1", "password": "hunter2hunter2",
		"role": "reseller", "user_quota": 50, "traffic_credit": 1 << 30,
	})
	if code != 201 {
		t.Fatalf("creating a reseller returned %d: %s", code, body)
	}
	var created adminView
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if created.Role != "reseller" || created.UserQuota != 50 {
		t.Fatalf("created account is wrong: %+v", created)
	}
	// The response must never carry secret material.
	for _, leak := range []string{"password", "hunter2", "password_hash", "totp"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("the create response leaks %q: %s", leak, body)
		}
	}

	code, body = doGET(t, s, "/api/admin/admins", token)
	if code != 200 {
		t.Fatalf("listing admins returned %d: %s", code, body)
	}
	var list []adminView
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 { // the setup owner plus the new reseller
		t.Fatalf("expected 2 admins, got %d: %s", len(list), body)
	}
}

func TestDuplicateUsernameIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	body := map[string]any{"username": "dup", "password": "hunter2hunter2", "role": "reseller"}
	if code, _ := realPost(t, s, "/api/admin/admins", token, body); code != 201 {
		t.Fatal("setup create failed")
	}
	code, resp := realPost(t, s, "/api/admin/admins", token, body)
	if code != http.StatusConflict {
		t.Fatalf("a duplicate username returned %d, want 409: %s", code, resp)
	}
}

// An unknown role matches no authorization rule and fails closed, so the account
// would exist, sign in, and be able to do nothing with nothing explaining why.
func TestUnknownRoleIsRefusedAtCreate(t *testing.T) {
	s, token := adminAPI(t)
	code, resp := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "weird", "password": "hunter2hunter2", "role": "superuser",
	})
	if code != 400 {
		t.Fatalf("an unknown role returned %d, want 400: %s", code, resp)
	}
	if !strings.Contains(resp, "reseller") {
		t.Errorf("the error should list the valid roles: %s", resp)
	}
}

func TestShortPasswordIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	code, _ := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "weak", "password": "short", "role": "viewer",
	})
	if code != 400 {
		t.Fatalf("a 5-character password returned %d, want 400", code)
	}
}

// Deleting an admin that owns users must say where they go. Orphaned users
// belong to nobody: no reseller sees them and nothing can manage them, while
// they keep being served.
func TestDeletingAnAdminWithUsersRefusesAndSaysWhy(t *testing.T) {
	s, token := adminAPI(t)
	code, body := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "owns-users", "password": "hunter2hunter2", "role": "reseller",
	})
	if code != 201 {
		t.Fatalf("setup: %d %s", code, body)
	}
	var created adminView
	_ = json.Unmarshal([]byte(body), &created)

	u := &store.User{Username: "theirs", SubToken: "tst", OwnerAdminID: created.ID}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	code, resp := doDELETE(t, s, "/api/admin/admins/"+itoa(int(created.ID)), token)
	if code != http.StatusConflict {
		t.Fatalf("deleting an admin with users returned %d, want 409: %s", code, resp)
	}
	if !strings.Contains(resp, "reassign_to") {
		t.Errorf("the refusal should name the way forward: %s", resp)
	}

	// With a target it succeeds and the user moves rather than being orphaned.
	code, resp = doDELETE(t, s, "/api/admin/admins/"+itoa(int(created.ID))+"?reassign_to=1", token)
	if code != 200 {
		t.Fatalf("reassigning delete returned %d: %s", code, resp)
	}
	got, err := s.db.UserByID(u.ID)
	if err != nil {
		t.Fatalf("the user was deleted with its owner: %v", err)
	}
	if got.OwnerAdminID != 1 {
		t.Fatalf("user owner is %d, want 1", got.OwnerAdminID)
	}
}

// Losing the last owner is unrecoverable through the panel: no account could
// grant the role back.
func TestTheLastOwnerIsProtectedOverHTTP(t *testing.T) {
	s, token := adminAPI(t)
	code, resp := doPATCH(t, s, "/api/admin/admins/1", token, map[string]any{"role": "viewer"})
	if code != http.StatusConflict {
		t.Fatalf("demoting the last owner returned %d, want 409: %s", code, resp)
	}
	if !strings.Contains(resp, "last_owner") {
		t.Errorf("the refusal should carry a machine-readable code: %s", resp)
	}
	a, _ := s.db.AdminByID(1)
	if a.Role != store.RoleOwner {
		t.Fatalf("the demotion was applied anyway: %s", a.Role)
	}
}

// Changing what an account may do has to invalidate the tokens it already
// holds, or a demoted owner keeps owner access until the token expires.
func TestRoleChangeRevokesExistingSessions(t *testing.T) {
	s, token := adminAPI(t)
	code, body := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "demote-me", "password": "hunter2hunter2", "role": "admin",
	})
	if code != 201 {
		t.Fatalf("setup: %s", body)
	}
	var created adminView
	_ = json.Unmarshal([]byte(body), &created)

	before, err := s.db.AdminSessionEpoch(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if code, resp := doPATCH(t, s, "/api/admin/admins/"+itoa(int(created.ID)), token,
		map[string]any{"role": "viewer"}); code != 200 {
		t.Fatalf("role change returned %d: %s", code, resp)
	}
	after, err := s.db.AdminSessionEpoch(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("the session epoch did not move, so the account keeps its old authority")
	}
}

// An omitted quota must not be read as zero: zero means unlimited, so every
// edit would silently remove the limit.
func TestOmittedQuotaIsNotTreatedAsZero(t *testing.T) {
	s, token := adminAPI(t)
	code, body := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "quota", "password": "hunter2hunter2", "role": "reseller", "user_quota": 25,
	})
	if code != 201 {
		t.Fatalf("setup: %s", body)
	}
	var created adminView
	_ = json.Unmarshal([]byte(body), &created)

	// Change only the traffic credit.
	if code, resp := doPATCH(t, s, "/api/admin/admins/"+itoa(int(created.ID)), token,
		map[string]any{"traffic_credit": 999}); code != 200 {
		t.Fatalf("patch returned %d: %s", code, resp)
	}
	got, _ := s.db.AdminByID(created.ID)
	if got.UserQuota != 25 {
		t.Fatalf("the untouched user quota became %d, want 25", got.UserQuota)
	}
	if got.TrafficCredit != 999 {
		t.Fatalf("traffic credit is %d, want 999", got.TrafficCredit)
	}
}

// --- request helpers -------------------------------------------------------
//
// These drive the SERVER's own handler chain rather than a router the test
// assembles, so the authorization middleware is in the path.

func adminReq(t *testing.T, s *Server, method, path, token string, body map[string]any) (int, string) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func doGET(t *testing.T, s *Server, path, token string) (int, string) {
	return adminReq(t, s, http.MethodGet, path, token, nil)
}

func doDELETE(t *testing.T, s *Server, path, token string) (int, string) {
	return adminReq(t, s, http.MethodDelete, path, token, nil)
}

func doPATCH(t *testing.T, s *Server, path, token string, body map[string]any) (int, string) {
	return adminReq(t, s, http.MethodPatch, path, token, body)
}
