package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/store"
)

// setupTestServer builds a minimal DB-backed server rooted at a temp data dir,
// runs setup reconciliation, and wires the setup + login routes.
func setupTestServer(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	db, err := store.Open(filepath.Join(dir, "forgepanel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	s := &Server{cfg: cfg, db: db, router: gin.New(), signer: auth.NewSigner([]byte("test-secret")), login: newLoginLimiter()}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.reconcileSetup(); err != nil {
		t.Fatalf("reconcileSetup: %v", err)
	}
	r := gin.New()
	r.GET("/api/setup/status", s.handleSetupStatus)
	r.POST("/api/setup/init", s.handleSetupInit)
	r.POST("/api/login", s.handleLogin)
	return s, r
}

func post(t *testing.T, r *gin.Engine, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestPasswordPolicy(t *testing.T) {
	cases := []struct {
		pw string
		ok bool
	}{
		{"short", false},          // too short
		{"alllowercase", false},   // one class only
		{"1234567890", false},     // one class only
		{"Sup3rSecret!", true},    // 3 classes, long enough
		{"abcdefghij1", true},     // letters + digit, >=10
		{"abcdefghijklmn", false}, // 14 letters, one class
		{"Password12", true},      // letters + digits
	}
	for _, c := range cases {
		err := validatePasswordPolicy(c.pw)
		if (err == nil) != c.ok {
			t.Errorf("policy(%q): got err=%v, want ok=%v", c.pw, err, c.ok)
		}
	}
}

func TestSetupFlow(t *testing.T) {
	s, r := setupTestServer(t)
	token := s.cfg.Panel().SetupToken
	if token == "" {
		t.Fatal("expected a setup token to be minted")
	}
	if s.SetupToken != token {
		t.Fatal("server SetupToken should mirror the panel token")
	}

	// status: required
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "true") {
		t.Fatalf("setup should be required: %s", rec.Body.String())
	}

	// wrong token
	if code, _ := post(t, r, "/api/setup/init", `{"token":"nope","username":"a","password":"Sup3rSecret!","password_confirm":"Sup3rSecret!"}`); code != 401 {
		t.Fatalf("wrong token: want 401 got %d", code)
	}
	// weak password
	if code, _ := post(t, r, "/api/setup/init", `{"token":"`+token+`","username":"a","password":"weak","password_confirm":"weak"}`); code != 400 {
		t.Fatalf("weak pw: want 400 got %d", code)
	}
	// mismatch
	if code, _ := post(t, r, "/api/setup/init", `{"token":"`+token+`","username":"a","password":"Sup3rSecret!","password_confirm":"Other12345"}`); code != 400 {
		t.Fatalf("mismatch: want 400 got %d", code)
	}
	// valid
	if code, _ := post(t, r, "/api/setup/init", `{"token":"`+token+`","username":"owner","password":"Sup3rSecret!","password_confirm":"Sup3rSecret!"}`); code != 200 {
		t.Fatalf("valid init: want 200 got %d", code)
	}

	// setup now disabled: token cleared, status false, re-init 409
	if s.cfg.Panel().SetupToken != "" || !s.cfg.Panel().SetupCompleted {
		t.Fatal("token should be cleared and setup marked complete")
	}
	if s.setupRequired() {
		t.Fatal("setup should no longer be required")
	}
	if code, _ := post(t, r, "/api/setup/init", `{"token":"`+token+`","username":"x","password":"Sup3rSecret!","password_confirm":"Sup3rSecret!"}`); code != 409 {
		t.Fatalf("re-init: want 409 got %d", code)
	}

	// login with the created account works
	code, out := post(t, r, "/api/login", `{"username":"owner","password":"Sup3rSecret!"}`)
	if code != 200 || out["access_token"] == nil {
		t.Fatalf("login after setup failed: %d %v", code, out)
	}
}

func TestSetupExpiredToken(t *testing.T) {
	s, r := setupTestServer(t)
	token := s.cfg.Panel().SetupToken
	// Force the token to have expired.
	s.cfg.Panel().SetupExpires = time.Now().Add(-time.Hour).Format(time.RFC3339)
	_ = s.cfg.SavePanel()
	if code, out := post(t, r, "/api/setup/init", `{"token":"`+token+`","username":"a","password":"Sup3rSecret!","password_confirm":"Sup3rSecret!"}`); code != 401 || !strings.Contains(toStr(out["error"]), "expired") {
		t.Fatalf("expired token: want 401/expired, got %d %v", code, out)
	}
}

func TestUpgradeMarksSetupCompleted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, _ := config.Load()
	db, _ := store.Open(filepath.Join(dir, "forgepanel.db"))
	t.Cleanup(func() { _ = db.Close() })
	// Existing install: an admin already present before reconcile.
	hash, _ := auth.HashPassword("Sup3rSecret!")
	if err := db.CreateAdmin(&store.Admin{Username: "old", PasswordHash: hash, Role: store.RoleOwner}); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, db: db, router: gin.New(), signer: auth.NewSigner([]byte("x")), login: newLoginLimiter()}
	if err := s.reconcileSetup(); err != nil {
		t.Fatal(err)
	}
	if !cfg.Panel().SetupCompleted || cfg.Panel().SetupToken != "" || s.SetupToken != "" {
		t.Fatalf("existing install should be marked complete with no token: %+v", cfg.Panel())
	}
	if s.setupRequired() {
		t.Fatal("setup must not be required when an admin already exists")
	}
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
