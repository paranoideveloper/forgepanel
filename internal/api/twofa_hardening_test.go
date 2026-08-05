package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// twofaServer builds a DB-backed server with one 2FA-enabled owner and the login
// route mounted, plus the session validator the real constructor installs.
func twofaServer(t *testing.T) (*Server, *store.Admin, string) {
	t.Helper()
	s := dbServerT(t)

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	admin := &store.Admin{Username: "owner", PasswordHash: hash,
		Role: store.RoleOwner, TOTPSecret: secret}
	if err := s.db.CreateAdmin(admin); err != nil {
		t.Fatal(err)
	}

	s.signer.SetSessionValidator(func(adminID, epoch uint) bool {
		cur, err := s.db.AdminSessionEpoch(adminID)
		if err != nil {
			return false
		}
		return epoch >= cur
	})

	r := gin.New()
	r.POST("/login", s.handleLogin)
	r.POST("/refresh", s.handleRefresh)
	authed := r.Group("/api", s.signer.Middleware())
	authed.GET("/me", s.handleMe)
	s.router = r
	return s, admin, secret
}

func postJSON(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func loginWithTOTP(t *testing.T, s *Server, code string) *httptest.ResponseRecorder {
	t.Helper()
	return postJSON(t, s, "/login", fmt.Sprintf(
		`{"username":"owner","password":"correct-horse-battery","totp":%q}`, code))
}

// TestTOTPCodeCannotBeReplayed is the §"TOTP correctness" regression: a code
// stays valid across the skew window, so without recording the used time step an
// intercepted code can be replayed for up to 90 seconds.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	s, _, secret := twofaServer(t)
	code, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if rec := loginWithTOTP(t, s, code); rec.Code != 200 {
		t.Fatalf("first login with a valid code failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := loginWithTOTP(t, s, code); rec.Code == 200 {
		t.Fatal("the same TOTP code was accepted twice — replay is possible")
	}
}

// TestConcurrentReplayAdmitsExactlyOne: the used-step claim must be a
// compare-and-set, not a read-then-write.
func TestConcurrentReplayAdmitsExactlyOne(t *testing.T) {
	s, _, secret := twofaServer(t)
	code, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	accepted := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := loginWithTOTP(t, s, code)
			if rec.Code == 200 {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("%d concurrent logins accepted the same TOTP code, want exactly 1", accepted)
	}
}

// TestFreshTOTPStepStillWorks guards against the replay check locking the
// account out on the next step.
func TestFreshTOTPStepStillWorks(t *testing.T) {
	s, admin, secret := twofaServer(t)
	past, err := auth.TOTPCode(secret, time.Now().Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_ = past
	code, _ := auth.TOTPCode(secret, time.Now())
	if rec := loginWithTOTP(t, s, code); rec.Code != 200 {
		t.Fatalf("login failed: %d", rec.Code)
	}
	// A code from a LATER step must still be accepted.
	next, _ := auth.TOTPCode(secret, time.Now().Add(30*time.Second))
	if next == code {
		t.Skip("clock landed on a step boundary")
	}
	if rec := loginWithTOTP(t, s, next); rec.Code != 200 {
		fresh, _ := s.db.AdminByUsername(admin.Username)
		t.Fatalf("a later TOTP step was rejected (last step %d): %d",
			fresh.LastTOTPStep, rec.Code)
	}
}

// TestRecoveryCodeLoginRevokesOtherSessions: a recovery-code login means the
// owner lost their authenticator, which is exactly when an attacker may already
// hold a session. It must not survive.
func TestRecoveryCodeLoginRevokesOtherSessions(t *testing.T) {
	s, admin, secret := twofaServer(t)

	// An existing session (say, the attacker's).
	code, _ := auth.TOTPCode(secret, time.Now())
	rec := loginWithTOTP(t, s, code)
	if rec.Code != 200 {
		t.Fatalf("setup login failed: %d", rec.Code)
	}
	var first struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if !tokenWorks(t, s, first.Access) {
		t.Fatal("setup: the first token should work")
	}

	// The owner recovers with a recovery code.
	codes, err := s.generateRecoveryCodes(admin.ID, 4)
	if err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, s, "/login", fmt.Sprintf(
		`{"username":"owner","password":"correct-horse-battery","recovery_code":%q}`, codes[0]))
	if rec.Code != 200 {
		t.Fatalf("recovery-code login failed: %d %s", rec.Code, rec.Body.String())
	}
	var second struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}

	if tokenWorks(t, s, first.Access) {
		t.Fatal("the pre-existing session survived a recovery-code login")
	}
	if !tokenWorks(t, s, second.Access) {
		t.Fatal("the recovering owner's own new token was rejected")
	}
}

// TestRecoveryCodeIsSingleUse pins the one-time property.
func TestRecoveryCodeIsSingleUse(t *testing.T) {
	s, admin, _ := twofaServer(t)
	codes, err := s.generateRecoveryCodes(admin.ID, 4)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"username":"owner","password":"correct-horse-battery","recovery_code":%q}`, codes[0])
	if rec := postJSON(t, s, "/login", body); rec.Code != 200 {
		t.Fatalf("first use failed: %d", rec.Code)
	}
	if rec := postJSON(t, s, "/login", body); rec.Code == 200 {
		t.Fatal("a recovery code was accepted twice")
	}
}

// TestRevokedSessionCannotRefresh: the refresh endpoint must not launder a
// revoked session into a fresh access token.
func TestRevokedSessionCannotRefresh(t *testing.T) {
	s, admin, secret := twofaServer(t)
	code, _ := auth.TOTPCode(secret, time.Now())
	rec := loginWithTOTP(t, s, code)
	var tok struct {
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	if err := s.db.BumpAdminSessionEpoch(admin.ID); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, s, "/refresh", fmt.Sprintf(`{"refresh_token":%q}`, tok.Refresh))
	if rec.Code == 200 {
		t.Fatal("a revoked session refreshed itself back into a valid access token")
	}
}

// TestRecoveryCodesStoredAsHashes: the plaintext must never be persisted.
func TestRecoveryCodesStoredAsHashes(t *testing.T) {
	s, admin, _ := twofaServer(t)
	codes, err := s.generateRecoveryCodes(admin.ID, 4)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.db.AdminByUsername("owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		if strings.Contains(fresh.RecoveryCodes, c) {
			t.Fatalf("plaintext recovery code %q found in storage", c)
		}
	}
	if n := recoveryRemaining(fresh.RecoveryCodes); n != 4 {
		t.Fatalf("remaining = %d, want 4", n)
	}
}

func tokenWorks(t *testing.T, s *Server, access string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec.Code == 200
}
