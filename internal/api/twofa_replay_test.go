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

// Replay protection on the 2FA MANAGEMENT flows.
//
// Login has claimed the used time step since the beginning; enable, disable and
// recovery-code regeneration called VerifyTOTP, which passes lastUsed = -1 and
// so skips the check entirely. That left the dangerous half unprotected: a code
// observed once stays valid for up to 90 seconds across the skew window, and
// replaying it at 2fa/disable turns the second factor OFF.

// twofaMgmtServer is twofaServer plus the management routes, behind the real
// session middleware so the handlers get the claims they read.
func twofaMgmtServer(t *testing.T) (*Server, *store.Admin, string, string) {
	t.Helper()
	s, admin, secret := twofaServer(t)

	r := gin.New()
	r.POST("/login", s.handleLogin)
	authed := r.Group("/api/admin", s.signer.Middleware())
	authed.POST("/2fa/setup", s.handle2FASetup)
	authed.POST("/2fa/enable", s.handle2FAEnable)
	authed.POST("/2fa/disable", s.handle2FADisable)
	authed.POST("/2fa/recovery/regenerate", s.handle2FARecoveryRegenerate)
	s.router = r

	// A session to act with. It spends a step, so every test below takes its
	// codes from a LATER step than this login used.
	code, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, s, "/login", fmt.Sprintf(
		`{"username":"owner","password":"correct-horse-battery","totp":%q}`, code))
	if rec.Code != 200 {
		t.Fatalf("setup login: %d %s", rec.Code, rec.Body.String())
	}
	var tok struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	return s, admin, secret, tok.Access
}

func postAuthed(t *testing.T, s *Server, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

// nextStepCode returns the code for the step AFTER the current one.
//
// One step, not two: the verifier only tries counter-1, counter and counter+1
// (RFC 6238 §5.2 skew), so a code from further out is invalid no matter what the
// replay check does. The harness login has already spent the current step, so
// counter+1 is the only step left that a management call can legitimately use.
func nextStepCode(t *testing.T, secret string) string {
	t.Helper()
	c, err := auth.TOTPCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// currentStep is the RFC 6238 time step now, for tests that need to place the
// account's last-used step relative to it.
func currentStep() int64 { return time.Now().Unix() / 30 }

// The headline case, ordered so the replay attempt actually reaches the
// handler.
//
// Written the obvious way — disable, then disable again with the same code — it
// passes whether or not the fix is present: the first disable revokes every
// session, so the second request is refused by the middleware with a 401 before
// any code is checked. Spending the code at a flow that does NOT revoke
// sessions first, and then trying to disable with it, tests the thing.
func TestACodeSpentElsewhereCannotThenDisable2FA(t *testing.T) {
	s, _, secret, token := twofaMgmtServer(t)
	code := nextStepCode(t, secret)

	rec := postAuthed(t, s, "/api/admin/2fa/recovery/regenerate", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		t.Fatalf("spending the code at regenerate: %d %s", rec.Code, rec.Body.String())
	}

	rec = postAuthed(t, s, "/api/admin/2fa/disable", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code == 200 {
		t.Fatal("a code already spent elsewhere was replayed to turn 2FA off")
	}
}

// Regenerating recovery codes with a replayed code hands an attacker a fresh
// set of single-use bypasses for the account.
func TestRegeneratingRecoveryCodesRefusesAReplayedCode(t *testing.T) {
	s, _, secret, token := twofaMgmtServer(t)
	code := nextStepCode(t, secret)

	rec := postAuthed(t, s, "/api/admin/2fa/recovery/regenerate", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		t.Fatalf("first regenerate: %d %s", rec.Code, rec.Body.String())
	}
	rec = postAuthed(t, s, "/api/admin/2fa/recovery/regenerate", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code == 200 {
		t.Fatal("a replayed code minted a second set of recovery codes")
	}
}

// The code spent turning 2FA ON must not still be usable to turn it back OFF.
func TestTheEnableCodeCannotBeReplayedAtDisable(t *testing.T) {
	s, admin, _, token := twofaMgmtServer(t)

	// Start from an account with 2FA off, then run the real setup/enable pair.
	admin.TOTPSecret = ""
	if err := s.db.SaveAdmin(admin); err != nil {
		t.Fatal(err)
	}

	rec := postAuthed(t, s, "/api/admin/2fa/setup", token, `{}`)
	if rec.Code != 200 {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}

	code := nextStepCode(t, setup.Secret)
	rec = postAuthed(t, s, "/api/admin/2fa/enable", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	// Enabling revokes every session and returns a fresh pair. Reusing the old
	// token here would get a 401 from the middleware and the test would pass
	// without the handler ever seeing the replayed code.
	var enabled struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enabled); err != nil {
		t.Fatal(err)
	}
	if enabled.Access == "" {
		t.Fatal("enable returned no fresh access token, so the replay cannot be attempted authenticated")
	}

	rec = postAuthed(t, s, "/api/admin/2fa/disable", enabled.Access, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code == 200 {
		t.Fatal("the code that enabled 2FA was replayed to disable it")
	}
}

// The claim must be a compare-and-set, not a read-then-write: two requests
// arriving together with one code must not both win.
func TestConcurrentDisableAdmitsExactlyOne(t *testing.T) {
	s, _, secret, token := twofaMgmtServer(t)
	code := nextStepCode(t, secret)

	var mu sync.Mutex
	var bodies []string
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := postAuthed(t, s, "/api/admin/2fa/disable", token,
				fmt.Sprintf(`{"code":%q}`, code))
			mu.Lock()
			bodies = append(bodies, fmt.Sprintf("%d %s", rec.Code, strings.TrimSpace(rec.Body.String())))
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Count the disables that actually SPENT the code, not every 200.
	//
	// Two other outcomes are legitimate and were miscounted at first: the loser
	// of the race can arrive after 2FA is already off and take the idempotent
	// early return ({"enabled":false}, no code consumed), and the rest get 401
	// because a successful disable revokes every session. Only the real path
	// reports sessions_revoked.
	real := 0
	for _, b := range bodies {
		if strings.Contains(b, `"sessions_revoked":true`) {
			real++
		}
	}
	if real != 1 {
		t.Fatalf("%d concurrent disables actually spent the code, want exactly 1:\n  %s",
			real, strings.Join(bodies, "\n  "))
	}
}

// The protection must not lock the operator out. Expressed as "a code newer
// than the last spent step is accepted", because that is the actual rule: two
// successive accepted codes cannot both exist at one wall-clock instant, since
// the acceptance window is a single step wide either side of now.
func TestAFreshCodeIsAcceptedAfterAnEarlierStepWasSpent(t *testing.T) {
	s, admin, secret, token := twofaMgmtServer(t)

	// Put the account's last-used step just behind the current one, as it would
	// be a minute after an ordinary login.
	fresh, err := s.db.AdminByUsername(admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	fresh.LastTOTPStep = currentStep() - 1
	if err := s.db.SaveAdmin(fresh); err != nil {
		t.Fatal(err)
	}

	code, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := postAuthed(t, s, "/api/admin/2fa/recovery/regenerate", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		again, _ := s.db.AdminByUsername(admin.Username)
		t.Fatalf("a code newer than the last spent step was rejected (last step %d, now %d): %d %s",
			again.LastTOTPStep, currentStep(), rec.Code, rec.Body.String())
	}
}

// Falling back to the password must still work — the code path that spends a
// step must not swallow the password branch.
func TestRegenerateStillAcceptsThePasswordInstead(t *testing.T) {
	s, _, _, token := twofaMgmtServer(t)
	rec := postAuthed(t, s, "/api/admin/2fa/recovery/regenerate", token,
		`{"password":"correct-horse-battery"}`)
	if rec.Code != 200 {
		t.Fatalf("password reauth: %d %s", rec.Code, rec.Body.String())
	}
}

// A spent step must not be written back by a later SaveAdmin in the same
// handler — that would silently un-spend the code.
func TestTheClaimedStepSurvivesTheHandlersOwnSave(t *testing.T) {
	s, admin, secret, token := twofaMgmtServer(t)
	code := nextStepCode(t, secret)

	before, err := s.db.AdminByUsername(admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	rec := postAuthed(t, s, "/api/admin/2fa/disable", token, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	after, err := s.db.AdminByUsername(admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastTOTPStep <= before.LastTOTPStep {
		t.Fatalf("last step went from %d to %d: the handler's SaveAdmin wrote back the stale value, "+
			"leaving the code spendable again", before.LastTOTPStep, after.LastTOTPStep)
	}
}
