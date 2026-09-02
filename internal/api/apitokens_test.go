package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The only machine credential the panel had was a full-privilege admin JWT: to
// let a monitoring script read a traffic figure you handed it something that
// could also delete every inbound. Nothing expired, and revoking meant changing
// the admin's password and breaking every other integration at once.

func withToken(t *testing.T, s *Server, method, path, secret, body string) (int, string) {
	t.Helper()
	var r *bytes.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	} else {
		r = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func mintToken(t *testing.T, s *Server, adminToken, name, scope, expiresIn string) (secret string, id uint) {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"scope":%q,"expires_in":%q}`, name, scope, expiresIn)
	code, resp := doPOST(t, s, "/api/admin/tokens", adminToken, body)
	if code != 201 {
		t.Fatalf("minting a %s token: %d %s", scope, code, resp)
	}
	var out struct {
		Secret string `json:"secret"`
		Token  struct {
			ID     uint   `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"token"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	if out.Secret == "" {
		t.Fatal("no secret returned at creation; it exists nowhere else")
	}
	return out.Secret, out.Token.ID
}

func TestAnAdminScopedTokenAuthenticates(t *testing.T) {
	s, admin := adminAPI(t)
	secret, _ := mintToken(t, s, admin, "ci", "admin", "720h")

	code, body := withToken(t, s, http.MethodGet, "/api/admin/users", secret, "")
	if code != 200 {
		t.Fatalf("an admin-scoped token could not read users: %d %s", code, body)
	}
}

func TestTheSecretIsNeverStoredOrShownAgain(t *testing.T) {
	s, admin := adminAPI(t)
	secret, _ := mintToken(t, s, admin, "once", "read", "24h")

	code, body := doGET(t, s, "/api/admin/tokens", admin)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	// A listing that could show the secret would mean it was stored, which would
	// mean a stolen database yields working credentials.
	if strings.Contains(body, secret) {
		t.Fatal("the token secret appears in the listing; it is being stored")
	}

	// And it is genuinely absent from the database, not merely filtered from the
	// response.
	toks, err := s.db.ListAPITokens(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range toks {
		if strings.Contains(tok.Hash, secret) || tok.Prefix == secret {
			t.Fatal("the secret is recoverable from the stored row")
		}
	}
}

func TestAReadOnlyTokenCannotWrite(t *testing.T) {
	s, admin := adminAPI(t)
	secret, _ := mintToken(t, s, admin, "prom", "read", "24h")

	if code, body := withToken(t, s, http.MethodGet, "/api/admin/users", secret, ""); code != 200 {
		t.Fatalf("a read token could not read: %d %s", code, body)
	}
	code, body := withToken(t, s, http.MethodPost, "/api/admin/users", secret,
		`{"username":"sneaky","data_limit_gb":1}`)
	// The whole point of a narrow scope. A read credential that can write is a
	// full credential with a misleading label.
	if code == 200 || code == 201 {
		t.Fatalf("a read-only token created a user (%d): %s", code, body)
	}
	if code != 403 {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestATokenCannotExceedItsOwner(t *testing.T) {
	s, _ := adminAPI(t)
	reseller := &store.Admin{Username: "rs", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 5}
	if err := s.db.CreateAdmin(reseller); err != nil {
		t.Fatal(err)
	}
	rtok, _, err := s.signer.Issue(reseller.ID, reseller.Username, string(store.RoleReseller))
	if err != nil {
		t.Fatal(err)
	}

	// A reseller mints an ADMIN-scoped token. If the scope were a grant rather
	// than a ceiling, minting a token would be a privilege escalation available
	// to anyone who can mint one.
	secret, _ := mintToken(t, s, rtok, "escalate", "admin", "24h")

	code, body := withToken(t, s, http.MethodGet, "/api/admin/routing/rules", secret, "")
	if code != 403 {
		t.Fatalf("a reseller's admin-scoped token reached an owner/admin route (%d): %s", code, body)
	}
}

func TestRevokingATokenStopsItImmediately(t *testing.T) {
	s, admin := adminAPI(t)
	secret, id := mintToken(t, s, admin, "leaked", "admin", "24h")

	if code, _ := withToken(t, s, http.MethodGet, "/api/admin/users", secret, ""); code != 200 {
		t.Fatal("setup: the token should work before revocation")
	}
	code, body := doDELETE(t, s, fmt.Sprintf("/api/admin/tokens/%d", id), admin)
	if code != 204 {
		t.Fatalf("revoke: %d %s", code, body)
	}
	code, body = withToken(t, s, http.MethodGet, "/api/admin/users", secret, "")
	if code != 401 {
		t.Fatalf("a revoked token still works (%d): %s", code, body)
	}
	// The holder needs to know WHICH it is: renew, or go and ask why.
	if !strings.Contains(body, "revoked") {
		t.Errorf("the refusal does not say the token was revoked: %s", body)
	}

	// The ROW survives revocation, so audit entries naming it still resolve.
	toks, _ := s.db.ListAPITokens(0)
	found := false
	for _, tok := range toks {
		if tok.ID == id {
			found = true
			if tok.RevokedAt == nil {
				t.Error("the token is not marked revoked")
			}
		}
	}
	if !found {
		t.Error("revocation deleted the row; every audit entry naming it now dangles")
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	s, admin := adminAPI(t)
	secret, id := mintToken(t, s, admin, "shortlived", "admin", "24h")

	// Backdate the expiry rather than waiting for one: the property under test
	// is that an elapsed expiry is refused, not how long a clock takes.
	past := time.Now().Add(-time.Hour)
	if err := s.db.SetAPITokenExpiry(id, &past); err != nil {
		t.Fatal(err)
	}
	code, body := withToken(t, s, http.MethodGet, "/api/admin/users", secret, "")
	if code != 401 {
		t.Fatalf("an expired token still works (%d): %s", code, body)
	}
	if !strings.Contains(body, "expired") {
		t.Errorf("the refusal does not say the token expired: %s", body)
	}
}

func TestAGarbageTokenIsRefusedWithoutLeakingWhichPartWasWrong(t *testing.T) {
	s, admin := adminAPI(t)
	secret, _ := mintToken(t, s, admin, "real", "admin", "24h")
	prefix := strings.Split(secret, "_")[1]

	_, wrongSecret := withToken(t, s, http.MethodGet, "/api/admin/users",
		"fp_"+prefix+"_wrongsecretvalue", "")
	_, unknownPrefix := withToken(t, s, http.MethodGet, "/api/admin/users",
		"fp_nosuchprefix_whatever", "")

	// Identical messages. Distinguishing "this prefix exists but the secret is
	// wrong" from "no such token" tells an attacker which prefixes are real.
	if wrongSecret != unknownPrefix {
		t.Errorf("a wrong secret and an unknown prefix give different answers:\n  %s\n  %s",
			wrongSecret, unknownPrefix)
	}
	// Both must have reached the LOOKUP, not been rejected as malformed. An
	// earlier version of this test passed because the token format was broken
	// and both inputs failed to parse — identical answers for the wrong reason,
	// proving nothing about the lookup at all.
	if strings.Contains(wrongSecret, "malformed") {
		t.Fatalf("neither request reached the token lookup: %s", wrongSecret)
	}
	if !strings.Contains(wrongSecret, "unknown API token") {
		t.Errorf("unexpected refusal: %s", wrongSecret)
	}
}

func TestAScopeIsRequiredAndNotGuessed(t *testing.T) {
	s, admin := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/tokens", admin, `{"name":"noscope","expires_in":"24h"}`)
	// A safe default silently breaks integrations; a useful default silently
	// over-grants. Neither is acceptable, so it is required.
	if code == 201 {
		t.Fatalf("a token was minted with no scope: %s", body)
	}
	if code, body = doPOST(t, s, "/api/admin/tokens", admin,
		`{"name":"n","scope":"superuser","expires_in":"24h"}`); code == 201 {
		t.Fatalf("an unknown scope was accepted: %s", body)
	}
}

func TestATokenIsNamedSoItCanBeRevokedLater(t *testing.T) {
	s, admin := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/tokens", admin, `{"scope":"read","expires_in":"24h"}`)
	if code == 201 {
		t.Fatalf("an anonymous token was minted: %s — a list of unnamed credentials "+
			"cannot be audited or safely revoked: %s", body, body)
	}
}
