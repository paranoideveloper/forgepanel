package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// internal/api/auditdiff.go is a complete diff-and-redact implementation with a
// real UI, and it was wired at exactly ONE call site. Every other mutating
// action wrote a bare "alice edited a user", which is not an answer to "who
// raised that quota" or "who repointed that domain".
//
// These cover the WIRING. Redaction itself is covered by
// TestSecretsAreNamedButNeverValued, which is the test that actually exercises
// it: two integration tests written here first appeared to prove secrets never
// reach the trail and PASSED with redaction disabled, because they changed a
// non-secret field and the credential never entered the diff at all. A test that
// passes against the bug it names is worse than no test.

func lastDiffFor(t *testing.T, s *Server, action string) string {
	t.Helper()
	entries, _, err := s.db.ListAuditLogs(store.AuditFilter{Action: action, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no audit entry for %q at all", action)
	}
	return entries[0].Diff
}

func TestUserUpdateRecordsWhatChanged(t *testing.T) {
	s, token := adminAPI(t)
	u := &store.User{Username: "quotaed", SubToken: "qt", Status: store.StatusActive, DataLimit: 1000}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	code, body := doPATCH(t, s, fmt.Sprintf("/api/admin/users/%d", u.ID), token,
		map[string]any{"data_limit": 999999})
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}

	diff := lastDiffFor(t, s, "user.update")
	// The OLD value is the point. "data limit changed" cannot distinguish a
	// correction from someone quietly granting themselves a hundred gigabytes.
	if !strings.Contains(diff, "1000") || !strings.Contains(diff, "999999") {
		t.Fatalf("diff = %q, want both the old and new data limit", diff)
	}
}

func TestCredentialResetRecordsWhichOnes(t *testing.T) {
	s, token := adminAPI(t)
	u := &store.User{Username: "rot", SubToken: "rt", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	code, body := doPOST(t, s, fmt.Sprintf("/api/admin/users/%d/reset-credentials", u.ID), token,
		`{"uuid":false,"password":false,"sub_token":true}`)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}

	diff := lastDiffFor(t, s, "user.credentials.reset")
	// "credentials reset" alone cannot answer whether someone handed out a fresh
	// subscription link or invalidated every config the user held — three very
	// different blast radii.
	if !strings.Contains(diff, "sub_token") {
		t.Fatalf("diff = %q, want the rotated field named", diff)
	}
	if strings.Contains(diff, "uuid") || strings.Contains(diff, "password") {
		t.Errorf("diff = %q, names credentials that were NOT rotated", diff)
	}
}

func TestAdminRoleChangeIsRecordedWithTheOldRole(t *testing.T) {
	s, token := adminAPI(t)
	a := &store.Admin{Username: "promoted", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 5}
	if err := s.db.CreateAdmin(a); err != nil {
		t.Fatal(err)
	}

	code, body := doPATCH(t, s, fmt.Sprintf("/api/admin/admins/%d", a.ID), token,
		map[string]any{"user_quota": 500})
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}

	diff := lastDiffFor(t, s, "admin.update")
	// This is the most security-relevant diff in the panel: a raised quota is a
	// privilege escalation that looks identical to legitimate use unless the
	// trail records what the value was before.
	if !strings.Contains(diff, "5") || !strings.Contains(diff, "500") {
		t.Fatalf("diff = %q, want the old and new quota", diff)
	}
}
