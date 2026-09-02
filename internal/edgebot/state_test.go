package edgebot

import (
	"os"
	"testing"
)

func TestStore_RoundTripAndEncryption(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 111)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A new requester becomes pending; the owner is auto-approved.
	if out, _ := s.EnsureRequest(222, "bob", "Bob"); out != RequestNew {
		t.Fatalf("first request outcome = %v", out)
	}
	if out, _ := s.EnsureRequest(222, "bob", "Bob"); out != RequestPending {
		t.Fatalf("second request outcome = %v", out)
	}
	if !s.IsApproved(111) {
		t.Fatal("owner must always be approved")
	}
	if s.IsApproved(222) {
		t.Fatal("pending user must not be approved")
	}
	if err := s.Decide(222, StatusApproved); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if err := s.SetCreds(222, "cf-secret-token", "acct-123"); err != nil {
		t.Fatalf("SetCreds: %v", err)
	}
	if err := s.AddDeployment(222, Deployment{Name: "w1", Origin: "https://w1.workers.dev", SecurePath: "p", FeedPushToken: "pt"}); err != nil {
		t.Fatalf("AddDeployment: %v", err)
	}

	// The file on disk must not contain the plaintext token.
	blob, err := os.ReadFile(dir + "/edgebot.state")
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("state file is empty")
	}
	if containsBytes(blob, "cf-secret-token") || containsBytes(blob, "bob") {
		t.Fatal("state file leaks plaintext — encryption is not applied")
	}

	// Reopen with the same key: everything survives.
	s2, err := Open(dir, 111)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !s2.IsApproved(222) {
		t.Fatal("approval did not persist")
	}
	tok, acct, ok := s2.Creds(222)
	if !ok || tok != "cf-secret-token" || acct != "acct-123" {
		t.Fatalf("creds did not persist: %q %q %v", tok, acct, ok)
	}
	if d, ok := s2.Deployment(222, "w1"); !ok || d.FeedPushToken != "pt" {
		t.Fatalf("deployment did not persist: %+v", d)
	}
}

func TestStore_OwnerCanStoreCredsWithoutApprovalFlow(t *testing.T) {
	// Regression: the owner is auto-approved but never goes through Decide, so a
	// user row must still exist for them — otherwise /cf fails with "unknown user".
	const owner = int64(100200300)
	s, err := Open(t.TempDir(), owner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !s.IsApproved(owner) {
		t.Fatal("owner must be approved")
	}
	if err := s.SetCreds(owner, "tok", "acct"); err != nil {
		t.Fatalf("owner SetCreds: %v", err)
	}
	if err := s.AddDeployment(owner, Deployment{Name: "w1"}); err != nil {
		t.Fatalf("owner AddDeployment: %v", err)
	}
	if tok, acct, ok := s.Creds(owner); !ok || tok != "tok" || acct != "acct" {
		t.Fatalf("owner creds: %q %q %v", tok, acct, ok)
	}
}

func TestStore_PerUserIsolation(t *testing.T) {
	s, err := Open(t.TempDir(), 111)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, _ = s.EnsureRequest(222, "a", "A")
	_, _ = s.EnsureRequest(333, "b", "B")
	_ = s.Decide(222, StatusApproved)
	_ = s.Decide(333, StatusApproved)
	_ = s.AddDeployment(222, Deployment{Name: "wa"})
	_ = s.AddDeployment(333, Deployment{Name: "wb"})

	if _, ok := s.Deployment(222, "wb"); ok {
		t.Fatal("user 222 must not see user 333's worker")
	}
	if len(s.Deployments(333)) != 1 || s.Deployments(333)[0].Name != "wb" {
		t.Fatalf("333 deployments wrong: %+v", s.Deployments(333))
	}
}

func TestStore_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1)
	_, _ = s.EnsureRequest(2, "x", "X")
	// Corrupt the key file; a reopen must refuse rather than silently reset.
	if err := os.WriteFile(dir+"/edgebot.key", []byte("not-a-valid-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, 1); err == nil {
		t.Fatal("expected an error opening with a corrupt key")
	}
}

func containsBytes(haystack []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		if string(haystack[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}
