package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("password stored in plaintext")
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("valid password rejected: %v %v", ok, err)
	}
	bad, _ := VerifyPassword("wrong", hash)
	if bad {
		t.Fatal("wrong password accepted")
	}
	// Two hashes of the same password must differ (random salt).
	hash2, _ := HashPassword("correct horse battery staple")
	if hash == hash2 {
		t.Fatal("salt is not random")
	}
}

func TestJWTIssueVerify(t *testing.T) {
	s := NewSigner([]byte("test-secret"))
	access, refresh, err := s.Issue(7, "admin", "owner")
	if err != nil {
		t.Fatal(err)
	}
	ac, err := s.Verify(access)
	if err != nil || ac.AdminID != 7 || ac.Kind != "access" || ac.Role != "owner" {
		t.Fatalf("bad access claims: %+v %v", ac, err)
	}
	rc, err := s.Verify(refresh)
	if err != nil || rc.Kind != "refresh" {
		t.Fatalf("bad refresh claims: %+v %v", rc, err)
	}
	// A token signed by a different secret must be rejected.
	other := NewSigner([]byte("other-secret"))
	if _, err := other.Verify(access); err == nil {
		t.Fatal("token verified under wrong secret")
	}
}
