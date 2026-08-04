package auth

import (
	"testing"
	"time"
)

func TestTOTPVerify(t *testing.T) {
	sec, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	code, err := TOTPCode(sec, now)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(sec, code, now) {
		t.Fatal("current code must verify")
	}
	// skew tolerance: code from 30s ago still valid
	prev, _ := TOTPCode(sec, now.Add(-30*time.Second))
	if !VerifyTOTP(sec, prev, now) {
		t.Fatal("one-step-back code must verify")
	}
	// wrong code fails; 2 steps away fails
	if VerifyTOTP(sec, "000000", now) {
		t.Fatal("wrong code must fail")
	}
	far, _ := TOTPCode(sec, now.Add(-120*time.Second))
	if VerifyTOTP(sec, far, now) {
		t.Fatal("far code must fail")
	}
	if len(code) != 6 {
		t.Fatalf("code must be 6 digits: %q", code)
	}
}
func TestRecoveryCodes(t *testing.T) {
	codes, err := RecoveryCodes(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 {
		t.Fatal("wrong count")
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatal("dup recovery code")
		}
		seen[c] = true
	}
}
