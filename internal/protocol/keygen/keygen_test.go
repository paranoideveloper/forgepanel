package keygen

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"golang.org/x/crypto/curve25519"
)

// TestRealityKeysDeriveConsistently proves the generated REALITY public key is
// genuinely X25519(private, basepoint) -- i.e. the keypair is cryptographically
// valid, not just random bytes.
func TestRealityKeysDeriveConsistently(t *testing.T) {
	kp, err := RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("bad private key: %v", err)
	}
	wantPub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(wantPub) != kp.PublicKey {
		t.Fatal("public key does not match X25519(private, basepoint)")
	}
	// And the exported helper recovers the same public key.
	got, err := RealityPublicFromPrivate(kp.PrivateKey)
	if err != nil || got != kp.PublicKey {
		t.Fatalf("RealityPublicFromPrivate mismatch: %v %q vs %q", err, got, kp.PublicKey)
	}
}

// TestSS2022PSKLengths asserts each 2022 method yields a PSK the model accepts.
func TestSS2022PSKLengths(t *testing.T) {
	for _, m := range []string{model.SS2022AES128, model.SS2022AES256, model.SS2022ChaCha20} {
		psk, err := SS2022PSK(m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		n := &model.Node{Protocol: model.ProtoShadowsocks, Address: "h", Port: 1, Method: m, Password: psk}
		n.Normalize()
		if err := n.Validate(); err != nil {
			t.Fatalf("%s: generated PSK rejected by validator: %v", m, err)
		}
	}
	if _, err := SS2022PSK("aes-256-gcm"); err == nil {
		t.Fatal("expected error for non-2022 method")
	}
}

// TestUUIDFromString matches Xray semantics: a valid UUID passes through, a
// non-UUID maps deterministically and stably.
func TestUUIDFromString(t *testing.T) {
	const u = "b831381d-6324-4d53-ad4f-8cda48b30811"
	if UUIDFromString(u) != u {
		t.Fatal("valid uuid should pass through unchanged")
	}
	a := UUIDFromString("hello")
	b := UUIDFromString("hello")
	if a != b {
		t.Fatal("mapping must be deterministic")
	}
	if a == UUIDFromString("world") {
		t.Fatal("different inputs must map to different uuids")
	}
	if len(a) != 36 || strings.Count(a, "-") != 4 {
		t.Fatalf("not a uuid: %q", a)
	}
}

// TestSSHKeysValid ensures the ed25519 SSH keypair is well formed.
func TestSSHKeys(t *testing.T) {
	kp, err := SSHKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.AuthorizedKey, "ssh-ed25519 ") {
		t.Fatalf("bad authorized key: %q", kp.AuthorizedKey)
	}
	if !strings.Contains(kp.PrivateKeyPEM, "OPENSSH PRIVATE KEY") {
		t.Fatal("private key not in OpenSSH PEM form")
	}
	if !strings.HasPrefix(kp.Fingerprint256, "SHA256:") {
		t.Fatalf("bad fingerprint: %q", kp.Fingerprint256)
	}
}

func TestShortIDAndPassword(t *testing.T) {
	sid, err := ShortID(4)
	if err != nil || len(sid) != 8 {
		t.Fatalf("ShortID(4) failed: %v, got %q", err, sid)
	}

	if _, err := ShortID(0); err == nil {
		t.Fatal("expected error for ShortID(0)")
	}
	if _, err := ShortID(9); err == nil {
		t.Fatal("expected error for ShortID(9)")
	}

	pw, err := Password(16)
	if err != nil || len(pw) == 0 {
		t.Fatalf("Password(16) failed: %v", err)
	}

	// Test entropy clamp < 8
	pwShort, err := Password(4)
	if err != nil || len(pwShort) == 0 {
		t.Fatalf("Password(4) failed: %v", err)
	}

	u := UUID()
	if len(u) == 0 {
		t.Fatal("UUID() returned empty string")
	}
}

func TestWireGuardKeysAndSSHKeys(t *testing.T) {
	wgKeys, err := WireGuardKeys()
	if err != nil {
		t.Fatalf("WireGuardKeys failed: %v", err)
	}
	if wgKeys.PrivateKey == "" || wgKeys.PublicKey == "" {
		t.Fatalf("WireGuardKeys returned empty keypair")
	}

	sshKeys, err := SSHKeys()
	if err != nil {
		t.Fatalf("SSHKeys failed: %v", err)
	}
	if !strings.Contains(sshKeys.PrivateKeyPEM, "PRIVATE KEY") || !strings.Contains(sshKeys.AuthorizedKey, "ssh-ed25519") {
		t.Fatalf("SSHKeys returned invalid format: %+v", sshKeys)
	}

	seed, err := MLDSA65Seed()
	if err != nil || len(seed) == 0 {
		t.Fatalf("MLDSA65Seed failed: %v", err)
	}

	fp := FingerprintCert([]byte("test cert der"))
	if len(fp) == 0 {
		t.Fatal("FingerprintCert returned empty string")
	}
}

func TestEncodePEMHelper(t *testing.T) {
	pemData := encodePEM([]byte("test der data"), "TEST BLOCK")
	if !strings.Contains(string(pemData), "BEGIN TEST BLOCK") {
		t.Fatalf("encodePEM failed: %s", string(pemData))
	}
}
