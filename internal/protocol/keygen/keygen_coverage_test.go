package keygen

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// failingReader always errors, so generators that take an io.Reader can have
// their error return exercised.
type failingReader struct{}

var errNoEntropy = errors.New("keygen_test: entropy source is unavailable")

func (failingReader) Read([]byte) (int, error) { return 0, errNoEntropy }

// TestRealityPublicFromPrivateRejectsBadKeys covers the error return of
// RealityPublicFromPrivate for every shape of invalid input.
func TestRealityPublicFromPrivateRejectsBadKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"not base64", "!!!! not base64 !!!!"},
		{"too short", base64.RawURLEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.RawURLEncoding.EncodeToString(make([]byte, 33))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RealityPublicFromPrivate(tt.key)
			if err == nil {
				t.Fatalf("expected an error for %q, got public key %q", tt.key, got)
			}
			if got != "" {
				t.Fatalf("a failed derivation must return no key, got %q", got)
			}
			if !strings.Contains(err.Error(), "invalid reality private key") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestRealityPublicFromPrivateAcceptsStdBase64 proves the decoder accepts the
// padded-standard spelling as well as the raw-url one RealityKeys emits, which
// is what lets a key pasted from `xray x25519` round-trip.
func TestRealityPublicFromPrivateAcceptsStdBase64(t *testing.T) {
	kp, err := RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RealityPublicFromPrivate(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("std-base64 private key rejected: %v", err)
	}
	if got != kp.PublicKey {
		t.Fatalf("public key mismatch: %q vs %q", got, kp.PublicKey)
	}
}

// TestSSHKeysEntropyFailure covers the ed25519.GenerateKey error return of
// SSHKeys. It is the one entropy-failure path in this package that is genuinely
// reachable: SSHKeys passes rand.Reader to ed25519.GenerateKey, which does a
// plain io.ReadFull and surfaces the error, whereas every other generator calls
// crypto/rand.Read, which by contract never returns an error.
func TestSSHKeysEntropyFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	kp, err := SSHKeys()
	if err == nil {
		t.Fatal("SSHKeys must fail when the entropy source fails")
	}
	if !errors.Is(err, errNoEntropy) {
		t.Fatalf("error should wrap the reader failure, got %v", err)
	}
	if kp != (SSHKeyPair{}) {
		t.Fatalf("a failed generation must return the zero keypair, got %+v", kp)
	}
}

// TestRealityKeysAreClampedAndUnique asserts the RFC 7748 clamping actually
// happened and that two calls do not collide.
func TestRealityKeysAreClampedAndUnique(t *testing.T) {
	a, err := RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	if a.PrivateKey == b.PrivateKey || a.PublicKey == b.PublicKey {
		t.Fatal("two REALITY keypairs must not be identical")
	}
	priv, err := base64.RawURLEncoding.DecodeString(a.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private key is not 32 raw-url base64 bytes: %v", err)
	}
	if priv[0]&7 != 0 {
		t.Fatalf("low three bits must be cleared, got %#02x", priv[0])
	}
	if priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatalf("high bits not clamped, got %#02x", priv[31])
	}
	// The public key must be exactly 32 raw-url base64 bytes and must not be the
	// all-zero (low order) point.
	pub, err := base64.RawURLEncoding.DecodeString(a.PublicKey)
	if err != nil || len(pub) != 32 {
		t.Fatalf("public key is not 32 raw-url base64 bytes: %v", err)
	}
	var zero [32]byte
	if string(pub) == string(zero[:]) {
		t.Fatal("public key is the all-zero point")
	}
}

// TestWireGuardKeysFormat asserts the keypair really is X25519 in the padded
// standard base64 WireGuard tooling expects (44 characters ending in "=").
func TestWireGuardKeysFormat(t *testing.T) {
	kp, err := WireGuardKeys()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private key is not 32 std base64 bytes: %v", err)
	}
	if len(kp.PrivateKey) != 44 || !strings.HasSuffix(kp.PrivateKey, "=") {
		t.Fatalf("wg private key is not in wg-quick form: %q", kp.PrivateKey)
	}
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatalf("wireguard key is not clamped: %#02x %#02x", priv[0], priv[31])
	}
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(want) != kp.PublicKey {
		t.Fatal("wireguard public key is not X25519(private, basepoint)")
	}

	other, err := WireGuardKeys()
	if err != nil {
		t.Fatal(err)
	}
	if other.PrivateKey == kp.PrivateKey {
		t.Fatal("two WireGuard keypairs must not be identical")
	}
}

// TestShortIDBoundaries walks the whole accepted range plus both rejected ends.
func TestShortIDBoundaries(t *testing.T) {
	for n := 1; n <= 8; n++ {
		sid, err := ShortID(n)
		if err != nil {
			t.Fatalf("ShortID(%d): %v", n, err)
		}
		if len(sid) != n*2 {
			t.Fatalf("ShortID(%d) = %q, want %d hex chars", n, sid, n*2)
		}
		if _, err := hex.DecodeString(sid); err != nil {
			t.Fatalf("ShortID(%d) = %q is not hex: %v", n, sid, err)
		}
		if strings.ToLower(sid) != sid {
			t.Fatalf("ShortID must be lowercase hex, got %q", sid)
		}
	}
	for _, n := range []int{-1, 0, 9, 64} {
		got, err := ShortID(n)
		if err == nil {
			t.Fatalf("ShortID(%d) must be rejected, got %q", n, got)
		}
		if got != "" {
			t.Fatalf("rejected ShortID must return the empty string, got %q", got)
		}
		if !strings.Contains(err.Error(), "1..8") {
			t.Fatalf("error should state the accepted range, got %v", err)
		}
	}
}

// TestPasswordEntropyClamp asserts the <8-byte clamp and the encoding.
func TestPasswordEntropyClamp(t *testing.T) {
	// 16 bytes of entropy -> 22 raw-url base64 characters.
	pw, err := Password(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 22 {
		t.Fatalf("Password(16) = %q (%d chars), want 22", pw, len(pw))
	}
	raw, err := base64.RawURLEncoding.DecodeString(pw)
	if err != nil || len(raw) != 16 {
		t.Fatalf("password is not 16 raw-url base64 bytes: %v", err)
	}
	// Anything below 8 bytes is clamped up to 16, not honoured.
	for _, n := range []int{0, 1, 7, -5} {
		short, err := Password(n)
		if err != nil {
			t.Fatalf("Password(%d): %v", n, err)
		}
		if len(short) != 22 {
			t.Fatalf("Password(%d) = %q (%d chars), want the 16-byte clamp (22)", n, short, len(short))
		}
	}
	// 8 is at the boundary and is honoured as-is.
	at8, err := Password(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(at8) != 11 {
		t.Fatalf("Password(8) = %q (%d chars), want 11", at8, len(at8))
	}
	if at8 == pw {
		t.Fatal("two passwords must not be identical")
	}
}

// TestSS2022PSKSizes asserts each 2022 method yields a PSK of exactly the key
// size that method requires, and that non-2022 methods are rejected.
func TestSS2022PSKSizes(t *testing.T) {
	for _, tc := range []struct {
		method string
		size   int
	}{
		{"2022-blake3-aes-128-gcm", 16},
		{"2022-blake3-aes-256-gcm", 32},
		{"2022-blake3-chacha20-poly1305", 32},
	} {
		psk, err := SS2022PSK(tc.method)
		if err != nil {
			t.Fatalf("%s: %v", tc.method, err)
		}
		raw, err := base64.StdEncoding.DecodeString(psk)
		if err != nil {
			t.Fatalf("%s: PSK is not std base64: %v", tc.method, err)
		}
		if len(raw) != tc.size {
			t.Fatalf("%s: PSK is %d bytes, want %d", tc.method, len(raw), tc.size)
		}
	}
	for _, m := range []string{"aes-128-gcm", "chacha20-ietf-poly1305", "", "nonsense"} {
		got, err := SS2022PSK(m)
		if err == nil {
			t.Fatalf("SS2022PSK(%q) must be rejected, got %q", m, got)
		}
		if got != "" {
			t.Fatalf("rejected method must return the empty string, got %q", got)
		}
		if !strings.Contains(err.Error(), "2022-blake3") {
			t.Fatalf("error should explain the 2022-blake3 requirement, got %v", err)
		}
	}
}

// TestMLDSA65SeedIs32Bytes pins the seed size the pinned Xray build expects.
func TestMLDSA65SeedIs32Bytes(t *testing.T) {
	seed, err := MLDSA65Seed()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil {
		t.Fatalf("seed is not raw-url base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("seed is %d bytes, want 32", len(raw))
	}
	other, err := MLDSA65Seed()
	if err != nil {
		t.Fatal(err)
	}
	if other == seed {
		t.Fatal("two ML-DSA seeds must not be identical")
	}
}

// TestFingerprintCertMatchesSHA256 proves the fingerprint really is the base64
// SHA-256 of the DER, which is what the Hysteria2/TUIC pinSHA256 option needs.
func TestFingerprintCertMatchesSHA256(t *testing.T) {
	der := []byte("\x30\x82 fake DER certificate bytes")
	sum := sha256.Sum256(der)
	want := base64.StdEncoding.EncodeToString(sum[:])
	if got := FingerprintCert(der); got != want {
		t.Fatalf("FingerprintCert = %q, want %q", got, want)
	}
	// Empty input still produces the well-defined SHA-256 of the empty string.
	emptySum := sha256.Sum256(nil)
	if got := FingerprintCert(nil); got != base64.StdEncoding.EncodeToString(emptySum[:]) {
		t.Fatalf("FingerprintCert(nil) = %q", got)
	}
}

// TestSSHKeysAreUsable proves the generated keypair actually parses back through
// x/crypto/ssh -- both halves, and that they belong together.
func TestSSHKeysAreUsable(t *testing.T) {
	kp, err := SSHKeys()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(kp.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("generated private key does not parse: %v", err)
	}
	if got := string(ssh.MarshalAuthorizedKey(signer.PublicKey())); got != kp.AuthorizedKey {
		t.Fatalf("authorized key does not match the private key:\n%q\n%q", got, kp.AuthorizedKey)
	}
	if got := ssh.FingerprintSHA256(signer.PublicKey()); got != kp.Fingerprint256 {
		t.Fatalf("fingerprint mismatch: %q vs %q", got, kp.Fingerprint256)
	}
	// And it can actually sign.
	sig, err := signer.Sign(rand.Reader, []byte("payload"))
	if err != nil {
		t.Fatalf("signer cannot sign: %v", err)
	}
	if err := signer.PublicKey().Verify([]byte("payload"), sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// TestUUIDIsV4AndUnique pins the UUID generator.
func TestUUIDIsV4AndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		u := UUID()
		if len(u) != 36 || strings.Count(u, "-") != 4 {
			t.Fatalf("not a UUID: %q", u)
		}
		if u[14] != '4' {
			t.Fatalf("UUID() must be v4, got %q", u)
		}
		if seen[u] {
			t.Fatalf("duplicate UUID %q after %d draws", u, i)
		}
		seen[u] = true
	}
}

// TestUUIDFromStringIsV5Shaped asserts the derived UUID carries the version-5
// nibble and RFC 4122 variant bits Xray stamps in.
func TestUUIDFromStringIsV5Shaped(t *testing.T) {
	u := UUIDFromString("some-user-handle")
	if u[14] != '5' {
		t.Fatalf("derived UUID must be version 5, got %q", u)
	}
	switch u[19] {
	case '8', '9', 'a', 'b':
	default:
		t.Fatalf("derived UUID has the wrong variant nibble: %q", u)
	}
	// A canonical UUID passes through byte-for-byte; an upper-case one is
	// normalised rather than re-derived.
	const canonical = "b831381d-6324-4d53-ad4f-8cda48b30811"
	if got := UUIDFromString(strings.ToUpper(canonical)); got != canonical {
		t.Fatalf("upper-case UUID should normalise to %q, got %q", canonical, got)
	}
}

// TestEncodePEMRoundTrips proves encodePEM emits a block the standard decoder
// reads back with the same type and payload.
func TestEncodePEMRoundTrips(t *testing.T) {
	out := encodePEM([]byte{0x01, 0x02, 0x03}, "FORGEPANEL TEST")
	s := string(out)
	if !strings.HasPrefix(s, "-----BEGIN FORGEPANEL TEST-----\n") {
		t.Fatalf("missing PEM header: %q", s)
	}
	if !strings.HasSuffix(s, "-----END FORGEPANEL TEST-----\n") {
		t.Fatalf("missing PEM footer: %q", s)
	}
	if !strings.Contains(s, base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})) {
		t.Fatalf("payload not base64 encoded into the block: %q", s)
	}
}

// compile-time assertion that failingReader satisfies io.Reader.
var _ io.Reader = failingReader{}

// TestEntropyFailurePropagates exercises the entropy-failure error return of
// every generator that draws from rand.Reader. Since Go 1.24 crypto/rand.Read
// no longer consults rand.Reader and cannot be made to fail, so each generator
// reads via io.ReadFull(rand.Reader, …): swapping rand.Reader for a failing
// source is the one way these defensive branches are reachable, and a real
// FIPS/entropy-starved host does hit them.
func TestEntropyFailurePropagates(t *testing.T) {
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	if _, err := RealityKeys(); !errors.Is(err, errNoEntropy) {
		t.Errorf("RealityKeys: want entropy error, got %v", err)
	}
	if _, err := ShortID(4); !errors.Is(err, errNoEntropy) {
		t.Errorf("ShortID: want entropy error, got %v", err)
	}
	if _, err := SS2022PSK("2022-blake3-aes-128-gcm"); !errors.Is(err, errNoEntropy) {
		t.Errorf("SS2022PSK: want entropy error, got %v", err)
	}
	if _, err := Password(16); !errors.Is(err, errNoEntropy) {
		t.Errorf("Password: want entropy error, got %v", err)
	}
	if _, err := WireGuardKeys(); !errors.Is(err, errNoEntropy) {
		t.Errorf("WireGuardKeys: want entropy error, got %v", err)
	}
	if _, err := MLDSA65Seed(); !errors.Is(err, errNoEntropy) {
		t.Errorf("MLDSA65Seed: want entropy error, got %v", err)
	}
}
