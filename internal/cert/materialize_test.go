package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// realPair mints a certificate/key pair the way an operator's uploaded PEM looks.
func realPair(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

// An imported certificate used to live in memory only: the upload succeeded, the
// panel served it, and at the next restart every TLS surface silently fell back
// to self-signed with no error anywhere to explain it.
func TestImportedCertificateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := realPair(t, "panel.example.com", time.Now().Add(90*24*time.Hour))

	first := NewStore(filepath.Join(dir, "acme"), true, nil)
	if _, err := first.Import(certPEM, keyPEM); err != nil {
		t.Fatalf("import: %v", err)
	}

	// A brand-new store is what a restart produces.
	second := NewStore(filepath.Join(dir, "acme"), true, nil)
	if got := len(second.List()); got != 0 {
		t.Fatalf("a fresh store should hold nothing before loading, got %d", got)
	}
	if errs := second.LoadImported(); len(errs) != 0 {
		t.Fatalf("LoadImported reported errors: %v", errs)
	}
	list := second.List()
	if len(list) != 1 {
		t.Fatalf("the imported certificate did not survive the restart: %d loaded", len(list))
	}
	if list[0].Domains[0] != "panel.example.com" {
		t.Fatalf("wrong certificate restored: %v", list[0].Domains)
	}
}

// An expired import must be reported, not silently ignored: falling back to
// self-signed looks like everything still works.
func TestExpiredImportIsReportedAndNotLoaded(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := realPair(t, "old.example.com", time.Now().Add(-time.Hour))

	first := NewStore(filepath.Join(dir, "acme"), true, nil)
	if _, err := first.Import(certPEM, keyPEM); err != nil {
		t.Fatalf("import: %v", err)
	}
	second := NewStore(filepath.Join(dir, "acme"), true, nil)
	errs := second.LoadImported()
	if len(errs) == 0 {
		t.Fatalf("an expired certificate loaded with no complaint")
	}
	if !strings.Contains(errs[0].Error(), "expired") {
		t.Fatalf("the error should say the certificate expired, got %v", errs[0])
	}
	if len(second.List()) != 0 {
		t.Fatalf("an expired certificate must not stay in the serving set")
	}
}

// The engines read certificates as FILES. Materialize is the bridge; without it
// ReloadSpecs handed every TLS inbound the self-signed pair even when a real
// certificate existed for the same name.
func TestMaterializeWritesAPairTheEnginesCanRead(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := realPair(t, "edge.example.com", time.Now().Add(90*24*time.Hour))
	s := NewStore(filepath.Join(dir, "acme"), true, nil)
	if _, err := s.Import(certPEM, keyPEM); err != nil {
		t.Fatalf("import: %v", err)
	}

	cp, kp, ok := s.Materialize("edge.example.com")
	if !ok {
		t.Fatalf("Materialize found no certificate for a name that was just imported")
	}
	// Both engines load the pair with exactly this call.
	if _, err := tls.LoadX509KeyPair(cp, kp); err != nil {
		t.Fatalf("the materialised pair does not load as a key pair: %v", err)
	}
	// The private key must not be world-readable: it sits in the data directory.
	info, err := os.Stat(kp)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key mode is %o, want 600", perm)
	}
}

// No certificate means no override: the caller keeps its self-signed fallback
// rather than being handed an empty path that would break the inbound.
func TestMaterializeReportsMissingRatherThanReturningEmptyPaths(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "acme"), true, nil)
	cp, kp, ok := s.Materialize("nothing.example.com")
	if ok || cp != "" || kp != "" {
		t.Fatalf("expected a miss, got ok=%v cp=%q kp=%q", ok, cp, kp)
	}
	if _, _, ok := s.Materialize(""); ok {
		t.Fatalf("an empty SNI must not resolve to a certificate")
	}
}

// Renewal only reaches the engines if the files are rewritten. A cached path
// pointing at stale bytes is how an expired certificate keeps being served.
func TestMaterializeRewritesAfterTheCertificateChanges(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "acme"), true, nil)

	oldPEM, oldKey := realPair(t, "renew.example.com", time.Now().Add(24*time.Hour))
	if _, err := s.Import(oldPEM, oldKey); err != nil {
		t.Fatal(err)
	}
	cp, _, ok := s.Materialize("renew.example.com")
	if !ok {
		t.Fatal("first materialise failed")
	}
	before, _ := os.ReadFile(cp)

	newPEM, newKey := realPair(t, "renew.example.com", time.Now().Add(90*24*time.Hour))
	if _, err := s.Import(newPEM, newKey); err != nil {
		t.Fatal(err)
	}
	cp2, _, ok := s.Materialize("renew.example.com")
	if !ok {
		t.Fatal("second materialise failed")
	}
	after, _ := os.ReadFile(cp2)
	if string(before) == string(after) {
		t.Fatalf("the materialised certificate did not change after renewal, so the engines keep serving the old one")
	}
}

// A wildcard or otherwise awkward SNI must not be able to escape the directory.
func TestMaterializePathIsContained(t *testing.T) {
	for _, in := range []string{"*.example.com", "../../etc/passwd", "UPPER.Example.COM"} {
		got := safeFileName(normalizeSNI(in))
		if strings.Contains(got, "/") || strings.Contains(got, "..") {
			t.Errorf("safeFileName(%q) = %q, which can escape the directory", in, got)
		}
	}
}
