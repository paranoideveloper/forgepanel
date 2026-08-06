package cert

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, dns string) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dns},
		DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	kpem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return cpem, kpem
}
func TestImportAndExpiry(t *testing.T) {
	s := NewStore(t.TempDir(), true, nil)
	cpem, kpem := selfSigned(t, "panel.example.com")
	imp, err := s.Import(cpem, kpem)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Domains) != 1 || imp.Domains[0] != "panel.example.com" {
		t.Fatalf("bad domains %+v", imp.Domains)
	}
	if len(s.List()) != 1 {
		t.Fatal("cert not stored")
	}
	// expiring within 72h (cert valid 48h) -> should be flagged
	if len(s.ExpiringWithin(72*time.Hour, time.Now())) != 1 {
		t.Fatal("should flag expiring cert")
	}
	if len(s.ExpiringWithin(1*time.Hour, time.Now())) != 0 {
		t.Fatal("should NOT flag cert valid for 48h within 1h")
	}
	// bad pair rejected
	if _, err := s.Import([]byte("notpem"), kpem); err == nil {
		t.Fatal("expected import error")
	}
}

func TestHostMatchesWildcard(t *testing.T) {
	cases := []struct {
		cert, sni string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com", false}, // caller normalizes; hostMatches is exact on normalized
		{"api.example.com", "api.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},          // apex not matched
		{"*.example.com", "deep.api.example.com", false}, // multi-level not matched
		{"*.example.com", "", false},
		{"", "api.example.com", false},
	}
	for _, c := range cases {
		if got := hostMatches(c.cert, c.sni); got != c.want {
			t.Errorf("hostMatches(%q,%q)=%v want %v", c.cert, c.sni, got, c.want)
		}
	}
	// normalizeSNI makes matching case/dot-insensitive at the boundary.
	if normalizeSNI("API.Example.COM.") != "api.example.com" {
		t.Fatal("normalizeSNI failed")
	}
	if !hostMatches(normalizeSNI("*.Example.com"), normalizeSNI("API.example.com.")) {
		t.Fatal("normalized wildcard match failed")
	}
}

func TestCachedInfoWildcard(t *testing.T) {
	// An imported wildcard cert must be found (status-wise) for a covered
	// subdomain, not just its exact SANs.
	s := NewStore(t.TempDir(), false, nil)
	s.imported["*.example.com"] = &Imported{Domains: []string{"*.example.com"}}
	if _, ok := s.CachedInfo("api.example.com"); !ok {
		t.Fatal("wildcard cert should be reported for api.example.com")
	}
	if _, ok := s.CachedInfo("example.com"); ok {
		t.Fatal("wildcard must NOT match the apex")
	}
	if _, ok := s.CachedInfo("nope.other.com"); ok {
		t.Fatal("unrelated name must not match")
	}
}

func TestStore_TLSConfigAndCachedInfo(t *testing.T) {
	s := NewStore(t.TempDir(), true, nil)
	cpem, kpem := selfSigned(t, "api.example.com")
	if _, err := s.Import(cpem, kpem); err != nil {
		t.Fatal(err)
	}

	info, ok := s.CachedInfo("api.example.com")
	if !ok || len(info.Domains) != 1 || info.Domains[0] != "api.example.com" {
		t.Fatalf("CachedInfo failed: %+v", info)
	}

	_, ok = s.CachedInfo("nonexistent.com")
	if ok {
		t.Fatal("CachedInfo expected false for nonexistent domain")
	}

	tlsCfg := s.TLSConfig()
	if tlsCfg == nil || tlsCfg.GetCertificate == nil {
		t.Fatal("TLSConfig failed to produce valid config")
	}

	if s.ACMEManager() == nil {
		t.Fatal("ACMEManager returned nil")
	}
}

func TestEnsureSelfSigned(t *testing.T) {
	dir := t.TempDir()
	crt, key, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned failed: %v", err)
	}

	if crt == "" || key == "" {
		t.Fatal("empty cert or key path returned")
	}

	// Calling again should reuse existing files
	crt2, key2, err := EnsureSelfSigned(dir)
	if err != nil || crt2 != crt || key2 != key {
		t.Fatalf("EnsureSelfSigned reuse failed: %v", err)
	}
}

func TestTLSConfigGetCertificate(t *testing.T) {
	s := NewStore(t.TempDir(), true, nil)
	cpem, kpem := selfSigned(t, "api.example.com")
	if _, err := s.Import(cpem, kpem); err != nil {
		t.Fatal(err)
	}

	cfg := s.TLSConfig()
	hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert, err := cfg.GetCertificate(hello)
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate failed for imported domain: %v", err)
	}

	// Unknown domain should trigger fallback or error
	helloUnknown := &tls.ClientHelloInfo{ServerName: "unknown.domain.org"}
	_, _ = cfg.GetCertificate(helloUnknown)
}
