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

func selfSignedCNOnly(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	kpem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return cpem, kpem
}

func selfSignedNoDomains(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
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
	if len(s.ExpiringWithin(72*time.Hour, time.Now())) != 1 {
		t.Fatal("should flag expiring cert")
	}
	if len(s.ExpiringWithin(1*time.Hour, time.Now())) != 0 {
		t.Fatal("should NOT flag cert valid for 48h within 1h")
	}
	if _, err := s.Import([]byte("notpem"), kpem); err == nil {
		t.Fatal("expected import error")
	}
}

func TestImportEdgeCases(t *testing.T) {
	s := NewStore(t.TempDir(), false, nil)

	// CN only cert
	cpem, kpem := selfSignedCNOnly(t, "cnonly.local")
	imp, err := s.Import(cpem, kpem)
	if err != nil {
		t.Fatalf("Import CN-only cert failed: %v", err)
	}
	if len(imp.Domains) != 1 || imp.Domains[0] != "cnonly.local" {
		t.Fatalf("expected cnonly.local domain, got %v", imp.Domains)
	}

	// Cert with no domains or common name
	nodomCert, nodomKey := selfSignedNoDomains(t)
	if _, err := s.Import(nodomCert, nodomKey); err == nil {
		t.Fatal("expected error importing cert with no domains")
	}

	// Invalid cert PEM block
	if _, err := s.Import([]byte("-----BEGIN CERTIFICATE-----\nINVALIDBASE64\n-----END CERTIFICATE-----"), kpem); err == nil {
		t.Fatal("expected error on invalid certificate bytes inside PEM block")
	}

	// Invalid key PEM
	if _, err := s.Import(cpem, []byte("invalid key")); err == nil {
		t.Fatal("expected error on invalid key PEM")
	}
}

func TestHostMatchesWildcard(t *testing.T) {
	cases := []struct {
		cert, sni string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com", false},
		{"api.example.com", "api.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "sub.api.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.*.example.com", "a.b.example.com", false},
		{"*.com", "example.com", true},
	}
	for _, c := range cases {
		got := hostMatches(c.cert, c.sni)
		if got != c.want {
			t.Errorf("hostMatches(%q, %q) = %v; want %v", c.cert, c.sni, got, c.want)
		}
	}
}

func TestCachedInfo(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, false, func(host string) bool { return host == "allowed.com" })

	// Check nonexistent in imported and cacheDir
	if info, ok := s.CachedInfo("missing.com"); ok || info != nil {
		t.Fatalf("expected false for missing domain, got %v", info)
	}

	// Import a cert and test CachedInfo matches
	cpem, kpem := selfSigned(t, "*.imported.com")
	if _, err := s.Import(cpem, kpem); err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if info, ok := s.CachedInfo("sub.imported.com"); !ok || info == nil {
		t.Fatalf("CachedInfo wildcard match failed")
	}

	// Write autocert cache file for disk cached info test
	cachedCertPEM, _ := selfSigned(t, "diskcached.com")
	_ = os.WriteFile(filepath.Join(dir, "diskcached.com"), append([]byte("KEY DATA\n"), cachedCertPEM...), 0644)
	if info, ok := s.CachedInfo("diskcached.com"); !ok || info == nil || info.Domains[0] != "diskcached.com" {
		t.Fatalf("CachedInfo from cacheDir failed: %+v", info)
	}

	// Write autocert CN-only cache file
	cachedCNPEM, _ := selfSignedCNOnly(t, "cncached.com")
	_ = os.WriteFile(filepath.Join(dir, "cncached.com"), cachedCNPEM, 0644)
	if info, ok := s.CachedInfo("cncached.com"); !ok || info == nil || info.Domains[0] != "cncached.com" {
		t.Fatalf("CachedInfo CN-only from cacheDir failed: %+v", info)
	}

	// Write invalid cache file
	_ = os.WriteFile(filepath.Join(dir, "invalid.com"), []byte("invalid data"), 0644)
	if _, ok := s.CachedInfo("invalid.com"); ok {
		t.Fatalf("expected false for invalid cache file")
	}

	// Store with empty cacheDir
	sNoCache := &Store{imported: map[string]*Imported{}}
	if _, ok := sNoCache.CachedInfo("test.com"); ok {
		t.Fatalf("expected false with empty cacheDir")
	}
}

func TestTLSConfigAndHostPolicy(t *testing.T) {
	dir := t.TempDir()
	allow := func(h string) bool { return h == "allow.com" }
	s := NewStore(dir, true, allow)

	if mgr := s.ACMEManager(); mgr == nil {
		t.Fatal("ACMEManager returned nil")
	}

	// Host policy verification
	policy := s.acme.HostPolicy
	if err := policy(nil, "allow.com"); err != nil {
		t.Fatalf("policy allow.com failed: %v", err)
	}
	if err := policy(nil, "deny.com"); err == nil {
		t.Fatal("policy expected error for deny.com")
	}

	// Import exact and wildcard certs
	exactPEM, exactKey := selfSigned(t, "exact.com")
	wildPEM, wildKey := selfSigned(t, "*.wild.com")
	s.Import(exactPEM, exactKey)
	s.Import(wildPEM, wildKey)

	tlsCfg := s.TLSConfig()

	// Get exact match
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "EXACT.COM"})
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate exact match failed: %v", err)
	}

	// Get wildcard match
	certWild, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.wild.com"})
	if err != nil || certWild == nil {
		t.Fatalf("GetCertificate wildcard match failed: %v", err)
	}
}

func TestEnsureSelfSigned(t *testing.T) {
	dir := t.TempDir()

	c1, k1, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned failed: %v", err)
	}
	if !fileExists(c1) || !fileExists(k1) {
		t.Fatal("EnsureSelfSigned files missing")
	}

	// Second call returns existing files
	c2, k2, err := EnsureSelfSigned(dir)
	if err != nil || c2 != c1 || k2 != k1 {
		t.Fatalf("EnsureSelfSigned second call failed: %v", err)
	}
}
