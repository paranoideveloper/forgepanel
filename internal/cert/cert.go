// Package cert is the certificate layer (spec §7): an imported-PEM store and an
// ACME manager (Let's Encrypt) built on autocert, which handles HTTP-01/TLS-ALPN
// issuance and automatic renewal. Providers for DNS-01 wildcard issuance slot in
// alongside; this build ships the HTTP-01/TLS-ALPN path end-to-end.
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Imported is a user-supplied certificate/key pair (spec §7 "import existing
// PEM"), parsed and validated.
type Imported struct {
	Domains   []string  `json:"domains"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Issuer    string    `json:"issuer"`
	cert      tls.Certificate
}

// Store holds imported certs keyed by primary domain, plus the ACME manager.
type Store struct {
	mu       sync.RWMutex
	imported map[string]*Imported
	acme     *autocert.Manager
	cacheDir string

	ssOnce sync.Once
	ss     *tls.Certificate // self-signed fallback so the panel can serve HTTPS with no domain
}

// selfSignedCert lazily generates (once) and returns the panel's self-signed
// certificate, so TLSConfig can always complete a handshake — even on an IP with
// no domain and no ACME cert. It is the same cert the proxy engine serves for
// TLS inbounds without a real cert (under <dataDir>/certs).
func (s *Store) selfSignedCert() *tls.Certificate {
	s.ssOnce.Do(func() {
		dir := filepath.Join(filepath.Dir(s.cacheDir), "certs")
		cp, kp, err := EnsureSelfSigned(dir)
		if err != nil {
			return
		}
		c, err := tls.LoadX509KeyPair(cp, kp)
		if err != nil {
			return
		}
		s.ss = &c
	})
	return s.ss
}

// NewStore creates a cert store whose ACME cache lives at cacheDir and whose
// issuance is limited to domains approved by allow (the domain registry).
func NewStore(cacheDir string, staging bool, allow func(domain string) bool) *Store {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		HostPolicy: func(_ context.Context, host string) error {
			if allow == nil || allow(host) {
				return nil
			}
			return fmt.Errorf("cert: host %q not in the panel domain registry", host)
		},
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	return &Store{imported: map[string]*Imported{}, acme: m, cacheDir: cacheDir}
}

// CachedInfo returns metadata for a domain's certificate — an imported pair if
// one exists, otherwise a certificate already issued by ACME and sitting in the
// on-disk cache. It never triggers issuance (pure read), so it is safe to call
// from a status endpoint. ok is false when no certificate is available yet.
func (s *Store) CachedInfo(domain string) (*Imported, bool) {
	s.mu.RLock()
	q := normalizeSNI(domain)
	for _, imp := range s.imported {
		for _, d := range imp.Domains {
			// Match exactly OR via a wildcard SAN, so cert status is reported for
			// every name an imported (possibly wildcard) cert actually serves.
			if hostMatches(normalizeSNI(d), q) {
				cp := *imp
				s.mu.RUnlock()
				return &cp, true
			}
		}
	}
	s.mu.RUnlock()
	if s.cacheDir == "" {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(s.cacheDir, strings.ToLower(domain)))
	if err != nil {
		return nil, false
	}
	// autocert stores the private key then the certificate chain as PEM blocks.
	var leaf *x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				leaf = c
				break
			}
		}
	}
	if leaf == nil {
		return nil, false
	}
	domains := leaf.DNSNames
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	return &Imported{
		Domains:   domains,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Issuer:    leaf.Issuer.CommonName,
	}, true
}

// TLSConfig returns a *tls.Config that serves imported certs when present and
// falls back to ACME for registry domains. Suitable for the panel and inbound
// TLS listeners.
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// ACME TLS-ALPN-01 challenges MUST be answered by autocert.
			for _, proto := range hello.SupportedProtos {
				if proto == acme.ALPNProto {
					return s.acme.GetCertificate(hello)
				}
			}
			sni := normalizeSNI(hello.ServerName)
			s.mu.RLock()
			var exact, wild *tls.Certificate
			for _, imp := range s.imported {
				for _, d := range imp.Domains {
					cd := normalizeSNI(d)
					if sni != "" && cd == sni {
						c := imp.cert
						exact = &c
					} else if wildcardMatch(cd, sni) {
						c := imp.cert
						wild = &c
					}
				}
				if exact != nil {
					break
				}
			}
			s.mu.RUnlock()
			// Exact SAN wins over a wildcard; an empty or unmatched SNI falls
			// through to ACME (which handles the panel domain / default path).
			if exact != nil {
				return exact, nil
			}
			if wild != nil {
				return wild, nil
			}
			// A real domain with an ACME cert wins; otherwise (IP access, no
			// domain, or issuance not yet complete) fall back to the self-signed
			// cert so the panel always serves HTTPS instead of failing the
			// handshake and appearing offline.
			// Serve an already-issued ACME certificate straight from the cache.
			// autocert issues per key type: if it holds an RSA cert but a modern
			// client offers ECDSA, it tries to (re)issue an ECDSA cert on the
			// handshake — a fresh order that stalls and, if it fails, drops back
			// to the self-signed fallback even though a valid cert is on disk.
			// Serving the cached cert directly makes the panel present its
			// Let's Encrypt certificate instead of appearing "Not Secure".
			if c := s.cachedACMECert(sni); c != nil {
				return c, nil
			}
			if c, err := s.acme.GetCertificate(hello); err == nil && c != nil {
				return c, nil
			}
			if ss := s.selfSignedCert(); ss != nil {
				return ss, nil
			}
			return nil, fmt.Errorf("cert: no certificate available for %q", sni)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

// normalizeSNI lowercases and strips a trailing dot so SNI matching is
// case-insensitive and dot-insensitive (SNI hostnames are already A-label form).
func normalizeSNI(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// hostMatches reports whether a normalized certificate SAN matches a normalized
// SNI: exact match, or a single left-most wildcard. Exposed for direct testing.
func hostMatches(certName, sni string) bool {
	if certName == "" || sni == "" {
		return false
	}
	if certName == sni {
		return true
	}
	return wildcardMatch(certName, sni)
}

// wildcardMatch implements TLS wildcard rules: "*.example.com" matches exactly
// one left-most label — "api.example.com" yes; the apex "example.com" no; a
// deeper "deep.api.example.com" no. Only the leftmost label may be the wildcard;
// no unsafe suffix-only matching.
func wildcardMatch(certName, sni string) bool {
	if sni == "" || !strings.HasPrefix(certName, "*.") {
		return false
	}
	suffix := certName[1:] // ".example.com"
	if !strings.HasSuffix(sni, suffix) {
		return false
	}
	label := sni[:len(sni)-len(suffix)] // the single left-most label
	return label != "" && !strings.Contains(label, ".")
}

// renewWindow is how long before expiry a cached ACME cert stops being served
// directly and instead routes through autocert, so autocert renews it in time.
const renewWindow = 30 * 24 * time.Hour

// cachedACMECert loads an already-issued ACME certificate for sni straight from
// the autocert cache, ready to serve. autocert issues per key type, so when it
// holds one key type (e.g. RSA) but a client offers another (ECDSA) it tries to
// (re)issue on the handshake, which stalls and can fall back to the self-signed
// cert even though a valid cert is on disk. Serving the cached cert avoids that.
// Returns nil when nothing usable is cached, or when the cert is within its
// renewal window (then autocert should handle it so it renews).
func (s *Store) cachedACMECert(sni string) *tls.Certificate {
	if s.cacheDir == "" {
		return nil
	}
	sni = normalizeSNI(sni)
	if sni == "" {
		return nil
	}
	// autocert cache keys: "<domain>" (its preferred key type) and "<domain>+rsa".
	for _, name := range []string{sni, sni + "+rsa"} {
		raw, err := os.ReadFile(filepath.Join(s.cacheDir, name))
		if err != nil {
			continue
		}
		cert, leaf := splitCachedCert(raw)
		if cert == nil || leaf == nil {
			continue
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			continue // expired or not yet valid — let autocert deal with it
		}
		if now.After(leaf.NotAfter.Add(-renewWindow)) {
			return nil // due for renewal — route through autocert
		}
		return cert
	}
	return nil
}

// splitCachedCert parses an autocert cache entry (the private key PEM followed by
// the certificate chain PEM) into a usable tls.Certificate and its parsed leaf.
func splitCachedCert(raw []byte) (*tls.Certificate, *x509.Certificate) {
	var certPEM, keyPEM []byte
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			keyPEM = append(keyPEM, pem.EncodeToMemory(block)...)
		case block.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil
	}
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	if leaf == nil {
		return nil, nil
	}
	c.Leaf = leaf
	return &c, leaf
}

// ACMEManager exposes the autocert manager (for mounting its HTTP-01 handler).
func (s *Store) ACMEManager() *autocert.Manager { return s.acme }

// Import parses and stores a PEM certificate+key, validating the pair and
// extracting its domains and validity window.
func (s *Store) Import(certPEM, keyPEM []byte) (*Imported, error) {
	imp, err := s.importParsed(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Persist it. An imported certificate that lives only in memory is gone at
	// the next restart, and the panel silently falls back to self-signed -- a
	// failure with no error anywhere, which is why this is not best-effort: the
	// operator is told if the certificate will not survive.
	if err := s.persistImport(imp, certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("cert: imported but could not be saved, so it would be lost on restart: %w", err)
	}
	return imp, nil
}

// importParsed validates and registers a pair in memory without persisting it.
// LoadImported reuses it to restore from disk, which is what keeps the two paths
// from disagreeing about what a valid certificate is.
func (s *Store) importParsed(certPEM, keyPEM []byte) (*Imported, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: invalid key pair: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("cert: no PEM block in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert: parse: %w", err)
	}
	imp := &Imported{
		Domains:   leaf.DNSNames,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Issuer:    leaf.Issuer.CommonName,
		cert:      tlsCert,
	}
	if len(imp.Domains) == 0 && leaf.Subject.CommonName != "" {
		imp.Domains = []string{leaf.Subject.CommonName}
	}
	if len(imp.Domains) == 0 {
		return nil, errors.New("cert: certificate has no domains")
	}
	s.mu.Lock()
	s.imported[imp.Domains[0]] = imp
	s.mu.Unlock()
	return imp, nil
}

// List returns metadata for every imported cert.
func (s *Store) List() []*Imported {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Imported, 0, len(s.imported))
	for _, imp := range s.imported {
		out = append(out, imp)
	}
	return out
}

// ExpiringWithin reports imported certs whose NotAfter is within d of now — the
// renewal trigger (spec §7: renew at 30 days).
func (s *Store) ExpiringWithin(d time.Duration, now time.Time) []*Imported {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Imported
	for _, imp := range s.imported {
		if imp.NotAfter.Sub(now) <= d {
			out = append(out, imp)
		}
	}
	return out
}
