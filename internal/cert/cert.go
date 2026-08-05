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
	for _, imp := range s.imported {
		for _, d := range imp.Domains {
			if strings.EqualFold(d, domain) {
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
			return s.acme.GetCertificate(hello)
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

// ACMEManager exposes the autocert manager (for mounting its HTTP-01 handler).
func (s *Store) ACMEManager() *autocert.Manager { return s.acme }

// Import parses and stores a PEM certificate+key, validating the pair and
// extracting its domains and validity window.
func (s *Store) Import(certPEM, keyPEM []byte) (*Imported, error) {
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
