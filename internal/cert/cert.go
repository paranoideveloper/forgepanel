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
	return &Store{imported: map[string]*Imported{}, acme: m}
}

// TLSConfig returns a *tls.Config that serves imported certs when present and
// falls back to ACME for registry domains. Suitable for the panel and inbound
// TLS listeners.
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			for _, imp := range s.imported {
				for _, d := range imp.Domains {
					if d == hello.ServerName {
						c := imp.cert
						s.mu.RUnlock()
						return &c, nil
					}
				}
			}
			s.mu.RUnlock()
			return s.acme.GetCertificate(hello)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
	}
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
