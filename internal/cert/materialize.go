package cert

// This file connects the panel's certificates to the proxy engines, and makes
// imported certificates survive a restart. Both were missing, and each failure
// was invisible in a different way.
//
// THE ENGINE BRIDGE. The panel obtains a real Let's Encrypt certificate for its
// domain and serves the admin UI over it correctly. The proxy inbounds never saw
// it: Controller.ReloadSpecs handed engine.BuildMulti the SELF-SIGNED pair
// unconditionally, so every TLS inbound was served with a self-signed
// certificate. Nothing failed loudly — the inbound starts, the handshake
// completes — but every client has to be told to skip verification, which is
// precisely the posture a real certificate exists to remove. Engines read
// certificates as FILES (Xray certificateFile/keyFile, sing-box
// certificate_path/key_path), while autocert keeps its own single-blob cache
// format, so bridging the two means writing the live pair out as two PEM files.
//
// IMPORT PERSISTENCE. Store.Import parsed the pair, validated it and put it in a
// map — in memory only. The certificate the operator uploaded was gone at the
// next restart, and because the code path that replaces it (self-signed
// injection) always succeeds, the panel came back up serving a self-signed
// certificate with no error anywhere. Imports are now written to disk and
// reloaded at startup.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// liveDir is where the materialised engine-facing pair lives, and importDir is
// where uploaded pairs are persisted. Both sit under the ACME cache directory so
// one data directory carries everything about certificates.
func (s *Store) liveDir() string   { return filepath.Join(s.cacheDir, "live") }
func (s *Store) importDir() string { return filepath.Join(s.cacheDir, "imported") }

// Materialize writes the certificate currently serving sni to two PEM files and
// returns their paths.
//
// It prefers an imported pair, then an ACME-issued one, and returns ok=false
// when neither exists — the caller then keeps its self-signed fallback. It never
// triggers issuance, so it is safe on the reload path: a build must not block on
// the network, and a rebuild during an outage must not downgrade a working
// inbound because a fetch timed out.
//
// The files are rewritten on every call rather than cached, because that is what
// makes renewal reach the engines: after a renewal the cache holds new bytes and
// the next reload writes them out. Writes are atomic (temp + rename) so an
// engine reading the path during a rewrite never sees a truncated file, and the
// key is 0600 — it is a private key sitting in the data directory.
func (s *Store) Materialize(sni string) (certPath, keyPath string, ok bool) {
	name := normalizeSNI(sni)
	if name == "" {
		return "", "", false
	}
	certPEM, keyPEM, err := s.pairPEM(name)
	if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return "", "", false
	}
	dir := s.liveDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", false
	}
	// The SNI is attacker-influenced in the general case, so it must never be
	// spliced into a path directly.
	base := filepath.Join(dir, safeFileName(name))
	if err := writeAtomic(base+".crt", certPEM, 0o644); err != nil {
		return "", "", false
	}
	if err := writeAtomic(base+".key", keyPEM, 0o600); err != nil {
		return "", "", false
	}
	return base + ".crt", base + ".key", true
}

// pairPEM returns the PEM-encoded chain and key currently serving name.
func (s *Store) pairPEM(name string) (certPEM, keyPEM []byte, err error) {
	s.mu.RLock()
	var found *Imported
	for _, imp := range s.imported {
		for _, d := range imp.Domains {
			if hostMatches(d, name) {
				found = imp
				break
			}
		}
		if found != nil {
			break
		}
	}
	s.mu.RUnlock()
	if found != nil {
		return encodePair(&found.cert)
	}
	if c := s.cachedACMECert(name); c != nil {
		return encodePair(c)
	}
	return nil, nil, errors.New("cert: no certificate available for " + name)
}

// encodePair re-encodes a parsed certificate back to PEM. The chain is written
// leaf-first, which is the order both engines expect.
func encodePair(c *tls.Certificate) (certPEM, keyPEM []byte, err error) {
	if c == nil || len(c.Certificate) == 0 || c.PrivateKey == nil {
		return nil, nil, errors.New("cert: incomplete certificate")
	}
	var cb strings.Builder
	for _, der := range c.Certificate {
		if err := pem.Encode(&stringWriter{&cb}, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return nil, nil, err
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cert: marshal private key: %w", err)
	}
	var kb strings.Builder
	if err := pem.Encode(&stringWriter{&kb}, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, nil, err
	}
	return []byte(cb.String()), []byte(kb.String()), nil
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// writeAtomic writes through a temp file in the same directory, so a reader
// either sees the old file or the complete new one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// safeFileName reduces a hostname to characters that cannot escape a directory.
// A wildcard name ("*.example.com") is the common case this exists for.
//
// Separators are neutralised, and so is any run of dots: a lone "." is a normal
// label separator, but ".." is a parent-directory reference and must not survive
// into a path built from a name a client controls. Neutralising the separator
// alone would already contain it — this is the second layer, so containment does
// not depend on one substitution being right.
func safeFileName(name string) string {
	var b strings.Builder
	prevDot := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
			prevDot = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
			prevDot = false
		case r == '.':
			if prevDot {
				b.WriteByte('_') // collapse "..", never emit a parent reference
				continue
			}
			b.WriteByte('.')
			prevDot = true
		default:
			b.WriteByte('_')
			prevDot = false
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "cert"
	}
	return out
}

// persistImport writes an imported pair to disk so it survives a restart.
func (s *Store) persistImport(imp *Imported, certPEM, keyPEM []byte) error {
	dir := s.importDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// One file holding cert then key, which is the same shape LoadImported reads
	// back and the same shape an operator would paste.
	blob := append(append([]byte{}, certPEM...), keyPEM...)
	return writeAtomic(filepath.Join(dir, safeFileName(imp.Domains[0])+".pem"), blob, 0o600)
}

// LoadImported restores previously imported certificates from disk.
//
// Called at startup. A pair that no longer parses, or that has expired, is
// skipped with an error rather than silently dropped: an operator whose uploaded
// certificate stopped being used deserves to know which one and why, since the
// alternative — falling back to self-signed — looks like everything still works.
func (s *Store) LoadImported() []error {
	entries, err := os.ReadDir(s.importDir())
	if err != nil {
		return nil // nothing imported yet is not an error
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		path := filepath.Join(s.importDir(), e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("cert: read %s: %w", e.Name(), err))
			continue
		}
		certPEM, keyPEM := splitPEMBlob(raw)
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			errs = append(errs, fmt.Errorf("cert: %s holds no certificate/key pair", e.Name()))
			continue
		}
		imp, err := s.importParsed(certPEM, keyPEM)
		if err != nil {
			errs = append(errs, fmt.Errorf("cert: %s: %w", e.Name(), err))
			continue
		}
		if time.Now().After(imp.NotAfter) {
			errs = append(errs, fmt.Errorf("cert: %s expired on %s and was not loaded",
				e.Name(), imp.NotAfter.Format(time.RFC3339)))
			s.forget(imp.Domains[0])
		}
	}
	return errs
}

// forget drops a domain from the in-memory set.
func (s *Store) forget(domain string) {
	s.mu.Lock()
	delete(s.imported, domain)
	s.mu.Unlock()
}

// splitPEMBlob separates the certificate blocks from the key block in a combined
// PEM file, in whichever order they appear.
func splitPEMBlob(raw []byte) (certPEM, keyPEM []byte) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := pem.EncodeToMemory(block)
		if strings.Contains(block.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, encoded...)
		} else if block.Type == "CERTIFICATE" {
			certPEM = append(certPEM, encoded...)
		}
	}
	return certPEM, keyPEM
}
