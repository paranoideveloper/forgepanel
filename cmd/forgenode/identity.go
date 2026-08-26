package main

// The node's own identity: a private key it generates, and a certificate the
// panel signs for it.
//
// Before this, a node's identity was the enrolment token — a string handed to
// it on a command line and then sent on every heartbeat, forever. Here the key
// is generated locally and never transmitted, so there is nothing in flight for
// anyone to capture; what travels is a certificate request, which is public by
// construction, and a certificate, which is public by design.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	nodeKeyFile  = "node-client.key"
	nodeCertFile = "node-client.crt"
	nodeCAFile   = "node-ca.crt"
)

// identityDir is where the node keeps its key and certificate.
func (a *NodeAgent) identityDir() string { return filepath.Join(a.dataDir, "identity") }

// loadIdentity reads the stored certificate, if there is a usable one.
func (a *NodeAgent) loadIdentity() (*tls.Certificate, *x509.Certificate, error) {
	dir := a.identityDir()
	certPEM, err := os.ReadFile(filepath.Join(dir, nodeCertFile))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, nodeKeyFile))
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("stored certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return &pair, leaf, nil
}

// newCSR generates a fresh key and a certificate request for it.
//
// A NEW key on every issuance, including renewals. Reusing the key would mean a
// key that leaked once stays valuable across every future certificate, which
// removes most of the benefit of them expiring at all.
//
// The subject is left empty: the panel sets the common name from the node it
// authenticated, and anything put here would be a request it ignores.
func newCSR() (csrPEM []byte, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// certResponse is what the panel returns from bootstrap and renew.
type certResponse struct {
	CertPEM   string    `json:"cert_pem"`
	CAPEM     string    `json:"ca_pem"`
	NotAfter  time.Time `json:"not_after"`
	RenewFrom time.Time `json:"renew_from"`
}

// saveIdentity writes the key, certificate and CA to disk.
func (a *NodeAgent) saveIdentity(keyPEM []byte, resp *certResponse) error {
	dir := a.identityDir()
	// 0700: this directory holds the key that IS this node's identity.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, nodeKeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, nodeCertFile), []byte(resp.CertPEM), 0o644); err != nil {
		return err
	}
	if resp.CAPEM != "" {
		if err := os.WriteFile(filepath.Join(dir, nodeCAFile), []byte(resp.CAPEM), 0o644); err != nil {
			return err
		}
	}
	// Drop the cached client so the next call presents the new certificate.
	a.mu.Lock()
	a.client = nil
	a.mu.Unlock()
	return nil
}

// bootstrap spends the one-time token for a client certificate.
//
// Skipped silently when the node already holds a usable certificate: the token
// is single-use, so a restart must not try to spend it again and fail on a
// panel that correctly refuses.
func (a *NodeAgent) bootstrap() error {
	if _, leaf, err := a.loadIdentity(); err == nil && time.Now().Before(leaf.NotAfter) {
		return nil
	}
	if a.bootstrapToken == "" {
		return errors.New("no bootstrap token: re-run the enrolment command from the panel")
	}
	csrPEM, keyPEM, err := newCSR()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"token": a.bootstrapToken, "csr_pem": string(csrPEM)})
	var resp certResponse
	if err := a.post("/api/node/bootstrap", body, &resp); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if resp.CertPEM == "" {
		return errors.New("bootstrap: the panel returned no certificate")
	}
	return a.saveIdentity(keyPEM, &resp)
}

// renewIfNeeded replaces the certificate before it expires.
//
// Called from the heartbeat loop rather than on a timer of its own: the
// heartbeat is already the node's proof that it can reach the panel, and a
// renewal that only fires on a timer would first be attempted at the exact
// moment a long-disconnected node comes back — when it is most likely to fail.
func (a *NodeAgent) renewIfNeeded() {
	_, leaf, err := a.loadIdentity()
	if err != nil {
		return // no certificate yet; bootstrap owns that path
	}
	if time.Now().Before(leaf.NotAfter.Add(-renewBefore)) {
		return
	}
	csrPEM, keyPEM, err := newCSR()
	if err != nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	var resp certResponse
	if err := a.post("/api/node/renew", body, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: certificate renewal failed:", err)
		return
	}
	if resp.CertPEM == "" {
		return
	}
	if err := a.saveIdentity(keyPEM, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: could not store the renewed certificate:", err)
		return
	}
	fmt.Println("forgenode: client certificate renewed, valid until", resp.NotAfter.Format(time.RFC3339))
}

// renewBefore mirrors the panel's own window.
const renewBefore = 10 * 24 * time.Hour

// clientCertificate returns the node's certificate for the TLS handshake, or
// nil when it has none yet.
func (a *NodeAgent) clientCertificate() *tls.Certificate {
	pair, _, err := a.loadIdentity()
	if err != nil {
		return nil
	}
	return pair
}

// identityFingerprint is the stored certificate's serial, for logging.
func (a *NodeAgent) identityFingerprint() string {
	_, leaf, err := a.loadIdentity()
	if err != nil {
		return ""
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s (expires %s)", leaf.SerialNumber.String(), leaf.NotAfter.Format(time.RFC3339))
	return b.String()
}
