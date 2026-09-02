// Package nodeca is the panel's private certificate authority for its control
// plane: it issues one client certificate per node, and one for the panel
// itself.
//
// What it replaces: the node's enrolment token was the whole of its identity,
// forever. It was returned in an API response body, embedded in a
// `curl … | bash` command line — so it lands in shell history, in ps output on
// a shared box, and in the journal — and then sent on every heartbeat for the
// life of the node, with no expiry and no way to rotate it short of deleting
// the node and re-enrolling it. Anyone who ever saw that string could
// impersonate the node indefinitely, and nothing on the panel could tell the
// difference or take it back.
//
// The shape here is the usual one for a control plane: a short-lived
// single-use bootstrap token is spent ONCE to obtain a client certificate, and
// the certificate — which never travels as a bearer string, because the private
// key never leaves the node — is what authenticates every call afterwards. It
// expires on its own, it can be renewed before it does, and revoking it is a
// panel-side action that does not require the node's cooperation.
package nodeca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// caTTL is deliberately long. Rotating the CA invalidates every node
	// certificate at once, which is a fleet-wide outage; the leaves are the
	// thing that rotates.
	caTTL = 10 * 365 * 24 * time.Hour
	// LeafTTL is how long a node certificate is valid. Short enough that a
	// stolen key stops working on its own, long enough that a node offline over
	// a weekend can still renew when it comes back.
	LeafTTL = 30 * 24 * time.Hour
	// RenewBefore is how long before expiry a node should renew.
	RenewBefore = 10 * 24 * time.Hour

	caCertFile    = "ca.crt"
	caKeyFile     = "ca.key"
	panelCertFile = "panel-client.crt"
	panelKeyFile  = "panel-client.key"
	nodeCNPrefix  = "forgepanel-node-"
	panelClientCN = "forgepanel-panel-client"
	organisation  = "ForgePanel"
)

// CA is the panel's node certificate authority.
type CA struct {
	dir  string
	mu   sync.RWMutex
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// revoked holds the serials of certificates that must no longer be
	// accepted, keyed by their decimal string.
	revoked map[string]bool
	now     func() time.Time
}

// Open loads the CA from dir, creating it on first use.
func Open(dir string) (*CA, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("nodeca: no directory was given")
	}
	// 0700: the directory holds the key that can mint an identity for any node.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("nodeca: create %s: %w", dir, err)
	}
	ca := &CA{dir: dir, revoked: map[string]bool{}, now: time.Now}
	if err := ca.load(); err == nil {
		_ = ca.loadRevocations()
		return ca, nil
	}
	if err := ca.create(); err != nil {
		return nil, err
	}
	_ = ca.loadRevocations()
	return ca, nil
}

func (c *CA) load() error {
	certPEM, err := os.ReadFile(filepath.Join(c.dir, caCertFile))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(c.dir, caKeyFile))
	if err != nil {
		return err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return errors.New("nodeca: the stored CA is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	c.cert, c.key = cert, key
	return nil
}

func (c *CA) create() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("nodeca: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ForgePanel Node CA",
			Organization: []string{organisation},
		},
		NotBefore: now.Add(-time.Hour), // tolerate a little clock skew on nodes
		NotAfter:  now.Add(caTTL),
		// A CA that can also sign server certificates for arbitrary names would
		// be a much bigger thing to lose than a control-plane CA needs to be.
		// MaxPathLenZero stops it issuing intermediates.
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("nodeca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.dir, caCertFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("nodeca: write CA certificate: %w", err)
	}
	// 0600: this key mints node identities.
	if err := os.WriteFile(filepath.Join(c.dir, caKeyFile),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("nodeca: write CA key: %w", err)
	}
	c.cert, c.key = cert, key
	return nil
}

// CertPEM returns the CA certificate, which a node needs to verify the panel
// and the panel needs to verify a node.
func (c *CA) CertPEM() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Pool returns the CA as a verification pool.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	c.mu.RLock()
	pool.AddCert(c.cert)
	c.mu.RUnlock()
	return pool
}

// NodeCN is the subject common name for a node's certificate.
func NodeCN(nodeID uint) string { return nodeCNPrefix + strconv.FormatUint(uint64(nodeID), 10) }

// NodeIDFromCN parses a node id back out of a common name.
func NodeIDFromCN(cn string) (uint, bool) {
	rest, ok := strings.CutPrefix(cn, nodeCNPrefix)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(rest, 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

// Issued is a signed certificate and the metadata the panel records about it.
type Issued struct {
	CertPEM   []byte    `json:"cert_pem"`
	CAPEM     []byte    `json:"ca_pem"`
	Serial    string    `json:"serial"`
	NotAfter  time.Time `json:"not_after"`
	RenewFrom time.Time `json:"renew_from"`
}

// SignNodeCSR issues a client certificate for a node from its CSR.
//
// The node generates its own key and never sends it, which is the property that
// makes this better than a token: there is no secret in flight to intercept, and
// the panel could not impersonate a node even if it wanted to.
func (c *CA) SignNodeCSR(csrDER []byte, nodeID uint) (*Issued, error) {
	if nodeID == 0 {
		return nil, errors.New("nodeca: a certificate cannot be issued without a node")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("nodeca: the certificate request could not be parsed: %w", err)
	}
	// Check the requester holds the private key for the public key it sent.
	// Without this, anyone could submit someone else's public key and have a
	// certificate issued for a key they do not control.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("nodeca: the certificate request is not signed by its own key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	caCert, caKey := c.cert, c.key
	c.mu.RUnlock()

	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// The subject comes from the PANEL, not from the CSR. A CSR's subject is
		// a request, not a fact: honouring it would let a node ask to be issued
		// as another node.
		Subject: pkix.Name{
			CommonName:   NodeCN(nodeID),
			Organization: []string{organisation},
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(LeafTTL),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Client auth ONLY. A control-plane certificate that also works as a
		// server certificate could be used to impersonate the panel to another
		// node.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("nodeca: sign node certificate: %w", err)
	}
	return &Issued{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAPEM:     c.CertPEM(),
		Serial:    serial.String(),
		NotAfter:  tmpl.NotAfter,
		RenewFrom: tmpl.NotAfter.Add(-RenewBefore),
	}, nil
}

// PanelClientCert returns the panel's own client certificate, minting it once.
//
// A separate NON-CA leaf, not the CA certificate itself. Using the CA key as a
// client identity means every outbound control-plane call carries the key that
// can issue certificates for the whole fleet — so any node the panel talks to,
// or anything that manages to terminate that connection, is one step from
// minting node identities at will. The leaf can be replaced without touching
// the CA.
func (c *CA) PanelClientCert() (certPEM, keyPEM []byte, err error) {
	certPath := filepath.Join(c.dir, panelCertFile)
	keyPath := filepath.Join(c.dir, panelKeyFile)
	if cp, err1 := os.ReadFile(certPath); err1 == nil {
		if kp, err2 := os.ReadFile(keyPath); err2 == nil && c.stillValid(cp) {
			return cp, kp, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	c.mu.RLock()
	caCert, caKey := c.cert, c.key
	c.mu.RUnlock()
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: panelClientCN, Organization: []string{organisation}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(LeafTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeca: sign the panel client certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = os.WriteFile(certPath, certPEM, 0o644)
	_ = os.WriteFile(keyPath, keyPEM, 0o600)
	return certPEM, keyPEM, nil
}

func (c *CA) stillValid(certPEM []byte) bool {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return false
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return false
	}
	return c.now().Before(cert.NotAfter.Add(-RenewBefore))
}

// ErrRevoked is returned when a presented certificate has been revoked.
var ErrRevoked = errors.New("nodeca: this certificate has been revoked")

// VerifyNode checks a presented client certificate and returns the node it
// identifies.
func (c *CA) VerifyNode(cert *x509.Certificate) (uint, error) {
	if cert == nil {
		return 0, errors.New("nodeca: no client certificate was presented")
	}
	c.mu.RLock()
	revoked := c.revoked[cert.SerialNumber.String()]
	c.mu.RUnlock()
	if revoked {
		return 0, ErrRevoked
	}
	opts := x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: c.now(),
		// Client auth only: a certificate issued for something else must not
		// authenticate a node here.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return 0, fmt.Errorf("nodeca: the client certificate is not valid: %w", err)
	}
	id, ok := NodeIDFromCN(cert.Subject.CommonName)
	if !ok {
		return 0, fmt.Errorf("nodeca: %q is not a node certificate", cert.Subject.CommonName)
	}
	return id, nil
}

// Revoke marks a serial as no longer acceptable.
//
// Panel-side and immediate: revoking does not need the node's cooperation, which
// is the point — a node whose key has leaked is exactly the node that will not
// help you.
func (c *CA) Revoke(serial string) error {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return nil
	}
	c.mu.Lock()
	c.revoked[serial] = true
	list := make([]string, 0, len(c.revoked))
	for s := range c.revoked {
		list = append(list, s)
	}
	c.mu.Unlock()
	return os.WriteFile(filepath.Join(c.dir, "revoked.txt"),
		[]byte(strings.Join(list, "\n")+"\n"), 0o600)
}

// IsRevoked reports whether a serial has been revoked.
func (c *CA) IsRevoked(serial string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revoked[strings.TrimSpace(serial)]
}

func (c *CA) loadRevocations() error {
	raw, err := os.ReadFile(filepath.Join(c.dir, "revoked.txt"))
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range strings.Split(string(raw), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			c.revoked[s] = true
		}
	}
	return nil
}

// Fingerprint is the CA certificate's SHA-256, hex — what a node pins.
func (c *CA) Fingerprint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// SetClock is for tests.
func (c *CA) SetClock(f func() time.Time) {
	c.mu.Lock()
	c.now = f
	c.mu.Unlock()
}

func randomSerial() (*big.Int, error) {
	// 128 bits. A predictable serial lets someone guess what to put on a
	// revocation list, and CA/Browser Forum practice is 64+ bits of entropy.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("nodeca: generate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}
