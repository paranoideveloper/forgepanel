package nodeca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func csrFor(t *testing.T, subject pkix.Name) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	if b == nil {
		t.Fatal("not PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnIssuedCertificateIdentifiesItsNode(t *testing.T) {
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, err := ca.SignNodeCSR(csr, 7)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.VerifyNode(parse(t, issued.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if id != 7 {
		t.Fatalf("verified as node %d, want 7", id)
	}
}

func TestTheSubjectComesFromThePanelNotTheRequest(t *testing.T) {
	// A CSR's subject is a REQUEST, not a fact. Honouring it would let a node
	// ask to be issued as another node — the one thing a private CA must never
	// do, because every check downstream trusts the common name.
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{CommonName: NodeCN(999)})
	issued, err := ca.SignNodeCSR(csr, 3)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.VerifyNode(parse(t, issued.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if id != 3 {
		t.Fatalf("a CSR asking to be node 999 was issued as node %d, want 3", id)
	}
}

func TestACSRSignedByADifferentKeyIsRefused(t *testing.T) {
	// Proof of possession. Without it anyone could submit someone else's public
	// key and have a certificate issued for a key they do not control.
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	// Corrupt the signature.
	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := ca.SignNodeCSR(tampered, 1); err == nil {
		t.Fatal("a CSR with a broken signature was signed")
	}
}

func TestANodeCertificateCannotActAsAServerOrACA(t *testing.T) {
	// A control-plane certificate that also worked as a server certificate could
	// impersonate the PANEL to another node; one that was a CA could mint
	// identities for the whole fleet.
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, err := ca.SignNodeCSR(csr, 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parse(t, issued.CertPEM)
	if leaf.IsCA {
		t.Error("the node certificate is a CA")
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Error("the node certificate can act as a server certificate")
		}
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want client auth only", leaf.ExtKeyUsage)
	}
}

func TestRevokingACertificateStopsItImmediately(t *testing.T) {
	// Panel-side and immediate. Revocation must not need the node's
	// cooperation: a node whose key has leaked is exactly the node that will not
	// help you.
	dir := t.TempDir()
	ca, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, _ := ca.SignNodeCSR(csr, 4)
	cert := parse(t, issued.CertPEM)

	if _, err := ca.VerifyNode(cert); err != nil {
		t.Fatal(err)
	}
	if err := ca.Revoke(issued.Serial); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.VerifyNode(cert); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked certificate still verified (%v)", err)
	}

	// And it must stay revoked across a restart — otherwise a panel reboot
	// silently reinstates every credential that was ever taken away.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.VerifyNode(cert); !errors.Is(err, ErrRevoked) {
		t.Fatalf("the revocation did not survive a restart (%v)", err)
	}
}

func TestAnExpiredCertificateIsRefused(t *testing.T) {
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, _ := ca.SignNodeCSR(csr, 5)
	cert := parse(t, issued.CertPEM)

	ca.SetClock(func() time.Time { return issued.NotAfter.Add(time.Hour) })
	if _, err := ca.VerifyNode(cert); err == nil {
		t.Fatal("an expired certificate verified")
	}
}

func TestACertificateFromAnotherCAIsRefused(t *testing.T) {
	// The obvious attack: bring your own CA.
	ours, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, _ := theirs.SignNodeCSR(csr, 1)
	if _, err := ours.VerifyNode(parse(t, issued.CertPEM)); err == nil {
		t.Fatal("a certificate signed by a foreign CA authenticated a node")
	}
}

func TestThePanelClientCertificateIsNotTheCA(t *testing.T) {
	// Using the CA key as the panel's own client identity means every outbound
	// control-plane call carries the key that can issue certificates for the
	// whole fleet — so anything that terminates that connection is one step from
	// minting node identities at will.
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.PanelClientCert()
	if err != nil {
		t.Fatal(err)
	}
	leaf := parse(t, certPEM)
	if leaf.IsCA {
		t.Fatal("the panel's client certificate is a CA certificate")
	}
	if strings.Contains(leaf.Subject.CommonName, "CA") {
		t.Errorf("the panel client CN is %q, which reads as the CA", leaf.Subject.CommonName)
	}
	// It must not authenticate as a node either.
	if _, err := ca.VerifyNode(leaf); err == nil {
		t.Fatal("the panel's own certificate authenticates as a node")
	}
	if len(keyPEM) == 0 {
		t.Fatal("no key was returned")
	}

	// Re-reading returns the same certificate rather than minting a new one on
	// every call.
	again, _, err := ca.PanelClientCert()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(certPEM) {
		t.Fatal("a second call minted a different panel certificate")
	}
}

func TestTheCASurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	issued, _ := first.SignNodeCSR(csr, 2)

	// A new CA per restart would invalidate every node certificate at once —
	// a fleet-wide outage on an ordinary panel upgrade.
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.VerifyNode(parse(t, issued.CertPEM)); err != nil {
		t.Fatalf("a certificate issued before the restart no longer verifies: %v", err)
	}
	if second.Fingerprint() != first.Fingerprint() {
		t.Fatal("the CA changed across a restart")
	}
}

func TestTheCAKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("the CA key is mode %o; it can mint an identity for any node in the fleet", perm)
	}
}

func TestNodeCNRoundTrips(t *testing.T) {
	for _, id := range []uint{1, 42, 999999} {
		got, ok := NodeIDFromCN(NodeCN(id))
		if !ok || got != id {
			t.Errorf("NodeCN(%d) did not round-trip (got %d, ok=%v)", id, got, ok)
		}
	}
	for _, bad := range []string{"", "forgepanel-node-", "forgepanel-node-x", "other-7", "forgepanel-node-0"} {
		if _, ok := NodeIDFromCN(bad); ok {
			t.Errorf("%q was accepted as a node CN", bad)
		}
	}
}

func TestSerialsAreUnpredictable(t *testing.T) {
	// A predictable serial tells an attacker what to put on a revocation list,
	// and CA/Browser Forum practice is 64+ bits of entropy.
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		csr, _ := csrFor(t, pkix.Name{})
		issued, err := ca.SignNodeCSR(csr, uint(i+1))
		if err != nil {
			t.Fatal(err)
		}
		if seen[issued.Serial] {
			t.Fatalf("serial %s was issued twice", issued.Serial)
		}
		seen[issued.Serial] = true
		if len(issued.Serial) < 20 {
			t.Fatalf("serial %s is too short to be 128 bits of entropy", issued.Serial)
		}
	}
}

func TestIssuingWithoutANodeIsRefused(t *testing.T) {
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, pkix.Name{})
	if _, err := ca.SignNodeCSR(csr, 0); err == nil {
		t.Fatal("a certificate was issued for node 0")
	}
}
