package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// certExpiringIn mints a real certificate for cn that expires after d.
func certExpiringIn(t *testing.T, cn string, d time.Duration) (certPEM, keyPEM []byte) {
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
		NotAfter:     time.Now().Add(d),
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

// autocert renews on the NEXT TLS HANDSHAKE. That is fine for a busy site and
// wrong for an admin panel, which can go weeks between visits — and the visit
// that would have triggered renewal is the one that fails. A DNS-01 panel never
// renews through autocert at all. telegram.EventCertExpiry was declared for
// exactly this and had no caller anywhere in the tree.
func TestACertificateNearingExpiryIsReported(t *testing.T) {
	s, _ := adminAPI(t)
	// Five days and a bit. The count rounds DOWN — never overstating the time
	// left is the right direction for an expiry warning — so an exact multiple
	// would report four and make this test about arithmetic rather than about
	// whether the alert names a number at all.
	certPEM, keyPEM := certExpiringIn(t, "soon.example.com", 5*24*time.Hour+time.Hour)
	if _, err := s.certs.Import(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateDomain(&store.Domain{Name: "soon.example.com"}); err != nil {
		t.Fatal(err)
	}

	var messages []string
	s.notifier = testNotifier2(func(msg string) { messages = append(messages, msg) })
	s.sweepCertificates()

	if len(messages) == 0 {
		t.Fatal("a certificate five days from expiry raised no alert")
	}
	joined := strings.Join(messages, " ")
	if !strings.Contains(joined, "soon.example.com") {
		t.Errorf("the alert does not name the domain: %s", joined)
	}
	// The number matters: "expiring soon" tells an operator nothing about
	// whether to act today or next week.
	if !strings.Contains(joined, "5 day") {
		t.Errorf("the alert does not say how long is left: %s", joined)
	}
}

// A healthy certificate must be silent. Let's Encrypt issues for 90 days and
// renews at 30, so warning at 30 would fire on every working panel and train
// the operator to ignore the channel.
func TestAHealthyCertificateIsSilent(t *testing.T) {
	s, _ := adminAPI(t)
	certPEM, keyPEM := certExpiringIn(t, "fine.example.com", 60*24*time.Hour)
	if _, err := s.certs.Import(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateDomain(&store.Domain{Name: "fine.example.com"}); err != nil {
		t.Fatal(err)
	}
	sent := 0
	s.notifier = testNotifier(func() { sent++ })
	s.sweepCertificates()
	if sent != 0 {
		t.Errorf("a certificate 60 days from expiry raised %d alert(s)", sent)
	}
}

// An already-expired certificate reads differently from one about to expire:
// clients are refusing the connection NOW, and the message has to say so.
func TestAnExpiredCertificateSaysItHasExpired(t *testing.T) {
	s, _ := adminAPI(t)
	certPEM, keyPEM := certExpiringIn(t, "dead.example.com", -3*24*time.Hour)
	if _, err := s.certs.Import(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateDomain(&store.Domain{Name: "dead.example.com"}); err != nil {
		t.Fatal(err)
	}
	var messages []string
	s.notifier = testNotifier2(func(msg string) { messages = append(messages, msg) })
	s.sweepCertificates()
	joined := strings.Join(messages, " ")
	if !strings.Contains(joined, "EXPIRED") {
		t.Errorf("an expired certificate was reported as merely expiring: %s", joined)
	}
}

// A domain with no certificate yet is the first-issuance path's business. An
// alert here would fire on every fresh install, for every domain, before
// anything is wrong.
func TestADomainWithNoCertificateIsNotAnAlert(t *testing.T) {
	s, _ := adminAPI(t)
	if err := s.db.CreateDomain(&store.Domain{Name: "new.example.com"}); err != nil {
		t.Fatal(err)
	}
	sent := 0
	s.notifier = testNotifier(func() { sent++ })
	s.sweepCertificates()
	if sent != 0 {
		t.Errorf("a domain with no certificate raised %d alert(s)", sent)
	}
}

// The wiring, again: every test above calls sweepCertificates directly and would
// pass with the call removed from runMaintenance.
func TestRunMaintenanceActuallySweepsCertificates(t *testing.T) {
	s, _ := adminAPI(t)
	certPEM, keyPEM := certExpiringIn(t, "wired.example.com", 2*24*time.Hour)
	if _, err := s.certs.Import(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateDomain(&store.Domain{Name: "wired.example.com"}); err != nil {
		t.Fatal(err)
	}
	sent := 0
	s.notifier = testNotifier(func() { sent++ })
	s.runMaintenance()
	if sent == 0 {
		t.Error("runMaintenance did not sweep certificates, so nothing ever will")
	}
}
