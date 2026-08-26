package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/nodeca"
	"github.com/forgepanel/forgepanel/internal/store"
)

func makeCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// postJSON drives a request through the router, optionally with a verified
// client certificate attached the way the TLS layer would.
func postNodeJSON(t *testing.T, s *Server, path string, body any, clientCert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if clientCert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func parseCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(pemStr))
	if b == nil {
		t.Fatal("response certificate is not PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// storeServer is a panel with a real database and its own data directory, so
// each case gets its own node CA rather than inheriting the previous case's.
func storeServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.DataDir = dir
	s, err := NewWithStore(cfg)
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// nodeWithBootstrap creates a node holding a fresh bootstrap token.
func nodeWithBootstrap(t *testing.T, s *Server, name string, expires time.Time) (*store.Node, string) {
	t.Helper()
	tok := "bootstrap-" + name
	n := &store.Node{
		Name: name, EnrollToken: "legacy-" + name,
		BootstrapHash: hashBootstrap(tok), BootstrapExpires: &expires,
	}
	if err := s.db.CreateNode(n); err != nil {
		t.Fatal(err)
	}
	return n, tok
}

func TestABootstrapTokenBuysExactlyOneCertificate(t *testing.T) {
	// Single-use is the whole point. An enrolment command that still works after
	// the node has enrolled is a permanent bearer credential again, just with
	// extra steps — which is precisely what this replaced.
	s := storeServer(t)
	_, tok := nodeWithBootstrap(t, s, "n1", time.Now().Add(time.Hour))

	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	if rec.Code != 200 {
		t.Fatalf("first bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	rec2 := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	if rec2.Code == 200 {
		t.Fatal("the bootstrap token was spendable a second time")
	}
}

func TestAnExpiredBootstrapTokenIsRefused(t *testing.T) {
	// The enrolment command is pasted into terminals, chat and ticket systems.
	// The window in which it is worth anything should be the window in which
	// someone is actually running it.
	s := storeServer(t)
	_, tok := nodeWithBootstrap(t, s, "n2", time.Now().Add(-time.Minute))

	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	if rec.Code == 200 {
		t.Fatal("an expired bootstrap token was accepted")
	}
}

func TestTheBootstrapTokenIsNotStoredInTheClear(t *testing.T) {
	// A panel database that has been read should not yield a working credential
	// for every node in it.
	s := storeServer(t)
	n, tok := nodeWithBootstrap(t, s, "n3", time.Now().Add(time.Hour))
	got, err := s.db.NodeByID(n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BootstrapHash == tok {
		t.Fatal("the bootstrap token is stored verbatim")
	}
	if strings.Contains(got.BootstrapHash, tok) {
		t.Fatal("the stored hash contains the token")
	}
}

func TestTheIssuedCertificateNamesTheNodeThatSpentTheToken(t *testing.T) {
	s := storeServer(t)
	n, tok := nodeWithBootstrap(t, s, "n4", time.Now().Add(time.Hour))

	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.CAPEM == "" {
		t.Error("the node was not given the CA to verify the panel against")
	}
	id, ok := nodeca.NodeIDFromCN(parseCert(t, out.CertPEM).Subject.CommonName)
	if !ok || id != n.ID {
		t.Fatalf("the certificate names node %d, want %d", id, n.ID)
	}
}

func TestHeartbeatAcceptsACertificateWithNoToken(t *testing.T) {
	// The point of the whole change: nothing that authenticates the node is
	// transmitted any more.
	s := storeServer(t)
	n, tok := nodeWithBootstrap(t, s, "n5", time.Now().Add(time.Hour))
	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	if rec.Code != 200 {
		t.Fatalf("bootstrap: %s", rec.Body.String())
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	cert := parseCert(t, out.CertPEM)

	hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, cert)
	if hb.Code != 200 {
		t.Fatalf("heartbeat with a client certificate and no token: %d %s", hb.Code, hb.Body.String())
	}
	_ = n
}

func TestARevokedCertificateStopsAuthenticating(t *testing.T) {
	// Revocation is panel-side and immediate. A node whose key has leaked is
	// exactly the node that will not cooperate in taking it away.
	s := storeServer(t)
	n, tok := nodeWithBootstrap(t, s, "n6", time.Now().Add(time.Hour))
	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	cert := parseCert(t, out.CertPEM)

	if hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, cert); hb.Code != 200 {
		t.Fatalf("precondition: %s", hb.Body.String())
	}
	fresh, _ := s.db.NodeByID(n.ID)
	s.revokeNodeCert(fresh)

	if hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, cert); hb.Code == 200 {
		t.Fatal("a revoked certificate still authenticated a heartbeat")
	}
}

func TestACertificateFromAnotherCADoesNotAuthenticate(t *testing.T) {
	s := storeServer(t)
	other, err := nodeca.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	issued, err := other.SignNodeCSR(der, 1)
	if err != nil {
		t.Fatal(err)
	}
	forged := parseCert(t, string(issued.CertPEM))

	if hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, forged); hb.Code == 200 {
		t.Fatal("a certificate from a foreign CA authenticated a heartbeat")
	}
}

func TestRenewalNeedsTheCurrentCertificateNotAToken(t *testing.T) {
	// Renewal authenticated by a bearer token would put the permanent-credential
	// problem straight back: whoever holds the token could renew forever.
	s := storeServer(t)
	_, tok := nodeWithBootstrap(t, s, "n7", time.Now().Add(time.Hour))
	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	cert := parseCert(t, out.CertPEM)

	// Assert on the REASON, not just the status. Without a certificate the
	// handler would fall through to looking up node 0, which also fails — so a
	// bare "not 200" passes even with the certificate check removed, and an
	// earlier version of this test did exactly that.
	r0 := postNodeJSON(t, s, "/api/node/renew", map[string]string{"csr_pem": makeCSR(t)}, nil)
	if r0.Code == 200 {
		t.Fatal("renewal succeeded with no client certificate")
	}
	if !strings.Contains(r0.Body.String(), "current client certificate") {
		t.Fatalf("renewal was refused for the wrong reason: %s", r0.Body.String())
	}
	r := postNodeJSON(t, s, "/api/node/renew", map[string]string{"csr_pem": makeCSR(t)}, cert)
	if r.Code != 200 {
		t.Fatalf("renewal with the current certificate: %d %s", r.Code, r.Body.String())
	}
}

func TestRenewingRevokesTheCertificateItReplaces(t *testing.T) {
	// Otherwise a renewal after a suspected compromise achieves nothing for
	// another thirty days: the old certificate keeps working until it expires.
	s := storeServer(t)
	_, tok := nodeWithBootstrap(t, s, "n8", time.Now().Add(time.Hour))
	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	var first struct {
		CertPEM string `json:"cert_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &first)
	oldCert := parseCert(t, first.CertPEM)

	r := postNodeJSON(t, s, "/api/node/renew", map[string]string{"csr_pem": makeCSR(t)}, oldCert)
	if r.Code != 200 {
		t.Fatalf("renew: %s", r.Body.String())
	}
	if hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, oldCert); hb.Code == 200 {
		t.Fatal("the replaced certificate still authenticates")
	}
}

func TestDeletingANodeRevokesItsCertificate(t *testing.T) {
	// A deleted node whose certificate still verifies is a working credential
	// for a node the operator believes is gone.
	s := storeServer(t)
	n, tok := nodeWithBootstrap(t, s, "n9", time.Now().Add(time.Hour))
	rec := postNodeJSON(t, s, "/api/node/bootstrap", map[string]string{"token": tok, "csr_pem": makeCSR(t)}, nil)
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	cert := parseCert(t, out.CertPEM)

	fresh, _ := s.db.NodeByID(n.ID)
	s.revokeNodeCert(fresh)
	_ = s.db.DeleteNode(n.ID)

	if hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"cpu": 1.0}, cert); hb.Code == 200 {
		t.Fatal("a deleted node's certificate still authenticated")
	}
}

func TestTheLegacyTokenStillWorksUntilMTLSIsRequired(t *testing.T) {
	// An upgrade must not disconnect a fleet that has not re-enrolled. The
	// tokens those nodes hold ARE the problem, so the switch exists — it is just
	// not thrown for them.
	s := storeServer(t)
	n := &store.Node{Name: "legacy", EnrollToken: "old-token"}
	if err := s.db.CreateNode(n); err != nil {
		t.Fatal(err)
	}
	hb := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"token": "old-token", "cpu": 1.0}, nil)
	if hb.Code != 200 {
		t.Fatalf("a pre-mTLS node was disconnected by the upgrade: %d %s", hb.Code, hb.Body.String())
	}

	if p := s.cfg.Panel(); p != nil {
		p.RequireNodeMTLS = true
	}
	hb2 := postNodeJSON(t, s, "/api/node/heartbeat", map[string]any{"token": "old-token", "cpu": 1.0}, nil)
	if hb2.Code == 200 {
		t.Fatal("the legacy token was still accepted with RequireNodeMTLS set")
	}
}

func TestTheListenerAsksForAClientCertificateWithoutRequiringOne(t *testing.T) {
	// Requiring one would break the panel for browsers: the same listener serves
	// the admin UI and the node control plane.
	s := storeServer(t)
	cfg := s.CertTLSConfig()
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven — anything stricter locks browsers out", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("no ClientCAs pool, so a node certificate could never be verified")
	}
}
