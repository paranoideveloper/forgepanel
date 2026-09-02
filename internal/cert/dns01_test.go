package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- a minimal ACME CA -------------------------------------------------------
//
// The whole point of this row is a flow, not a function: account, order, one
// authorization per name, a challenge each, finalize, download. Testing the
// pieces separately would have proved nothing about the one bug that actually
// bites — two authorizations wanting two different TXT records at the SAME name
// at the SAME time — because that only exists when the order has more than one
// identifier. So this speaks enough real ACME to drive the client through it.

type fakeCA struct {
	srv *httptest.Server
	mu  sync.Mutex

	// identifiers requested in the order, in order.
	identifiers []string
	wildcard    map[string]bool
	// accepted records which challenges were accepted, and — crucially — what
	// the zone looked like at that moment.
	accepted     []string
	acceptedIdx  map[int]bool
	zoneAtAccept [][]string

	// zoneSnapshot is injected by the test so the CA can look at the zone the
	// way a real one would.
	zoneSnapshot func(fqdn string) []string

	// csr is what finalize was given. A real CA signs the public key inside the
	// CSR; minting a fresh key here would hand back a certificate whose key the
	// client does not hold, and the test would prove nothing about the pair.
	csr    *x509.CertificateRequest
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	ca := &fakeCA{wildcard: map[string]bool{}, acceptedIdx: map[int]bool{}, caKey: key, caCert: caCert}
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.handle))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (c *fakeCA) url(p string) string { return c.srv.URL + p }

func (c *fakeCA) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path

	switch {
	case path == "/directory":
		json.NewEncoder(w).Encode(map[string]any{
			"newNonce": c.url("/new-nonce"), "newAccount": c.url("/new-account"),
			"newOrder": c.url("/new-order"), "revokeCert": c.url("/revoke"),
			"keyChange": c.url("/key-change"),
		})
	case path == "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case path == "/new-account":
		w.Header().Set("Location", c.url("/acct/1"))
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	case path == "/new-order":
		c.newOrder(w, r)
	case strings.HasPrefix(path, "/authz/"):
		c.authz(w, path)
	case strings.HasPrefix(path, "/chal/"):
		c.accept(w, path)
	case path == "/order/1":
		c.order(w, "ready")
	case path == "/finalize":
		c.finalize(w, r)
	case path == "/cert/1":
		c.cert(w)
	default:
		http.NotFound(w, r)
	}
}

// jwsPayload pulls the (unsigned, base64url) payload out of a JWS body. The
// signature is not verified: this CA exists to drive the protocol, not to test
// the client's crypto.
func jwsPayload(r *http.Request) map[string]any {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		return nil
	}
	raw, err := base64URLDecode(env.Payload)
	if err != nil {
		return nil
	}
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

var base64Std = base64.URLEncoding

func base64URLDecode(s string) ([]byte, error) { return jwsDecode(s) }

func (c *fakeCA) newOrder(w http.ResponseWriter, r *http.Request) {
	payload := jwsPayload(r)
	c.mu.Lock()
	c.identifiers = nil
	if ids, ok := payload["identifiers"].([]any); ok {
		for _, id := range ids {
			m, _ := id.(map[string]any)
			v, _ := m["value"].(string)
			// A real CA splits "*.example.com" into a bare identifier with the
			// wildcard flag set. Reproducing that is the whole reason the
			// same-name collision exists at all.
			if strings.HasPrefix(v, "*.") {
				bare := strings.TrimPrefix(v, "*.")
				c.wildcard[bare] = true
				v = bare
			}
			c.identifiers = append(c.identifiers, v)
		}
	}
	n := len(c.identifiers)
	c.mu.Unlock()

	authz := make([]string, n)
	for i := range authz {
		authz[i] = c.url(fmt.Sprintf("/authz/%d", i))
	}
	w.Header().Set("Location", c.url("/order/1"))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "pending", "authorizations": authz, "finalize": c.url("/finalize"),
	})
}

func (c *fakeCA) authz(w http.ResponseWriter, path string) {
	var i int
	fmt.Sscanf(path, "/authz/%d", &i)
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.identifiers) {
		http.NotFound(w, nil)
		return
	}
	name := c.identifiers[i]
	// A real CA flips the authorization to valid once its challenge passes;
	// staying "pending" forever is what made WaitAuthorization spin.
	status := "pending"
	if c.acceptedIdx[i] {
		status = "valid"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status": status, "wildcard": c.wildcard[name],
		"identifier": map[string]any{"type": "dns", "value": name},
		"challenges": []any{
			map[string]any{"type": "http-01", "url": c.url("/chal/http"), "token": "httptok"},
			map[string]any{"type": "dns-01", "url": c.url(fmt.Sprintf("/chal/%d", i)), "token": fmt.Sprintf("tok%d", i)},
		},
	})
}

func (c *fakeCA) accept(w http.ResponseWriter, path string) {
	var idx int
	fmt.Sscanf(path, "/chal/%d", &idx)
	c.mu.Lock()
	c.acceptedIdx[idx] = true
	c.accepted = append(c.accepted, path)
	// Snapshot the zone exactly when the challenge is accepted — this is the
	// instant a real CA reads it.
	if c.zoneSnapshot != nil && len(c.identifiers) > 0 {
		c.zoneAtAccept = append(c.zoneAtAccept, c.zoneSnapshot("_acme-challenge."+c.identifiers[0]))
	}
	c.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"type": "dns-01", "status": "valid", "url": c.url(path)})
}

func (c *fakeCA) order(w http.ResponseWriter, status string) {
	json.NewEncoder(w).Encode(map[string]any{
		"status": status, "finalize": c.url("/finalize"),
		"authorizations": []string{c.url("/authz/0")},
	})
}

func (c *fakeCA) finalize(w http.ResponseWriter, r *http.Request) {
	if payload := jwsPayload(r); payload != nil {
		if enc, ok := payload["csr"].(string); ok {
			if der, err := jwsDecode(enc); err == nil {
				if csr, err := x509.ParseCertificateRequest(der); err == nil {
					c.mu.Lock()
					c.csr = csr
					c.mu.Unlock()
				}
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status": "valid", "certificate": c.url("/cert/1"),
		"finalize": c.url("/finalize"),
	})
}

func (c *fakeCA) cert(w http.ResponseWriter) {
	c.mu.Lock()
	csr := c.csr
	c.mu.Unlock()
	if csr == nil {
		http.Error(w, "finalize was never called", http.StatusConflict)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, csr.PublicKey, c.caKey)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.caCert.Raw})
}

// --- a zone that behaves like a zone ----------------------------------------

// fakeZone stores TXT records the way DNS does: several values can live at one
// name at the same time.
type fakeZone struct {
	mu      sync.Mutex
	records map[string][]string
	// upsert makes Present REPLACE instead of ADD, to reproduce the bug.
	upsert bool
}

func newFakeZone() *fakeZone { return &fakeZone{records: map[string][]string{}} }

func (z *fakeZone) Present(_ context.Context, fqdn, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.upsert {
		z.records[fqdn] = []string{value}
		return nil
	}
	z.records[fqdn] = append(z.records[fqdn], value)
	return nil
}

func (z *fakeZone) CleanUp(_ context.Context, fqdn, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	var keep []string
	for _, v := range z.records[fqdn] {
		if v != value {
			keep = append(keep, v)
		}
	}
	if len(keep) == 0 {
		delete(z.records, fqdn)
	} else {
		z.records[fqdn] = keep
	}
	return nil
}

func (z *fakeZone) lookup(_ context.Context, fqdn string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string{}, z.records[fqdn]...), nil
}

func (z *fakeZone) at(fqdn string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string{}, z.records[fqdn]...)
}

// --- tests -------------------------------------------------------------------

func TestIssuesAWildcardAndItsApexInOneCertificate(t *testing.T) {
	ca := newFakeCA(t)
	zone := newFakeZone()
	ca.zoneSnapshot = zone.at

	s := NewStore(t.TempDir(), false, nil)
	imp, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup: zone.lookup, PollInterval: time.Millisecond,
	}, "*.example.com", "example.com")
	if err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	got := map[string]bool{}
	for _, d := range imp.Domains {
		got[d] = true
	}
	if !got["*.example.com"] || !got["example.com"] {
		t.Fatalf("certificate covers %v, want both the wildcard and the apex", imp.Domains)
	}
}

func TestBothChallengeRecordsExistAtTheSameNameSimultaneously(t *testing.T) {
	// The bug this exists for: a wildcard and its apex produce TWO
	// authorizations whose dns-01 challenges live at the SAME name,
	// _acme-challenge.example.com, with DIFFERENT values. Publishing with an
	// upsert leaves only the last one, so whichever authorization the CA checks
	// first fails — on a zone that looks entirely correct afterwards, because
	// the surviving record IS valid, just not the one being checked.
	ca := newFakeCA(t)
	zone := newFakeZone()
	ca.zoneSnapshot = zone.at

	s := NewStore(t.TempDir(), false, nil)
	if _, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup: zone.lookup, PollInterval: time.Millisecond,
	}, "*.example.com", "example.com"); err != nil {
		t.Fatalf("issuance failed: %v", err)
	}

	if len(ca.zoneAtAccept) < 2 {
		t.Fatalf("the CA accepted %d challenges, want 2 (one per authorization)", len(ca.zoneAtAccept))
	}
	for i, snapshot := range ca.zoneAtAccept {
		if len(snapshot) != 2 {
			t.Fatalf("at accept #%d the zone held %d TXT record(s) at _acme-challenge.example.com: %v — "+
				"both must be present at once or one authorization fails", i+1, len(snapshot), snapshot)
		}
	}
	if snapshots := ca.zoneAtAccept; snapshots[0][0] == snapshots[0][1] {
		t.Fatalf("the two challenge values are identical (%v); each authorization has its own", snapshots[0])
	}
}

func TestChallengeRecordsAreRemovedAfterIssuance(t *testing.T) {
	// A stale _acme-challenge value is not litter: the CA reads it on the NEXT
	// run and finds it wrong, so one un-cleaned attempt breaks the attempts
	// after it.
	ca := newFakeCA(t)
	zone := newFakeZone()
	s := NewStore(t.TempDir(), false, nil)
	if _, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup: zone.lookup, PollInterval: time.Millisecond,
	}, "example.com"); err != nil {
		t.Fatal(err)
	}
	if left := zone.at("_acme-challenge.example.com"); len(left) != 0 {
		t.Fatalf("left %v behind in the zone", left)
	}
}

func TestChallengeRecordsAreRemovedWhenIssuanceFails(t *testing.T) {
	ca := newFakeCA(t)
	zone := newFakeZone()
	s := NewStore(t.TempDir(), false, nil)
	// A lookup that never sees the record forces the propagation gate to give up.
	_, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup:             func(context.Context, string) ([]string, error) { return nil, nil },
		PropagationTimeout: 10 * time.Millisecond, PollInterval: time.Millisecond,
	}, "example.com")
	if err == nil {
		t.Fatal("issuance succeeded despite the record never becoming visible")
	}
	if left := zone.at("_acme-challenge.example.com"); len(left) != 0 {
		t.Fatalf("a failed run left %v behind; the next attempt would read it and fail too", left)
	}
}

func TestChallengesAreNotAcceptedBeforeTheRecordIsVisible(t *testing.T) {
	// Accepting early is the expensive mistake: the CA checks immediately, a
	// miss marks the authorization invalid rather than retryable, and failed
	// orders count against a rate limit measured in hours.
	ca := newFakeCA(t)
	zone := newFakeZone()
	var visible bool
	var mu sync.Mutex
	gated := func(ctx context.Context, fqdn string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if !visible {
			return nil, nil
		}
		return zone.lookup(ctx, fqdn)
	}
	ca.zoneSnapshot = func(string) []string {
		mu.Lock()
		defer mu.Unlock()
		if !visible {
			return nil // the CA would see nothing
		}
		return zone.at("_acme-challenge.example.com")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		visible = true
		mu.Unlock()
	}()

	s := NewStore(t.TempDir(), false, nil)
	if _, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup: gated, PropagationTimeout: 5 * time.Second, PollInterval: 2 * time.Millisecond,
	}, "example.com"); err != nil {
		t.Fatal(err)
	}
	for i, snap := range ca.zoneAtAccept {
		if len(snap) == 0 {
			t.Fatalf("challenge %d was accepted while the CA could still see nothing at the challenge name", i+1)
		}
	}
}

func TestPropagationTimeoutNamesTheRecordAndWhatToCheck(t *testing.T) {
	ca := newFakeCA(t)
	zone := newFakeZone()
	s := NewStore(t.TempDir(), false, nil)
	_, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup:             func(context.Context, string) ([]string, error) { return nil, nil },
		PropagationTimeout: 5 * time.Millisecond, PollInterval: time.Millisecond,
	}, "example.com")
	if err == nil {
		t.Fatal("expected a propagation failure")
	}
	for _, want := range []string{"_acme-challenge.example.com", "delegated", "CNAME"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q — an operator needs to know where to look", err, want)
		}
	}
}

func TestIssuedCertificateSurvivesARestart(t *testing.T) {
	// Re-issuing on every restart is how an operator meets Let's Encrypt's
	// duplicate-certificate limit: five per week for the same names, then a week
	// of nothing.
	dir := t.TempDir()
	ca := newFakeCA(t)
	zone := newFakeZone()
	s := NewStore(dir, false, nil)
	if _, err := s.IssueDNS01(context.Background(), DNS01Options{
		Solver: zone, DirectoryURL: ca.url("/directory"),
		Lookup: zone.lookup, PollInterval: time.Millisecond,
	}, "*.example.com"); err != nil {
		t.Fatal(err)
	}

	fresh := NewStore(dir, false, nil)
	n, err := fresh.LoadDNS01Cache()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reloaded %d certificates, want 1", n)
	}
	if _, ok := fresh.CachedInfo("api.example.com"); !ok {
		t.Fatal("the reloaded wildcard does not answer for a subdomain")
	}
}

func TestTheAccountKeyIsReusedAcrossRuns(t *testing.T) {
	// A new key is a NEW ACCOUNT at the CA, with its own rate limits and no
	// record of what this panel has already been issued.
	dir := t.TempDir()
	s := NewStore(dir, false, nil)
	k1, err := s.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewStore(dir, false, nil)
	k2, err := fresh.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Public().(*ecdsa.PublicKey).Equal(k2.Public()) {
		t.Fatal("a restart generated a new ACME account key")
	}
}

func TestChallengeNameStripsTheWildcard(t *testing.T) {
	// _acme-challenge.*.example.com is not a name that can exist; the CA's
	// authorization identifier carries the bare domain.
	if got := ChallengeName("*.example.com"); got != "_acme-challenge.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := ChallengeName("Example.COM."); got != "_acme-challenge.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRejectsNamesTheCAWouldRefuse(t *testing.T) {
	for _, bad := range []string{"foo.*.example.com", "*.*.example.com", "ex*mple.com"} {
		if _, err := normalizeDomains([]string{bad}); err == nil {
			t.Errorf("%q was accepted; a wildcard may only be the left-most label", bad)
		}
	}
	got, err := normalizeDomains([]string{"B.example.com", "b.example.com", "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("got %v, want the two distinct names, lowercased and sorted", got)
	}
}

func TestIssuanceNeedsASolver(t *testing.T) {
	s := NewStore(t.TempDir(), false, nil)
	_, err := s.IssueDNS01(context.Background(), DNS01Options{}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "solver") {
		t.Fatalf("got %v, want a clear error about the missing solver", err)
	}
}

// jwsDecode is base64url-without-padding, which is what JWS uses.
func jwsDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64Std.DecodeString(s)
}
