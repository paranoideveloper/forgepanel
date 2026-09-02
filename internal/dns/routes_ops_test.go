package dns

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRoutesZoneSettings(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")

	rec := f.do(t, http.MethodPost, "/dns/zone-settings", map[string]any{
		"credential": "cf1", "zone": "zone1", "recommended": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	if f.cf.Settings["zone1"]["ssl"] != "strict" {
		t.Fatalf("expected strict origin pull, got %q", f.cf.Settings["zone1"]["ssl"])
	}

	rec = f.do(t, http.MethodGet, "/dns/zone-settings?credential=cf1&zone=zone1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// A provider with no settings API must 501 with the manual instructions.
func TestRoutesZoneSettingsUnsupported(t *testing.T) {
	f := newRouteFixture(t)
	cs, err := NewCredentialStore(f.deps.Credentials, f.deps.Encryptor)
	requireNoError(t, err)
	_, err = cs.Put("ds1", "desec", "", Credentials{"token": "t"})
	requireNoError(t, err)

	rec := f.do(t, http.MethodPost, "/dns/zone-settings", map[string]any{
		"credential": "ds1", "zone": "example.com", "recommended": true,
	})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, decodeBody(t, rec)["remediation"].(string), "Flexible", "unsupported settings remediation")
}

func TestRoutesSetProxiedUnsupportedOnDesec(t *testing.T) {
	f := newRouteFixture(t)
	cs, err := NewCredentialStore(f.deps.Credentials, f.deps.Encryptor)
	requireNoError(t, err)
	_, err = cs.Put("ds1", "desec", "", Credentials{"token": "t"})
	requireNoError(t, err)

	rec := f.do(t, http.MethodPost, "/dns/records/proxy", map[string]any{
		"credential": "ds1", "zone": "example.com", "record_id": "ws/A", "proxied": true,
	})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, decodeBody(t, rec)["remediation"].(string), "REALITY", "no-CDN remediation")
}

func TestRoutesPreflight(t *testing.T) {
	f := newRouteFixture(t)
	f.res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	f.res.TXT["_acme-challenge.ws.example.com"] = nil

	rec := f.do(t, http.MethodPost, "/dns/preflight", map[string]any{
		"domain": "ws.example.com", "expect_ip": "203.0.113.10", "challenge": "dns-01",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["ok"] != true {
		t.Fatalf("expected a passing report: %s", rec.Body)
	}
	checks, _ := body["checks"].([]any)
	if len(checks) < 4 {
		t.Fatalf("expected a full check list, got %v", body["checks"])
	}

	// A domain that does not resolve must come back 422 with the report intact,
	// so the UI can show exactly which check failed and why.
	rec = f.do(t, http.MethodPost, "/dns/preflight", map[string]any{
		"domain": "missing.example.com", "expect_ip": "203.0.113.10", "challenge": "dns-01",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for an unready domain, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, rec.Body.String(), "has not been created", "preflight failure remediation")
}

func TestRoutesPool(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.do(t, http.MethodPost, "/dns/pool/edge/entries", map[string]any{
		"domain": "a.example.com", "zone": "zone1", "target": "203.0.113.10",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body)
	}

	rec = f.do(t, http.MethodGet, "/dns/pool/edge", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	entries, _ := decodeBody(t, rec)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	rec = f.do(t, http.MethodDelete, "/dns/pool/edge/entries?domain=a.example.com", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	rec = f.do(t, http.MethodGet, "/dns/pool/edge", nil)
	entries, _ = decodeBody(t, rec)["entries"].([]any)
	if len(entries) != 0 {
		t.Fatalf("expected the entry to be gone, got %d", len(entries))
	}
}

// Without pool storage wired, the pool routes must 501 with the wiring
// instruction rather than panicking.
func TestRoutesPoolWithoutStorage(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	r := gin.New()
	RegisterRoutes(r, Deps{Credentials: NewMemStore(), Encryptor: enc})

	req := httptest.NewRequest(http.MethodGet, "/dns/pool/edge", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, rec.Body.String(), "dns.NewGormStore", "pool wiring remediation")
}

func TestRoutesCleanIPScanAndFetch(t *testing.T) {
	f := newRouteFixture(t)
	srv := newTLSTestServer(t, "ws.example.com")
	// The scan route builds its own ScanConfig, so drive it through explicit
	// addresses against the local listener by scanning the loopback directly.
	rec := f.do(t, http.MethodPost, "/dns/cleanip/scan", map[string]any{
		"name": "ws.example.com", "sni": "ws.example.com",
		"port": srv.Port, "addresses": []string{"127.0.0.1"}, "probes": 1,
	})
	// The handshake against a self-signed certificate fails verification, so
	// this reports a shortfall — which is itself the behaviour under test.
	if rec.Code != http.StatusOK && rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 200 or 422, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["report"] == nil {
		t.Fatalf("the scan must always return its report: %s", rec.Body)
	}

	// A set that was never scanned must 404 with advice.
	rec = f.do(t, http.MethodGet, "/dns/cleanip/never-scanned", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, decodeBody(t, rec)["remediation"].(string), "run a scan first", "missing set remediation")

	// A stored-but-stale set comes back with a warning rather than an error.
	requireNoError(t, f.store.SaveCleanIPs(CleanIPSet{
		Name: "old", SNI: "ws.example.com", IPs: []CleanIP{{IP: "104.16.0.1"}},
		UpdatedAt: f.deps.now().Add(-72 * time.Hour),
	}))
	rec = f.do(t, http.MethodGet, "/dns/cleanip/old", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a stale set, got %d: %s", rec.Code, rec.Body)
	}
	body = decodeBody(t, rec)
	if body["stale"] != true {
		t.Fatalf("expected the set to be flagged stale: %s", rec.Body)
	}

	rec = f.do(t, http.MethodGet, "/dns/cleanip", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRoutesProvision(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")
	f.res.IPs["ws-fra1.example.com"] = []string{"203.0.113.10"}

	rec := f.do(t, http.MethodPost, "/dns/provision", map[string]any{
		"credential": "cf1", "domain": "example.com", "ip": "203.0.113.10",
		"node": "fra1", "template": "{proto}-{node}",
		"protocols":                []map[string]any{{"proto": "ws", "port": 443, "proxied": true, "tls": true}},
		"skip_preflight":           true,
		"skip_traffic_proof":       true,
		"propagation_wait_seconds": -1,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["ok"] != true {
		t.Fatalf("expected the run to succeed: %s", rec.Body)
	}
	endpoints, _ := body["endpoints"].([]any)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	ep, _ := endpoints[0].(map[string]any)
	if ep["host"] != "ws-fra1.example.com" {
		t.Fatalf("unexpected hostname %v", ep["host"])
	}
	if len(f.cf.Records["zone1"]) != 1 {
		t.Fatalf("expected the record to be created, got %d", len(f.cf.Records["zone1"]))
	}
}

// A failed provisioning run must be 422 with the full report, not a bare error.
func TestRoutesProvisionFailureReturnsTheReport(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")
	f.cf.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	rec := f.do(t, http.MethodPost, "/dns/provision", map[string]any{
		"credential": "cf1", "domain": "example.com", "ip": "203.0.113.10", "node": "fra1",
		"protocols":                []map[string]any{{"proto": "ws", "port": 443}},
		"skip_preflight":           true,
		"skip_traffic_proof":       true,
		"propagation_wait_seconds": -1,
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["ok"] != false {
		t.Fatal("expected ok=false")
	}
	steps, _ := body["steps"].([]any)
	if len(steps) == 0 {
		t.Fatal("a failed run must still return its steps")
	}
	requireContains(t, rec.Body.String(), ScopeDNSEdit, "provision failure names the scope")
}

func TestRoutesAuditsMutations(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")
	f.do(t, http.MethodPost, "/dns/records", map[string]any{
		"credential": "cf1", "zone": "zone1",
		"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "203.0.113.10"},
	})
	found := false
	for _, a := range f.audits {
		if strings.HasPrefix(a, "dns.record.created ws.example.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the record creation to be audited, got %v", f.audits)
	}
}

// Deps without an encryptor must fail on use with the wiring instruction, not
// panic at mount time.
func TestRoutesWithoutEncryptorFailCleanly(t *testing.T) {
	r := gin.New()
	RegisterRoutes(r, Deps{Credentials: NewMemStore()})
	req := httptest.NewRequest(http.MethodGet, "/dns/credentials", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body)
	}
	requireContains(t, rec.Body.String(), "never stored in plaintext", "missing encryptor remediation")
}

// RegisterRoutes must mount under whatever group the caller passes, so the
// panel decides the prefix and the auth middleware.
func TestRegisterRoutesRespectsTheCallersGroup(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	r := gin.New()
	admin := r.Group("/api/admin")
	RegisterRoutes(admin, Deps{Credentials: NewMemStore(), Encryptor: enc})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/dns/providers", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the routes under the caller's prefix, got %d", rec.Code)
	}
}
