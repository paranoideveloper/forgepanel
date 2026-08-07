package dns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

type routeFixture struct {
	router *gin.Engine
	deps   Deps
	store  *MemStore
	cf     *cfMock
	res    *fakeResolver
	audits []string
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	key, err := GenerateKey()
	requireNoError(t, err)
	enc, err := NewAESGCM(key)
	requireNoError(t, err)

	store := NewMemStore()
	cf := newCFMock(t)
	cf.addZone("zone1", "example.com", "active", "amy.ns.cloudflare.com")
	res := newFakeResolver()
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}

	f := &routeFixture{store: store, cf: cf, res: res}
	// Point the readiness checker at local servers so no test touches the real
	// ACME directory or certificate-transparency log.
	pf := newPreflight(t, res, time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), nil)
	f.deps = Deps{
		Credentials: store, Encryptor: enc, Pools: store, CleanIPs: store,
		Resolver: res, Preflight: &pf,
		Now: fixedNow(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)),
		Audit: func(_ *gin.Context, action, target, result string) {
			f.audits = append(f.audits, action+" "+target+" "+result)
		},
	}
	f.router = gin.New()
	RegisterRoutes(f.router, f.deps)
	return f
}

// storeCredential registers a credential pointed at the mock Cloudflare.
func (f *routeFixture) storeCredential(t *testing.T, id string) {
	t.Helper()
	cs, err := NewCredentialStore(f.deps.Credentials, f.deps.Encryptor)
	requireNoError(t, err)
	_, err = cs.Put(id, "cloudflare", "test", Credentials{
		"api_token": "test-token", "base_url": f.cf.server.URL + "/client/v4",
	})
	requireNoError(t, err)
}

func (f *routeFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		requireNoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("could not decode response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestRoutesListProviders(t *testing.T) {
	f := newRouteFixture(t)
	rec := f.do(t, http.MethodGet, "/dns/providers", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	providers, _ := body["providers"].([]any)
	if len(providers) != 9 {
		t.Fatalf("expected 9 providers, got %d", len(providers))
	}
	impl, _ := body["implemented"].([]any)
	if len(impl) != 3 {
		t.Fatalf("expected 3 implemented providers, got %v", impl)
	}
}

func TestRoutesCredentialLifecycle(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.do(t, http.MethodPost, "/dns/credentials", map[string]any{
		"id": "cf1", "provider": "cloudflare", "label": "main",
		"data": map[string]string{"api_token": "test-token", "base_url": f.cf.server.URL + "/client/v4"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body)
	}
	// The response must never echo the secret back.
	if strings.Contains(rec.Body.String(), "test-token") {
		t.Fatalf("the credential response leaked the token: %s", rec.Body)
	}

	rec = f.do(t, http.MethodGet, "/dns/credentials", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "test-token") {
		t.Fatalf("the credential listing leaked the token: %s", rec.Body)
	}

	rec = f.do(t, http.MethodPost, "/dns/credentials/cf1/verify", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected verification to pass, got %d: %s", rec.Code, rec.Body)
	}

	rec = f.do(t, http.MethodDelete, "/dns/credentials/cf1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	rec = f.do(t, http.MethodPost, "/dns/credentials/cf1/verify", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after deletion, got %d", rec.Code)
	}
}

// A bad token supplied with verify:true must be rejected at registration rather
// than stored and discovered later.
func TestRoutesCredentialVerifyOnCreate(t *testing.T) {
	f := newRouteFixture(t)
	rec := f.do(t, http.MethodPost, "/dns/credentials", map[string]any{
		"id": "bad", "provider": "cloudflare", "verify": true,
		"data": map[string]string{"api_token": "wrong", "base_url": f.cf.server.URL + "/client/v4"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["kind"] != string(KindAuth) {
		t.Fatalf("expected an auth kind, got %v", body["kind"])
	}
	if body["remediation"] == "" {
		t.Fatal("the error body must carry remediation")
	}
	list, err := f.store.ListCredentials()
	requireNoError(t, err)
	if len(list) != 0 {
		t.Fatal("a rejected credential must not be stored")
	}
}

// Every error kind must map onto the right HTTP status, since that is the
// contract the frontend reacts to.
func TestRoutesErrorStatusMapping(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")

	cases := []struct {
		name   string
		setup  func()
		method string
		path   string
		body   any
		want   int
		kind   Kind
	}{
		{
			name:   "validation",
			method: http.MethodPost, path: "/dns/records",
			body: map[string]any{"credential": "cf1", "zone": "zone1",
				"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "not-an-ip"}},
			want: http.StatusBadRequest, kind: KindValidation,
		},
		{
			name: "permission",
			setup: func() {
				f.cf.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}
			},
			method: http.MethodPost, path: "/dns/records",
			body: map[string]any{"credential": "cf1", "zone": "zone1",
				"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "203.0.113.10"}},
			want: http.StatusForbidden, kind: KindPermission,
		},
		{
			name:   "not found",
			method: http.MethodPost, path: "/dns/zones/resolve",
			body: map[string]any{"credential": "cf1", "domain": "nope.test"},
			want: http.StatusNotFound, kind: KindNotFound,
		},
		{
			name:   "missing credential",
			method: http.MethodGet, path: "/dns/zones",
			want: http.StatusBadRequest, kind: KindValidation,
		},
		{
			name:   "unknown credential",
			method: http.MethodGet, path: "/dns/zones?credential=nope",
			want: http.StatusNotFound, kind: KindNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
				t.Cleanup(func() { f.cf.Deny = map[string]cfMessage{} })
			}
			rec := f.do(t, tc.method, tc.path, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d: %s", tc.want, rec.Code, rec.Body)
			}
			body := decodeBody(t, rec)
			if body["kind"] != string(tc.kind) {
				t.Fatalf("expected kind %q, got %v", tc.kind, body["kind"])
			}
			if rem, _ := body["remediation"].(string); rem == "" {
				t.Fatalf("every error must carry remediation, got %s", rec.Body)
			}
		})
	}
}

// A permission failure must reach the client with the exact scope named.
func TestRoutesSurfaceTheMissingScope(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")
	f.cf.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	rec := f.do(t, http.MethodPost, "/dns/records", map[string]any{
		"credential": "cf1", "zone": "zone1",
		"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "203.0.113.10"},
	})
	body := decodeBody(t, rec)
	if body["missing_scope"] != ScopeDNSEdit {
		t.Fatalf("expected the missing scope in the body, got %v", body["missing_scope"])
	}
}

func TestRoutesZonesAndRecords(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")

	rec := f.do(t, http.MethodGet, "/dns/zones?credential=cf1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}

	rec = f.do(t, http.MethodPost, "/dns/zones/resolve", map[string]any{
		"credential": "cf1", "domain": "ws.team.example.com",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	zone, _ := body["zone"].(map[string]any)
	if zone["name"] != "example.com" {
		t.Fatalf("expected the parent zone, got %v", zone["name"])
	}
	if body["subname"] != "ws.team" {
		t.Fatalf("expected the relative subname, got %v", body["subname"])
	}

	rec = f.do(t, http.MethodPost, "/dns/records", map[string]any{
		"credential": "cf1", "zone": "zone1",
		"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "203.0.113.10", "proxied": true},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	body = decodeBody(t, rec)
	if body["action"] != "created" {
		t.Fatalf("expected a creation, got %v", body["action"])
	}

	// Second call is idempotent.
	rec = f.do(t, http.MethodPost, "/dns/records", map[string]any{
		"credential": "cf1", "zone": "zone1",
		"record": map[string]any{"type": "A", "name": "ws.example.com", "content": "203.0.113.10", "proxied": true},
	})
	body = decodeBody(t, rec)
	if body["action"] != "unchanged" {
		t.Fatalf("expected an idempotent no-op, got %v", body["action"])
	}

	rec = f.do(t, http.MethodGet, "/dns/records?credential=cf1&zone=zone1&type=A", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rec = f.do(t, http.MethodDelete, "/dns/records?credential=cf1&zone=zone1&name=ws.example.com&type=A", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	if decodeBody(t, rec)["deleted"].(float64) != 1 {
		t.Fatalf("expected one deletion, got %s", rec.Body)
	}
}

func TestRoutesBulkRecords(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")

	rec := f.do(t, http.MethodPost, "/dns/records/bulk", map[string]any{
		"credential": "cf1", "zone": "zone1", "domain": "example.com",
		"template": "{proto}-{rand:5}", "type": "A", "content": "203.0.113.10",
		"count": 5, "proxied": true, "proto": "ws",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	results, _ := decodeBody(t, rec)["results"].([]any)
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	if len(f.cf.Records["zone1"]) != 5 {
		t.Fatalf("expected 5 records at the provider, got %d", len(f.cf.Records["zone1"]))
	}
}

// A partially-completed bulk run must return what landed alongside the error,
// not discard it.
func TestRoutesBulkPartialFailureReturns207(t *testing.T) {
	f := newRouteFixture(t)
	f.storeCredential(t, "cf1")
	f.cf.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	rec := f.do(t, http.MethodPost, "/dns/records/bulk", map[string]any{
		"credential": "cf1", "zone": "zone1", "domain": "example.com",
		"type": "A", "content": "203.0.113.10", "count": 5, "proto": "ws",
	})
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("expected 207, got %d: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["remediation"] == "" {
		t.Fatal("the partial-failure body must carry remediation")
	}
	if results, _ := body["results"].([]any); len(results) == 0 {
		t.Fatal("the partial-failure body must report what was attempted")
	}
}
