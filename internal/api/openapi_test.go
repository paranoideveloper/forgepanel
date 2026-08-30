package api

// The API describes itself, or it does not.
//
// docs/API.md covers about a quarter of the routes, is not embedded in the
// binary and is referenced by no test, so it drifts the moment anyone adds an
// endpoint. These tests hold the served document to the router itself: every
// route the panel actually answers is in it, it is behind the same auth as the
// rest of the admin API, and the roles it publishes are the roles the panel
// enforces.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// openapiPathT converts a gin route pattern to an OpenAPI template. Written out
// here rather than borrowed from openapi.go so the assertion does not agree with
// the implementation by construction.
func openapiPathT(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segs, "/")
}

// fetchOpenAPIDoc asks the wired panel for its own description, as an owner.
func fetchOpenAPIDoc(t *testing.T, s *Server, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/openapi.json", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/admin/openapi.json: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("document is not JSON: %v (%s)", err, w.Body.String())
	}
	return doc
}

// The document is generated from the live route table, so a route added
// tomorrow appears without anyone editing anything. If it is ever snapshotted at
// registration time, or filtered by a hand-kept list, this is what notices.
func TestOpenAPIDocumentCoversEveryRegisteredRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)

	doc := fetchOpenAPIDoc(t, s, token)
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("document has no paths object: %v", doc["paths"])
	}
	// A document that is empty for an unrelated reason must report as a broken
	// scan, not as a pass.
	if len(paths) < 20 {
		t.Fatalf("only %d paths in the document — the generator is broken, not the router", len(paths))
	}

	var missing []string
	for _, r := range s.router.Routes() {
		// Catch-alls are deliberately absent; TestOpenAPIOmitsCatchAllRoutes...
		// is the guard for those.
		if !strings.HasPrefix(r.Path, "/api/") || strings.Contains(r.Path, "/*") {
			continue
		}
		item, ok := paths[openapiPathT(r.Path)].(map[string]any)
		if !ok {
			missing = append(missing, r.Method+" "+r.Path+" (path absent)")
			continue
		}
		if _, ok := item[strings.ToLower(r.Method)]; !ok {
			missing = append(missing, r.Method+" "+r.Path+" (method absent)")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d route(s) the panel serves are absent from its own OpenAPI document:\n  - %s",
			len(missing), strings.Join(missing, "\n  - "))
	}

	// operationId must be unique, and this router genuinely collides:
	// handleSaveProfile, handleSaveOutbound and handleEdgePush are each mounted
	// on two routes. openapi-generator rejects a duplicate outright; other tools
	// silently drop one of the pair, so a client is generated without a method
	// nobody notices is gone.
	seen := map[string]string{}
	for p, raw := range paths {
		item := raw.(map[string]any)
		for method, rawOp := range item {
			id, _ := rawOp.(map[string]any)["operationId"].(string)
			if id == "" {
				t.Errorf("%s %s has no operationId", method, p)
				continue
			}
			if where, dup := seen[id]; dup {
				t.Errorf("operationId %q is used by both %s and %s %s", id, where, method, p)
			}
			seen[id] = method + " " + p
		}
	}
}

// "Behind the same auth as the API" is the half of this row the coverage test
// cannot see: mounting the document on the public /api group satisfies that test
// completely while handing the panel's whole endpoint inventory to anyone who
// can reach the port.
func TestOpenAPIIsBehindAdminAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, _ := createComprehensiveTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/openapi.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/admin/openapi.json: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	// internal/auth/middleware.go writes this refusal raw, without the apierr
	// envelope. Asserting the sentence rather than a kind keeps this test about
	// the mount point instead of quietly demanding a rewrite of every 401.
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("401 body is not JSON: %v (%s)", err, w.Body.String())
	}
	if body["error"] != "authentication required" {
		t.Fatalf("expected the auth middleware's refusal, got %v — the route is not behind the admin chain",
			w.Body.String())
	}
}

// x-forgepanel-roles has to come from the live policy table. A constant, or a
// lookup done on the converted {id} path (which misses every exact rule and
// silently falls through to the catch-all), publishes a WRONG privilege map —
// worse than publishing none.
func TestOpenAPIPublishesTheRBACItEnforces(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)

	doc := fetchOpenAPIDoc(t, s, token)
	paths, _ := doc["paths"].(map[string]any)

	// Two differently-ruled paths, so one constant everywhere cannot pass.
	for _, tc := range []string{"/api/admin/admins", "/api/admin/overview"} {
		item, ok := paths[tc].(map[string]any)
		if !ok {
			t.Fatalf("%s absent from the document", tc)
		}
		op, ok := item["get"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no get operation", tc)
		}
		raw, ok := op["x-forgepanel-roles"].([]any)
		if !ok {
			t.Fatalf("%s get has no x-forgepanel-roles: %v", tc, op)
		}
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			got = append(got, v.(string))
		}
		want := rolesForRoute(http.MethodGet, tc)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s get publishes roles %v but the panel enforces %v", tc, got, want)
		}
	}

	// Two samples cannot see a resolver asked with the wrong spelling of the
	// path, so check the whole admin surface against the live table. (Today the
	// gin and OpenAPI spellings happen to resolve alike on all 74 parameterised
	// admin routes; this is what notices the first time an exact rule sits under
	// a differently-ruled prefix and they stop agreeing.)
	for _, r := range s.router.Routes() {
		if !strings.HasPrefix(r.Path, "/api/admin") {
			continue
		}
		conv := openapiPathT(r.Path)
		item, ok := paths[conv].(map[string]any)
		if !ok {
			t.Errorf("%s %s absent from the document", r.Method, r.Path)
			continue
		}
		op, ok := item[strings.ToLower(r.Method)].(map[string]any)
		if !ok {
			t.Errorf("%s %s has no operation", r.Method, r.Path)
			continue
		}
		raw, _ := op["x-forgepanel-roles"].([]any)
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			got = append(got, v.(string))
		}
		if want := rolesForRoute(r.Method, r.Path); !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s publishes roles %v but the panel enforces %v", r.Method, r.Path, got, want)
		}
	}

	// A path with no rule at all must omit the field rather than publish null.
	if item, ok := paths["/api/protocols"].(map[string]any); ok {
		if op, ok := item["get"].(map[string]any); ok {
			if _, present := op["x-forgepanel-roles"]; present {
				t.Errorf("/api/protocols is not an admin route but publishes x-forgepanel-roles")
			}
		}
	}
}

// security must name the scheme the handler actually reads. A generated client
// that is told to send "Authorization: Bearer …" to /api/node/register sends a
// header nobody looks at and omits the token that route really wants, which is a
// worse outcome than the document saying nothing about it.
func TestOpenAPIDescribesTheBearerSchemeItActuallyReads(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)

	doc := fetchOpenAPIDoc(t, s, token)
	comps, _ := doc["components"].(map[string]any)
	schemes, _ := comps["securitySchemes"].(map[string]any)
	scheme, ok := schemes["bearerAuth"].(map[string]any)
	if !ok {
		t.Fatalf("no bearerAuth security scheme: %v", comps)
	}
	if scheme["type"] != "http" || scheme["scheme"] != "bearer" {
		t.Errorf("bearerAuth is not an HTTP bearer scheme: %v", scheme)
	}
	if _, ok := comps["schemas"].(map[string]any)["Error"]; !ok {
		t.Errorf("no shared Error schema, so no operation can reference one")
	}

	paths, _ := doc["paths"].(map[string]any)
	secOf := func(path, method string) []any {
		t.Helper()
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Fatalf("%s absent from the document", path)
		}
		op, ok := item[method].(map[string]any)
		if !ok {
			t.Fatalf("%s has no %s operation", path, method)
		}
		if _, ok := op["responses"].(map[string]any)["default"]; !ok {
			t.Errorf("%s %s has no default response, so a client has no error shape", method, path)
		}
		sec, ok := op["security"].([]any)
		if !ok {
			t.Fatalf("%s %s has no security member", method, path)
		}
		return sec
	}
	// The admin chain and the edge pull feed both read a bearer header.
	for _, tc := range [][2]string{{"/api/admin/overview", "get"}, {"/api/edge/feed", "get"}} {
		sec := secOf(tc[0], tc[1])
		if len(sec) != 1 {
			t.Errorf("%s %s: expected exactly one security requirement, got %v", tc[1], tc[0], sec)
			continue
		}
		if _, ok := sec[0].(map[string]any)["bearerAuth"]; !ok {
			t.Errorf("%s %s: expected bearerAuth, got %v", tc[1], tc[0], sec[0])
		}
	}
	// These carry no bearer at all: /api/protocols is public, and the node agent
	// puts its credential in the request body.
	for _, tc := range [][2]string{{"/api/protocols", "get"}, {"/api/node/register", "post"}} {
		if sec := secOf(tc[0], tc[1]); len(sec) != 0 {
			t.Errorf("%s %s claims a security scheme it does not read: %v", tc[1], tc[0], sec)
		}
	}
}

// A gin catch-all has no OpenAPI spelling: "{rest}" matches exactly one segment,
// so emitting it would hand every generator a path that cannot reach the route.
// Leaving it out is a gap a reader can see; converting it is a lie they cannot.
func TestOpenAPIOmitsCatchAllRoutesRatherThanInventingAPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)
	s.router.GET("/api/openapitest/*rest", func(c *gin.Context) { c.Status(http.StatusOK) })

	paths, _ := fetchOpenAPIDoc(t, s, token)["paths"].(map[string]any)
	for p := range paths {
		if strings.Contains(p, "*") {
			t.Errorf("document contains a gin catch-all pattern as a path: %q", p)
		}
	}
	if _, ok := paths["/api/openapitest/{rest}"]; ok {
		t.Errorf("a catch-all was published as a single-segment path, which cannot reach the route")
	}
}
