package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// --- deploy -----------------------------------------------------------------

func TestDeploy_HappyPath(t *testing.T) {
	m := newCFMock(t)
	c := m.client()

	res, err := Deploy(ctx(t), c, DeploySpec{
		Name: "forgeedge-a1b2c3", SecurePath: "qrs7tuvwxy23456789abcdef",
		Bundle: []byte("export default {}"), SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.Origin != "https://forgeedge-a1b2c3.acme.workers.dev" {
		t.Errorf("origin = %q", res.Origin)
	}
	if res.PanelURL != res.Origin+"/qrs7tuvwxy23456789abcdef/panel" {
		t.Errorf("panel URL = %q", res.PanelURL)
	}
	if !strings.HasSuffix(res.SubTemplate, "/sub/<sub_token>") {
		t.Errorf("subscription template = %q", res.SubTemplate)
	}
	if res.KVNamespaceID == "" {
		t.Error("no KV namespace was created")
	}

	up := m.snapshot().LastUpload
	if up == nil {
		t.Fatal("nothing was uploaded")
	}
	// keep_bindings is not optional: without it an update detaches KV and every
	// subscriber's config disappears on the Worker's next request.
	if len(up.KeepBindings) != 2 || up.KeepBindings[0] != "kv_namespace" || up.KeepBindings[1] != "d1" {
		t.Fatalf("keep_bindings = %v, want [kv_namespace d1]", up.KeepBindings)
	}
	if up.MainModule != "worker.js" {
		t.Errorf("main_module = %q", up.MainModule)
	}
	if len(up.CompatibilityFlags) == 0 || up.CompatibilityFlags[0] != "nodejs_compat" {
		t.Errorf("compatibility_flags = %v", up.CompatibilityFlags)
	}
	if _, err := time.Parse("2006-01-02", up.CompatibilityDate); err != nil {
		t.Errorf("compatibility_date = %q", up.CompatibilityDate)
	}
	// SECURE_PATH must be passed in as plain text so forgectl knows every URL up
	// front instead of scraping it from a Worker log line.
	var sawPath, sawKV bool
	for _, b := range up.Bindings {
		switch b.Type {
		case "plain_text":
			if b.Name == "SECURE_PATH" && b.Text == "qrs7tuvwxy23456789abcdef" {
				sawPath = true
			}
		case "kv_namespace":
			sawKV = b.Name == "KV" && b.NamespaceID == res.KVNamespaceID
		}
	}
	if !sawPath {
		t.Errorf("no SECURE_PATH plain_text binding in %+v", up.Bindings)
	}
	if !sawKV {
		t.Errorf("no KV binding in %+v", up.Bindings)
	}
	if !m.snapshot().SubEnabled["forgeedge-a1b2c3"] {
		t.Error("the workers.dev subdomain was never enabled, so the Worker is unreachable")
	}
}

// TestDeploy_SelfManageBindsCloudflareCredential covers the one append every
// other path in this feature flows through.
//
// The Worker's own Deployment panel reads env.CF_API_TOKEN + env.CF_ACCOUNT_ID
// and reports "no Cloudflare credential bound" without them. Nothing has ever
// sent them, so that branch has been permanently starved.
func TestDeploy_SelfManageBindsCloudflareCredential(t *testing.T) {
	deploy := func(t *testing.T, selfManage bool) *uploadMetadata {
		t.Helper()
		m := newCFMock(t)
		if _, err := Deploy(ctx(t), m.client(), DeploySpec{
			Name: "w", SecurePath: "qrs7tuvwxy23456789abcdef",
			Bundle: []byte("export default {}"), SelfManage: selfManage, SkipVerify: true,
		}); err != nil {
			t.Fatalf("Deploy: %v", err)
		}
		up := m.snapshot().LastUpload
		if up == nil {
			t.Fatal("nothing was uploaded")
		}
		return up
	}

	t.Run("binds both when asked", func(t *testing.T) {
		up := deploy(t, true)
		var sawToken, sawAccount bool
		for _, b := range up.Bindings {
			// secret_text, not plain_text: same shape on the wire, but
			// Cloudflare redacts it from the dashboard and the API. This is the
			// one binding whose value is a credential.
			if b.Name == "CF_API_TOKEN" && b.Type == "secret_text" && b.Text == "test-token" {
				sawToken = true
			}
			if b.Name == "CF_ACCOUNT_ID" && b.Type == "plain_text" && b.Text == "acct-1" {
				sawAccount = true
			}
		}
		if !sawToken {
			t.Errorf("no CF_API_TOKEN secret_text binding in %+v", up.Bindings)
		}
		// Both or neither: the Worker hands back no credentials unless it has
		// both, so binding one alone looks exactly like binding nothing.
		if !sawAccount {
			t.Errorf("no CF_ACCOUNT_ID plain_text binding in %+v", up.Bindings)
		}
	})

	t.Run("never by default", func(t *testing.T) {
		up := deploy(t, false)
		for _, b := range up.Bindings {
			if b.Name == "CF_API_TOKEN" || b.Name == "CF_ACCOUNT_ID" {
				t.Errorf("a plain deploy wrote a credential into the Worker: %+v", b)
			}
		}
	})
}

func TestDeploy_RefusesToClobber(t *testing.T) {
	m := newCFMock(t)
	m.Scripts["taken"] = ScriptInfo{ID: "taken"}
	c := m.client()

	_, err := Deploy(ctx(t), c, DeploySpec{Name: "taken", Bundle: []byte("x"), SkipVerify: true})
	if err == nil {
		t.Fatal("silently overwriting an existing Worker is not acceptable")
	}
	if !IsConflict(err) {
		t.Fatalf("want a conflict, got %#v", err)
	}

	// --force is the deliberate override.
	if _, err := Deploy(ctx(t), c, DeploySpec{Name: "taken", Bundle: []byte("x"), Force: true, SkipVerify: true}); err != nil {
		t.Fatalf("--force should overwrite: %v", err)
	}
}

func TestDeploy_UpdateReusesKVAndKeepsBindings(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	first, err := Deploy(ctx(t), c, DeploySpec{Name: "w", SecurePath: "path23456789abcdefghijkl", Bundle: []byte("v1"), SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Deploy(ctx(t), c, DeploySpec{Name: "w", SecurePath: "path23456789abcdefghijkl", SkipVerify: true,
		Bundle: []byte("v2"), Update: true})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if second.KVNamespaceID != first.KVNamespaceID {
		t.Fatalf("an update created a new KV namespace (%s → %s); every subscriber's config would vanish",
			first.KVNamespaceID, second.KVNamespaceID)
	}
	if !second.Updated {
		t.Error("the result should be marked as an update")
	}
	if m.snapshot().LastScript != "v2" {
		t.Errorf("the new bundle was not uploaded: %q", m.snapshot().LastScript)
	}
	if len(m.snapshot().KV) != 1 {
		t.Errorf("expected exactly one KV namespace, got %d", len(m.snapshot().KV))
	}
}

func TestDeploy_GeneratesSecurePathWhenAbsent(t *testing.T) {
	m := newCFMock(t)
	res, err := Deploy(ctx(t), m.client(), DeploySpec{Name: "w", Bundle: []byte("x"), SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecurePath) != SecurePathLength {
		t.Fatalf("secure path %q has length %d, want %d", res.SecurePath, len(res.SecurePath), SecurePathLength)
	}
}

func TestDeploy_ClaimsSubdomainWhenAccountHasNone(t *testing.T) {
	m := newCFMock(t)
	m.Subdomain = ""
	res, err := Deploy(ctx(t), m.client(), DeploySpec{Name: "w", Bundle: []byte("x"), SkipVerify: true})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if m.snapshot().Subdomain == "" {
		t.Fatal("the account subdomain was never claimed, so workers.dev would 404")
	}
	if !strings.Contains(res.Origin, m.snapshot().Subdomain) {
		t.Errorf("origin %q does not use the claimed subdomain %q", res.Origin, m.snapshot().Subdomain)
	}
}

func TestDeploy_AttachesCustomDomain(t *testing.T) {
	m := newCFMock(t)
	m.Zones = append(m.Zones, struct{ ID, Name string }{"zone-1", "example.com"})
	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), Domain: "edge.example.com", SecurePath: "p23456789abcdefghijklmno",
		SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.Origin != "https://edge.example.com" {
		t.Errorf("a custom domain must become the origin, got %q", res.Origin)
	}
	if got := m.snapshot().Domains["w"]; len(got) != 1 || got[0] != "edge.example.com" {
		t.Errorf("hostname not attached: %v", got)
	}
}

func TestDeploy_UnknownDomainZone(t *testing.T) {
	m := newCFMock(t)
	_, err := Deploy(ctx(t), m.client(), DeploySpec{Name: "w", Bundle: []byte("x"), Domain: "edge.nowhere.test"})
	if !IsNotFound(err) {
		t.Fatalf("want a not-found for a zone this account cannot see, got %v", err)
	}
}

func TestDeploy_Rejections(t *testing.T) {
	m := newCFMock(t)
	t.Run("empty bundle", func(t *testing.T) {
		_, err := Deploy(ctx(t), m.client(), DeploySpec{Name: "w"})
		e, ok := AsError(err)
		if !ok || e.Kind != KindValidation || !strings.Contains(e.Remediation, "bun run build") {
			t.Fatalf("want a validation error naming the build step, got %v", err)
		}
	})
	t.Run("pages is not implemented", func(t *testing.T) {
		_, err := Deploy(ctx(t), m.client(), DeploySpec{Name: "w", Target: "pages", Bundle: []byte("x")})
		if e, ok := AsError(err); !ok || e.Kind != KindValidation {
			t.Fatalf("an unimplemented target must say so, got %v", err)
		}
	})
	t.Run("no account id", func(t *testing.T) {
		c := m.client()
		c.AccountID = ""
		_, err := Deploy(ctx(t), c, DeploySpec{Name: "w", Bundle: []byte("x"), SkipVerify: true})
		if e, ok := AsError(err); !ok || e.Kind != KindValidation {
			t.Fatalf("want a validation error for a missing account, got %v", err)
		}
	})
}

// --- destroy ----------------------------------------------------------------

func TestDestroy(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	if _, err := Deploy(ctx(t), c, DeploySpec{Name: "doomed", Bundle: []byte("x"), SkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	if err := Destroy(ctx(t), c, "doomed", "workers", false); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, ok := m.snapshot().Scripts["doomed"]; ok {
		t.Error("the Worker survived the delete")
	}
	if len(m.snapshot().KV) != 0 {
		t.Error("the KV namespace survived a delete without --keep-kv")
	}
}

func TestDestroy_KeepKV(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	if _, err := Deploy(ctx(t), c, DeploySpec{Name: "w", Bundle: []byte("x"), SkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	if err := Destroy(ctx(t), c, "w", "workers", true); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if len(m.snapshot().KV) != 1 {
		t.Error("--keep-kv must leave the namespace (and every subscriber's config) alone")
	}
}

func TestDestroy_MissingWorker(t *testing.T) {
	m := newCFMock(t)
	err := Destroy(ctx(t), m.client(), "never-existed", "workers", false)
	if !IsNotFound(err) {
		t.Fatalf("want a not-found, got %v", err)
	}
}

func TestDestroy_MissingKVIsNotAFailure(t *testing.T) {
	m := newCFMock(t)
	m.Scripts["w"] = ScriptInfo{ID: "w"} // a Worker with no namespace of its own
	if err := Destroy(ctx(t), m.client(), "w", "workers", false); err != nil {
		t.Fatalf("a namespace that is already gone is not a failed delete: %v", err)
	}
}

// --- client errors ----------------------------------------------------------

func TestClient_ErrorClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		msg    apiMessage
		want   Kind
	}{
		{"auth", http.StatusUnauthorized, apiMessage{Code: 10000, Message: "Authentication error"}, KindAuth},
		{"permission", http.StatusForbidden, apiMessage{Code: 9109, Message: "Unauthorized to access requested resource"}, KindPermission},
		{"not found", http.StatusNotFound, apiMessage{Code: 7003, Message: "Could not route to /x"}, KindNotFound},
		{"conflict", http.StatusConflict, apiMessage{Code: 1, Message: "already exists"}, KindConflict},
		{"validation", http.StatusBadRequest, apiMessage{Code: 1004, Message: "bad"}, KindValidation},
		{"rate limit", http.StatusTooManyRequests, apiMessage{Code: 971, Message: "slow down"}, KindRateLimit},
		{"server", http.StatusInternalServerError, apiMessage{Code: 500, Message: "boom"}, KindServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newCFMock(t)
			m.Deny["GET /accounts"] = tc.msg
			m.DenyStatus["GET /accounts"] = tc.status
			_, err := m.client().ListAccounts(ctx(t))
			e, ok := AsError(err)
			if !ok {
				t.Fatalf("want a typed error, got %v", err)
			}
			if e.Kind != tc.want {
				t.Fatalf("kind = %q, want %q (message %q)", e.Kind, tc.want, e.Message)
			}
			if e.Remediation == "" {
				t.Error("every failure must carry a remediation an operator can act on")
			}
			if tc.want == KindPermission && e.MissingScope == "" {
				t.Error("a permission failure must name the missing scope")
			}
		})
	}
}

func TestClient_BadToken(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	c.Token = "wrong"
	_, err := c.ListAccounts(ctx(t))
	if e, ok := AsError(err); !ok || e.Kind != KindAuth {
		t.Fatalf("want an auth failure, got %v", err)
	}
}

func TestClient_NonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>a proxy ate this</html>"))
	}))
	defer srv.Close()
	c := &Client{Token: "t", AccountID: "a", BaseURL: srv.URL, HTTP: srv.Client(),
		MaxRetries: 1, Sleep: func(time.Duration) {}}
	_, err := c.ListAccounts(ctx(t))
	e, ok := AsError(err)
	if !ok || e.Kind != KindServer || !strings.Contains(e.Message, "non-JSON") {
		t.Fatalf("want a clear non-JSON diagnosis, got %v", err)
	}
}

func TestClient_NetworkFailure(t *testing.T) {
	c := &Client{Token: "t", AccountID: "a", BaseURL: "http://127.0.0.1:1", MaxRetries: 0,
		Sleep: func(time.Duration) {}, HTTP: &http.Client{Timeout: time.Second}}
	_, err := c.ListAccounts(ctx(t))
	if e, ok := AsError(err); !ok || e.Kind != KindNetwork {
		t.Fatalf("want a network error, got %v", err)
	}
}

func TestClient_RetriesOn5xxThenSucceeds(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":500,"message":"boom"}],"result":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"acct-1","name":"Acme"}]}`))
	}))
	defer srv.Close()
	c := &Client{Token: "t", BaseURL: srv.URL, HTTP: srv.Client(), MaxRetries: 2, Sleep: func(time.Duration) {}}
	accts, err := c.ListAccounts(ctx(t))
	if err != nil {
		t.Fatalf("a transient 5xx should be retried: %v", err)
	}
	if len(accts) != 1 || calls != 2 {
		t.Fatalf("accounts=%v calls=%d", accts, calls)
	}
}

func TestErrorHelpers(t *testing.T) {
	e := &Error{Op: "x", Kind: KindNotFound, Message: "gone"}
	if e.Error() != "x: gone" {
		t.Errorf("Error() = %q", e.Error())
	}
	bare := &Error{Kind: KindServer, Message: "gone"}
	if bare.Error() != "gone" {
		t.Errorf("Error() without op = %q", bare.Error())
	}
	if _, ok := AsError(errUpload("plain")); ok {
		t.Error("AsError must not claim an unrelated error")
	}
	if IsNotFound(nil) || IsConflict(nil) {
		t.Error("nil is neither")
	}
	nc := ErrNoCredentials("edge-deploy")
	if nc.Kind != KindNoCredentials || !strings.Contains(nc.Remediation, "forgectl edge deploy") {
		t.Errorf("ErrNoCredentials = %+v", nc)
	}
}

func TestTokenURL(t *testing.T) {
	u := TokenURL()
	for _, want := range []string{"permissionGroupKeys", "worker.write", "storage.kv.write", "ForgePanel-Edge"} {
		if !strings.Contains(u, want) && !strings.Contains(strings.ReplaceAll(u, "%2E", "."), want) {
			t.Errorf("token URL is missing %q: %s", want, u)
		}
	}
}

func TestKVHelpers(t *testing.T) {
	if KVTitle("forgeedge-a1") != "forgeedge-a1-forgeedge" {
		t.Errorf("KVTitle = %q", KVTitle("forgeedge-a1"))
	}
	m := newCFMock(t)
	if _, err := m.client().FindKVNamespace(ctx(t), "nope"); !IsNotFound(err) {
		t.Fatalf("want not-found for a missing namespace, got %v", err)
	}
}

func TestD1Lifecycle(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	res, err := Deploy(ctx(t), c, DeploySpec{Name: "w", Bundle: []byte("x"), D1: true, SkipVerify: true})
	if err != nil {
		t.Fatalf("Deploy with D1: %v", err)
	}
	if res.D1DatabaseID == "" {
		t.Fatal("no D1 database was created")
	}
	var sawD1 bool
	for _, b := range m.snapshot().LastUpload.Bindings {
		if b.Type == "d1" && b.ID == res.D1DatabaseID {
			sawD1 = true
		}
	}
	if !sawD1 {
		t.Errorf("no d1 binding in %+v", m.snapshot().LastUpload.Bindings)
	}
	if err := c.DeleteD1(ctx(t), res.D1DatabaseID); err != nil {
		t.Fatalf("DeleteD1: %v", err)
	}
}

func TestWorkerDomainsAndPages(t *testing.T) {
	m := newCFMock(t)
	m.Zones = append(m.Zones, struct{ ID, Name string }{"z", "example.com"})
	c := m.client()
	if err := c.AttachDomain(ctx(t), "w", "a.example.com", "z"); err != nil {
		t.Fatal(err)
	}
	hosts, err := c.WorkerDomains(ctx(t), "w")
	if err != nil || len(hosts) != 1 || hosts[0] != "a.example.com" {
		t.Fatalf("WorkerDomains = %v (%v)", hosts, err)
	}
	if err := c.DeletePagesProject(ctx(t), "proj"); err != nil {
		t.Fatalf("DeletePagesProject: %v", err)
	}
}

func TestFindZone_PrefersTheLongestMatch(t *testing.T) {
	m := newCFMock(t)
	m.Zones = append(m.Zones,
		struct{ ID, Name string }{"parent", "example.com"},
		struct{ ID, Name string }{"child", "edge.example.com"},
	)
	id, name, err := m.client().FindZone(ctx(t), "a.edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != "child" || name != "edge.example.com" {
		t.Fatalf("FindZone = %q/%q, want the most specific zone", id, name)
	}
}

func TestScriptExists(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	ok, err := c.ScriptExists(ctx(t), "nope")
	if err != nil || ok {
		t.Fatalf("ScriptExists(missing) = %v, %v", ok, err)
	}
	m.Scripts["yes"] = ScriptInfo{ID: "yes"}
	ok, err = c.ScriptExists(ctx(t), "yes")
	if err != nil || !ok {
		t.Fatalf("ScriptExists(present) = %v, %v", ok, err)
	}
	m.Deny["GET /accounts/acct-1/workers/scripts"] = apiMessage{Code: 9109, Message: "Unauthorized to access requested resource"}
	if _, err := c.ScriptExists(ctx(t), "yes"); err == nil {
		t.Fatal("a permission failure must not be reported as 'does not exist'")
	}
}

// --- secure path / names ----------------------------------------------------

func TestGenerateSecurePath(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := GenerateSecurePath(0)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != SecurePathLength {
			t.Fatalf("length %d", len(p))
		}
		// The Worker validates SECURE_PATH against ^[a-z0-9-]{8,64}$ and its own
		// alphabet excludes l and o so a path can be read aloud.
		for _, r := range p {
			if !strings.ContainsRune(SecurePathAlphabet, r) {
				t.Fatalf("character %q is outside the Worker's alphabet", r)
			}
		}
		if strings.ContainsAny(p, "lo") {
			t.Fatalf("path %q contains an ambiguous character", p)
		}
		seen[p] = true
	}
	if len(seen) < 50 {
		t.Fatalf("only %d unique paths out of 50; the generator is not random", len(seen))
	}
	if p, _ := GenerateSecurePath(8); len(p) != 8 {
		t.Error("an explicit length must be honoured")
	}
}

func TestRandomName(t *testing.T) {
	n, err := RandomName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n, "forgeedge-") || len(n) != len("forgeedge-")+6 {
		t.Fatalf("RandomName = %q", n)
	}
}

// --- update check -----------------------------------------------------------

func TestCheckForUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("the GitHub API rejects a request with no User-Agent")
		}
		switch r.URL.Path {
		case "/repos/forgepanel/forgepanel/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v0.3.0","html_url":"https://example.invalid/r"}`))
		case "/repos/none/none/releases/latest":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := GitHubAPIBase
	GitHubAPIBase = srv.URL
	defer func() { GitHubAPIBase = old }()

	info, err := CheckForUpdate(ctx(t), srv.Client(), "", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if info.Latest != "0.3.0" || !info.UpdateAvailable || info.ReleaseURL == "" {
		t.Fatalf("update info = %+v", info)
	}
	if _, err := time.Parse(time.RFC3339, info.CheckedAt); err != nil {
		t.Errorf("checked_at = %q", info.CheckedAt)
	}

	same, err := CheckForUpdate(ctx(t), srv.Client(), "", "0.3.0")
	if err != nil || same.UpdateAvailable {
		t.Fatalf("running the latest release must not report an update: %+v (%v)", same, err)
	}

	if _, err := CheckForUpdate(ctx(t), srv.Client(), "none/none", "0.1.0"); err == nil {
		t.Fatal("a 404 from GitHub must be reported, not silently treated as up to date")
	}
}

// --- worker client ----------------------------------------------------------

// mockWorker replays a deployed ForgeEdge Worker.
type mockWorker struct {
	path      string
	password  string
	pushToken string
	loggedIn  bool
	feed      []byte
	rotated   string
	config    []byte
	srv       *httptest.Server
}

// machineAuthed reports whether the request carries the push token as a bearer,
// which the real Worker accepts on every panel route (handler.ts).
func (m *mockWorker) machineAuthed(r *http.Request) bool {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == m.pushToken
}

func newMockWorker(t *testing.T) *mockWorker {
	t.Helper()
	m := &mockWorker{path: "workerpath23456789abcdef", password: "hunter2hunter2", pushToken: "push-tok"}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockWorker) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	route := strings.TrimPrefix(r.URL.Path, "/"+m.path)
	switch route {
	case "/api/login":
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password != m.password {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Wrong password.","body":null}`))
			return
		}
		m.loggedIn = true
		w.Header().Set("Set-Cookie", "fe_session=abc; HttpOnly; Path=/; SameSite=Strict")
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Signed in.","body":{"firstRun":false}}`))
	case "/api/status":
		if !m.loggedIn || r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":null,"body":{"version":"0.1.0","users":14,"feedPushToken":"push-tok","backendMode":"off","cleanIPs":{"count":37,"updatedAt":"2026-08-07T06:17:00Z"}}}`))
	case "/api/rotate-path":
		if !m.loggedIn {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		m.rotated = "freshpath23456789abcdefg"
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Rotated.","body":{"securePath":"freshpath23456789abcdefg"}}`))
	case "/api/config":
		if !m.machineAuthed(r) && !m.loggedIn {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			// Reject a config whose customCdnSni is obviously bad, so the test can
			// prove a validation error is relayed verbatim.
			if bytes.Contains(body, []byte(`"customCdnSni":"bad sni"`)) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"success":false,"status":400,"message":"customCdnSni is not a hostname","body":null}`))
				return
			}
			m.config = body
			_, _ = w.Write(append(append([]byte(`{"success":true,"status":200,"message":"Saved.","body":`), body...), '}'))
			return
		}
		if m.config == nil {
			m.config = []byte(`{"version":1,"cleanIPs":["1.2.3.4"],"customCdnSni":"","ports":[443]}`)
		}
		_, _ = w.Write(append(append([]byte(`{"success":true,"status":200,"message":null,"body":`), m.config...), '}'))
	case "/api/clean-ip/refresh":
		if !m.machineAuthed(r) && !m.loggedIn {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":null,"body":{"entries":["1.2.3.4","104.16.0.1"],"updatedAt":"2026-08-09T00:00:00Z"}}`))
	case "/feed":
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != m.pushToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Invalid feed push token.","body":null}`))
			return
		}
		m.feed, _ = readAll(r)
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Feed accepted.","body":{"users":2,"sharedNodes":1,"warnings":["dropped user 9: no sub_token"]}}`))
	default:
		// The decoy: anything off the secure path is HTML, not JSON.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>nothing here</html>"))
	}
}

func readAll(r *http.Request) ([]byte, error) {
	buf := make([]byte, r.ContentLength)
	_, err := r.Body.Read(buf)
	return buf, err
}

func TestWorkerClient_StatusAndRotate(t *testing.T) {
	m := newMockWorker(t)
	wc := NewWorkerClient(m.srv.URL+"/", "/"+m.path+"/")
	wc.HTTP = m.srv.Client()

	// No password: the Worker's own 401 comes back, not a fabricated success.
	if _, err := wc.Status(ctx(t), ""); err == nil {
		t.Fatal("an unauthenticated status must fail")
	} else if e, ok := AsError(err); !ok || e.Kind != KindAuth {
		t.Fatalf("want an auth failure, got %v", err)
	}

	st, err := wc.Status(ctx(t), m.password)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Version != "0.1.0" || st.Users != 14 || st.FeedPushToken != "push-tok" || st.CleanIPs.Count != 37 {
		t.Fatalf("status = %+v", st)
	}

	fresh, err := wc.RotatePath(ctx(t), m.password)
	if err != nil {
		t.Fatalf("RotatePath: %v", err)
	}
	if fresh != "freshpath23456789abcdefg" {
		t.Fatalf("rotated path = %q", fresh)
	}
}

func TestWorkerClient_ConfigEditor(t *testing.T) {
	m := newMockWorker(t)
	wc := NewWorkerClient(m.srv.URL, m.path)
	wc.HTTP = m.srv.Client()
	wc.Bearer = m.pushToken // machine credential — no admin password needed

	// Read-modify-write: pull the live config, add a clean IP, write it back.
	cfg, err := wc.GetConfigRaw(ctx(t))
	if err != nil {
		t.Fatalf("GetConfigRaw: %v", err)
	}
	ips, _ := cfg["cleanIPs"].([]any)
	if len(ips) != 1 {
		t.Fatalf("seed cleanIPs = %v", cfg["cleanIPs"])
	}
	cfg["cleanIPs"] = append(ips, "5.6.7.8")
	saved, err := wc.PutConfigRaw(ctx(t), cfg)
	if err != nil {
		t.Fatalf("PutConfigRaw: %v", err)
	}
	if got, _ := saved["cleanIPs"].([]any); len(got) != 2 {
		t.Fatalf("saved cleanIPs = %v", saved["cleanIPs"])
	}

	// A validation failure is relayed as a KindValidation error with the
	// Worker's own message, never swallowed.
	cfg["customCdnSni"] = "bad sni"
	if _, err := wc.PutConfigRaw(ctx(t), cfg); err == nil {
		t.Fatal("expected the Worker's validation error")
	} else if e, ok := AsError(err); !ok || e.Kind != KindValidation {
		t.Fatalf("want a validation error, got %v", err)
	} else if !strings.Contains(e.Message, "customCdnSni") {
		t.Fatalf("message not relayed: %q", e.Message)
	}

	// Machine bearer also drives a clean-IP refresh.
	store, err := wc.RefreshCleanIPs(ctx(t))
	if err != nil {
		t.Fatalf("RefreshCleanIPs: %v", err)
	}
	if len(store.Entries) != 2 {
		t.Fatalf("refresh entries = %v", store.Entries)
	}
}

func TestWorkerClient_WrongPassword(t *testing.T) {
	m := newMockWorker(t)
	wc := NewWorkerClient(m.srv.URL, m.path)
	wc.HTTP = m.srv.Client()
	if err := wc.Login(ctx(t), "not-the-password"); err == nil {
		t.Fatal("a wrong password must be rejected")
	}
}

func TestWorkerClient_WrongSecurePathHitsTheDecoy(t *testing.T) {
	m := newMockWorker(t)
	wc := NewWorkerClient(m.srv.URL, "totally-wrong-path-here")
	wc.HTTP = m.srv.Client()
	_, err := wc.Status(ctx(t), "")
	e, ok := AsError(err)
	if !ok || !strings.Contains(e.Remediation, "decoy") {
		t.Fatalf("a wrong secure path should be diagnosed as the decoy handler, got %v", err)
	}
}

func TestWorkerClient_Unreachable(t *testing.T) {
	wc := NewWorkerClient("http://127.0.0.1:1", "p")
	wc.HTTP = &http.Client{Timeout: time.Second}
	if _, err := wc.Status(ctx(t), ""); err == nil {
		t.Fatal("an unreachable edge must error")
	} else if e, _ := AsError(err); e == nil || e.Kind != KindNetwork {
		t.Fatalf("want a network error, got %v", err)
	}
}

func TestPushFeed(t *testing.T) {
	m := newMockWorker(t)
	feedURL := m.srv.URL + "/" + m.path + "/feed"
	doc := map[string]any{"version": 1, "users": []any{}}

	res, err := PushFeed(ctx(t), m.srv.Client(), feedURL, m.pushToken, doc)
	if err != nil {
		t.Fatalf("PushFeed: %v", err)
	}
	if res.Users != 2 || res.SharedNodes != 1 {
		t.Fatalf("push result = %+v", res)
	}
	// Warnings must be returned, never swallowed: each one is a subscriber
	// getting a short list without knowing it.
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings were dropped: %+v", res)
	}

	if _, err := PushFeed(ctx(t), m.srv.Client(), feedURL, "wrong", doc); err == nil {
		t.Fatal("a wrong push token must be rejected")
	} else if e, _ := AsError(err); e == nil || e.Kind != KindAuth {
		t.Fatalf("want an auth failure, got %v", err)
	}

	if _, err := PushFeed(ctx(t), m.srv.Client(), m.srv.URL+"/wrong/feed", m.pushToken, doc); err == nil {
		t.Fatal("pushing to the decoy must not read as success")
	}
	if _, err := PushFeed(ctx(t), m.srv.Client(), feedURL, m.pushToken, make(chan int)); err == nil {
		t.Fatal("an unencodable document must be refused before it is sent")
	}
}
