package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/store"
)

// --- Cloudflare API mock ----------------------------------------------------

// cfEdgeMock replays just enough of api.cloudflare.com for the deploy/update/
// delete paths, so `forgectl edge` is exercised against the wire format rather
// than a stub of our own functions.
type cfEdgeMock struct {
	mu      sync.Mutex
	scripts map[string]bool
	kv      map[string]string // id -> title
	deleted []string
	// lastBindings is the bindings array of the most recent script upload.
	// The upload used to be copied to io.Discard, which made every binding the
	// CLI sends — or fails to re-send — invisible to these tests.
	lastBindings []map[string]any
	srv          *httptest.Server
}

func newCFEdgeMock(t *testing.T) *cfEdgeMock {
	t.Helper()
	m := &cfEdgeMock{scripts: map[string]bool{}, kv: map[string]string{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *cfEdgeMock) ok(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	raw, _ := json.Marshal(result)
	if result == nil {
		raw = []byte("null")
	}
	_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":` + string(raw) + `}`))
}

func (m *cfEdgeMock) fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]any{
		"success": false, "result": nil,
		"errors": []map[string]any{{"code": code, "message": msg}},
	})
	_, _ = w.Write(body)
}

func (m *cfEdgeMock) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case path == "/accounts":
		m.ok(w, []map[string]string{{"id": "acct-1", "name": "Acme"}})
	case path == "/accounts/acct-1/workers/subdomain":
		m.ok(w, map[string]string{"subdomain": "acme"})
	case strings.HasPrefix(path, "/accounts/acct-1/storage/kv/namespaces"):
		id := strings.Trim(strings.TrimPrefix(path, "/accounts/acct-1/storage/kv/namespaces"), "/")
		switch r.Method {
		case http.MethodGet:
			out := []map[string]string{}
			for k, v := range m.kv {
				out = append(out, map[string]string{"id": k, "title": v})
			}
			m.ok(w, out)
		case http.MethodPost:
			var body struct {
				Title string `json:"title"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.kv["kv-1"] = body.Title
			m.ok(w, map[string]string{"id": "kv-1", "title": body.Title})
		case http.MethodDelete:
			delete(m.kv, id)
			m.deleted = append(m.deleted, "kv:"+id)
			m.ok(w, nil)
		}
	case strings.HasPrefix(path, "/accounts/acct-1/workers/scripts/"):
		rest := strings.TrimPrefix(path, "/accounts/acct-1/workers/scripts/")
		name, sub, _ := strings.Cut(rest, "/")
		if sub == "subdomain" {
			m.ok(w, map[string]bool{"enabled": true})
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !m.scripts[name] {
				m.fail(w, http.StatusNotFound, 10007, "workers.api.error.script_not_found")
				return
			}
			m.ok(w, map[string]string{"id": name})
		case http.MethodPut:
			// sub == "" is the script upload; the deploy also PUTs
			// .../schedules, which carries no bindings and must not clear them.
			if sub == "" {
				m.lastBindings = uploadBindings(r)
			}
			m.scripts[name] = true
			m.ok(w, map[string]string{"id": name})
		case http.MethodDelete:
			if !m.scripts[name] {
				m.fail(w, http.StatusNotFound, 10007, "workers.api.error.script_not_found")
				return
			}
			delete(m.scripts, name)
			m.deleted = append(m.deleted, "script:"+name)
			m.ok(w, map[string]string{"id": name})
		}
	default:
		m.fail(w, http.StatusNotFound, 7003, "Could not route to "+path)
	}
}

func (m *cfEdgeMock) base() string { return m.srv.URL + "/client/v4" }

func (m *cfEdgeMock) hasScript(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scripts[name]
}

// bindings returns the last upload's bindings array.
func (m *cfEdgeMock) bindings() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastBindings
}

// binding returns the uploaded binding with this name, or nil.
func (m *cfEdgeMock) binding(name string) map[string]any {
	for _, b := range m.bindings() {
		if b["name"] == name {
			return b
		}
	}
	return nil
}

// uploadBindings pulls the bindings array out of the multipart `metadata` part
// of a script upload. A parse failure returns nil, which reads as "no bindings"
// and fails the assertions rather than passing them silently.
func uploadBindings(r *http.Request) []map[string]any {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err != nil {
			return nil
		}
		if part.FormName() != "metadata" {
			continue
		}
		var meta struct {
			Bindings []map[string]any `json:"bindings"`
		}
		if err := json.NewDecoder(part).Decode(&meta); err != nil {
			return nil
		}
		return meta.Bindings
	}
}

func (m *cfEdgeMock) wasDeleted(what string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.deleted {
		if d == what {
			return true
		}
	}
	return false
}

// --- edge Worker mock -------------------------------------------------------

type edgeWorkerMock struct {
	mu        sync.Mutex
	path      string
	password  string
	pushToken string
	loggedIn  bool
	feed      map[string]any
	srv       *httptest.Server
}

func newEdgeWorkerMock(t *testing.T) *edgeWorkerMock {
	t.Helper()
	m := &edgeWorkerMock{path: "clipath23456789abcdefghi", password: "hunter2hunter2", pushToken: "push-tok"}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *edgeWorkerMock) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	route := strings.TrimPrefix(r.URL.Path, "/"+m.path)
	m.mu.Lock()
	defer m.mu.Unlock()
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
		w.Header().Set("Set-Cookie", "fe_session=abc; Path=/")
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Signed in.","body":{"firstRun":false}}`))
	case "/api/status":
		if !m.loggedIn {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":null,"body":{"version":"0.1.0","users":14,"backendMode":"off","feedGeneratedAt":"2026-08-07T09:10:00Z","securePathRotatedAt":"2026-08-01T12:00:00Z","cleanIPs":{"count":37,"updatedAt":"2026-08-07T06:17:00Z"}}}`))
	case "/api/rotate-path":
		if !m.loggedIn {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Rotated.","body":{"securePath":"freshpath23456789abcdefg"}}`))
	case "/feed":
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != m.pushToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Invalid feed push token.","body":null}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &m.feed)
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Feed accepted.","body":{"users":1,"sharedNodes":0,"warnings":["dropped user 9: no sub_token"]}}`))
	default:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>decoy</html>"))
	}
}

// --- helpers ----------------------------------------------------------------

// edgeDataDir returns a temp dir with a panel database, optionally holding one
// registered deployment.
func edgeDataDir(t *testing.T, deployments ...*store.EdgeDeployment) string {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "forgepanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range deployments {
		if err := db.CreateEdgeDeployment(d); err != nil {
			t.Fatalf("CreateEdgeDeployment: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeBundle(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "worker.js")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFeed(t *testing.T, doc any) string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleFeed() map[string]any {
	return map[string]any{
		"version": 1, "generated_at": "2026-08-07T09:00:00Z",
		"users": []any{map[string]any{
			"id": "1", "sub_token": "tok", "email": "alice", "enabled": true,
			"nodes": []any{map[string]any{"protocol": "vless", "address": "a.example.com", "port": 443}},
		}},
		"shared_nodes": []any{},
	}
}

// --- dispatch and exit codes ------------------------------------------------

func TestEdgeDispatch(t *testing.T) {
	if err := cmdEdge([]string{"--help"}); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if err := cmdEdge([]string{"token-url"}); err != nil {
		t.Fatalf("token-url: %v", err)
	}
	if code := exitCodeFor(cmdEdge(nil)); code != exitUsage {
		t.Errorf("no subcommand should be a usage error, got exit %d", code)
	}
	if code := exitCodeFor(cmdEdge([]string{"frobnicate"})); code != exitUsage {
		t.Errorf("an unknown subcommand should be a usage error, got exit %d", code)
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, exitOK},
		{"plain", errors.New("boom"), exitFailure},
		{"explicit", withExit(exitFeedRejected, errors.New("rejected")), exitFeedRejected},
		{"auth", &edge.Error{Kind: edge.KindAuth, Message: "no"}, exitAuth},
		{"permission", &edge.Error{Kind: edge.KindPermission, Message: "no"}, exitAuth},
		{"no credentials", edge.ErrNoCredentials("x"), exitAuth},
		{"conflict", &edge.Error{Kind: edge.KindConflict, Message: "taken"}, exitNameTaken},
		{"not found", &edge.Error{Kind: edge.KindNotFound, Message: "gone"}, exitNotFound},
		{"other kind", &edge.Error{Kind: edge.KindServer, Message: "boom"}, exitFailure},
	}
	for _, tc := range cases {
		if got := exitCodeFor(tc.err); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
	if withExit(exitAuth, nil) != nil {
		t.Error("withExit(nil) must stay nil")
	}
}

// --- deploy -----------------------------------------------------------------

func TestEdgeDeploy_RegistersInThePanel(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t)
	bundle := writeBundle(t, "export default {}")

	err := cmdEdgeDeploy([]string{
		"--name", "forgeedge-cli", "--api-token", "test-token", "--account", "acct-1",
		"--bundle", bundle, "--secure-path", "clipath23456789abcdefghi",
		"--api-base", cf.base(), "--data", data, "--skip-verify",
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if !cf.hasScript("forgeedge-cli") {
		t.Fatal("the Worker was never uploaded")
	}
	db, err := store.Open(filepath.Join(data, "forgepanel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d, err := db.EdgeDeploymentByName("forgeedge-cli")
	if err != nil {
		t.Fatalf("the deployment was not registered in the panel: %v", err)
	}
	if d.Origin != "https://forgeedge-cli.acme.workers.dev" || d.SecurePath != "clipath23456789abcdefghi" {
		t.Fatalf("registered row = %+v", d)
	}
	if d.AccountID != "acct-1" {
		t.Errorf("account id = %q", d.AccountID)
	}
}

func TestEdgeDeploy_JSONOutputAndReDeploy(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t)
	bundle := writeBundle(t, "export default {}")
	args := []string{"--name", "w", "--api-token", "t", "--account", "acct-1",
		"--bundle", bundle, "--api-base", cf.base(), "--data", data, "--skip-verify", "--json"}
	if err := cmdEdgeDeploy(args); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	// Second run without --force must refuse rather than clobber.
	if err := cmdEdgeDeploy(args); err == nil {
		t.Fatal("re-deploying over an existing Worker must be refused")
	} else if exitCodeFor(err) != exitNameTaken {
		t.Fatalf("want exit %d for a taken name, got %d (%v)", exitNameTaken, exitCodeFor(err), err)
	}
	// --force overwrites, and the panel row is updated rather than duplicated.
	if err := cmdEdgeDeploy(append(args, "--force")); err != nil {
		t.Fatalf("forced deploy: %v", err)
	}
	db, _ := store.Open(filepath.Join(data, "forgepanel.db"))
	defer db.Close()
	rows, _ := db.ListEdgeDeployments()
	if len(rows) != 1 {
		t.Fatalf("want a single row after a re-deploy, got %d", len(rows))
	}
}

func TestEdgeDeploy_MissingBundle(t *testing.T) {
	err := cmdEdgeDeploy([]string{"--name", "w", "--api-token", "t", "--bundle", "/nonexistent/worker.js"})
	if err == nil {
		t.Fatal("a missing bundle must fail")
	}
	e, ok := edge.AsError(err)
	if !ok || !strings.Contains(e.Remediation, "bun run build") {
		t.Fatalf("the error must carry a remediation naming the build step: %v", err)
	}
	// And that remediation has to reach the operator, not just the error value.
	var buf strings.Builder
	printRemediation(&buf, err)
	if !strings.Contains(buf.String(), "bun run build") {
		t.Errorf("printRemediation dropped it: %q", buf.String())
	}
}

func TestEdgeDeploy_BadFlag(t *testing.T) {
	if code := exitCodeFor(cmdEdgeDeploy([]string{"--not-a-flag"})); code != exitUsage {
		t.Errorf("an unknown flag is a usage error, got exit %d", code)
	}
}

// --- update -----------------------------------------------------------------

func TestEdgeUpdate_ReUploadsRegisteredWorkers(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: "https://w.acme.workers.dev", SecurePath: "path23456789abcdefghijkl",
	})
	bundle := writeBundle(t, "export default {v:2}")
	if err := cmdEdgeUpdate([]string{
		"--name", "w", "--api-token", "t", "--account", "acct-1",
		"--bundle", bundle, "--api-base", cf.base(), "--data", data, "--skip-verify",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !cf.hasScript("w") {
		t.Fatal("the update never uploaded a script")
	}
}

// TestEdgeUpdate_ResendsTheSelfManageBinding pins the half of this feature that
// is easiest to leave out and impossible to see from the panel host.
//
// keep_bindings is ["kv_namespace","d1"], so every upload resends a CLOSED list
// of text bindings: anything not in the new upload is gone. An operator who
// ticks "let this worker manage itself" gets a working Deployment panel, and the
// next `forgectl edge update --all` silently strips the credential — with no
// error anywhere, because nothing on the Go side ever reads a binding back.
func TestEdgeUpdate_ResendsTheSelfManageBinding(t *testing.T) {
	update := func(t *testing.T, selfManage bool) *cfEdgeMock {
		t.Helper()
		cf := newCFEdgeMock(t)
		data := edgeDataDir(t, &store.EdgeDeployment{
			Name: "w", Origin: "https://w.acme.workers.dev",
			SecurePath: "path23456789abcdefghijkl", SelfManage: selfManage,
		})
		bundle := writeBundle(t, "export default {v:2}")
		if err := cmdEdgeUpdate([]string{
			"--name", "w", "--api-token", "cf-token", "--account", "acct-1",
			"--bundle", bundle, "--api-base", cf.base(), "--data", data, "--skip-verify",
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		return cf
	}

	t.Run("re-sends both bindings", func(t *testing.T) {
		cf := update(t, true)
		tok := cf.binding("CF_API_TOKEN")
		if tok == nil {
			t.Fatalf("the update dropped CF_API_TOKEN; bindings were %+v", cf.bindings())
		}
		if tok["type"] != "secret_text" {
			t.Errorf("CF_API_TOKEN type = %v, want secret_text", tok["type"])
		}
		if tok["text"] != "cf-token" {
			t.Errorf("CF_API_TOKEN text = %v, want the token this invocation used", tok["text"])
		}
		acct := cf.binding("CF_ACCOUNT_ID")
		if acct == nil {
			t.Fatalf("the update dropped CF_ACCOUNT_ID; bindings were %+v", cf.bindings())
		}
		// Both or neither: the Worker returns no credentials unless it has both,
		// so a half-bound Worker is indistinguishable from an unbound one.
		if acct["type"] != "plain_text" || acct["text"] != "acct-1" {
			t.Errorf("CF_ACCOUNT_ID = %+v, want plain_text acct-1", acct)
		}
	})

	t.Run("not when the deployment did not ask for it", func(t *testing.T) {
		cf := update(t, false)
		if b := cf.binding("CF_API_TOKEN"); b != nil {
			t.Errorf("an unrequested deploy bound the API token: %+v", b)
		}
		if b := cf.binding("CF_ACCOUNT_ID"); b != nil {
			t.Errorf("an unrequested deploy bound the account id: %+v", b)
		}
	})
}

func TestEdgeUpdate_CheckOnly(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://example.invalid/r"}`))
	}))
	defer gh.Close()
	old := edge.GitHubAPIBase
	edge.GitHubAPIBase = gh.URL
	defer func() { edge.GitHubAPIBase = old }()

	data := edgeDataDir(t)
	if err := cmdEdgeUpdate([]string{"--check-only", "--data", data, "--json"}); err != nil {
		t.Fatalf("check-only: %v", err)
	}
	// --check-only must never need a bundle or a credential.
	if err := cmdEdgeUpdate([]string{"--check-only", "--data", data}); err != nil {
		t.Fatalf("check-only without --json: %v", err)
	}
}

func TestEdgeUpdate_NeedsATarget(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t)
	bundle := writeBundle(t, "x")
	err := cmdEdgeUpdate([]string{"--api-token", "t", "--account", "acct-1",
		"--bundle", bundle, "--api-base", cf.base(), "--data", data})
	if err == nil || exitCodeFor(err) != exitUsage {
		t.Fatalf("update with neither --name nor --all must be a usage error, got %v", err)
	}
}

func TestEdgeUpdate_UnknownName(t *testing.T) {
	data := edgeDataDir(t)
	err := cmdEdgeUpdate([]string{"--name", "nope", "--api-token", "t", "--account", "acct-1",
		"--bundle", writeBundle(t, "x"), "--data", data})
	if exitCodeFor(err) != exitNotFound {
		t.Fatalf("want exit %d for an unregistered name, got %d (%v)", exitNotFound, exitCodeFor(err), err)
	}
}

// --- delete -----------------------------------------------------------------

func TestEdgeDelete_RequiresConfirmation(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "doomed", Origin: "https://doomed.acme.workers.dev",
		SecurePath: "p23456789abcdefghijklmno", LastStatus: "ok: 14 user(s)",
	})
	err := cmdEdgeDelete([]string{"--name", "doomed", "--api-token", "t", "--account", "acct-1",
		"--api-base", cf.base(), "--data", data})
	if err == nil || exitCodeFor(err) != exitUsage {
		t.Fatalf("delete without --yes must refuse, got %v", err)
	}
	if cf.wasDeleted("script:doomed") {
		t.Fatal("the Worker was destroyed despite the missing confirmation")
	}
}

func TestEdgeDelete_DestroysWorkerAndRow(t *testing.T) {
	cf := newCFEdgeMock(t)
	cf.scripts["doomed"] = true
	cf.kv["kv-1"] = edge.KVTitle("doomed")
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "doomed", Origin: "https://doomed.acme.workers.dev", SecurePath: "p23456789abcdefghijklmno",
	})
	if err := cmdEdgeDelete([]string{"--name", "doomed", "--yes", "--api-token", "t",
		"--account", "acct-1", "--api-base", cf.base(), "--data", data}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if cf.hasScript("doomed") {
		t.Error("the Worker survived")
	}
	if !cf.wasDeleted("kv:kv-1") {
		t.Error("the KV namespace was not destroyed and no --keep-kv was given")
	}
	db, _ := store.Open(filepath.Join(data, "forgepanel.db"))
	defer db.Close()
	if _, err := db.EdgeDeploymentByName("doomed"); err == nil {
		t.Error("the panel row survived the delete")
	}
}

func TestEdgeDelete_KeepKV(t *testing.T) {
	cf := newCFEdgeMock(t)
	cf.scripts["w"] = true
	cf.kv["kv-1"] = edge.KVTitle("w")
	if err := cmdEdgeDelete([]string{"--name", "w", "--yes", "--keep-kv", "--api-token", "t",
		"--account", "acct-1", "--api-base", cf.base(), "--data", edgeDataDir(t)}); err != nil {
		t.Fatalf("delete --keep-kv: %v", err)
	}
	if cf.wasDeleted("kv:kv-1") {
		t.Error("--keep-kv must leave the namespace alone")
	}
}

func TestEdgeDelete_NeedsName(t *testing.T) {
	if code := exitCodeFor(cmdEdgeDelete([]string{"--yes"})); code != exitUsage {
		t.Errorf("delete with no --name is a usage error, got exit %d", code)
	}
}

// --- status -----------------------------------------------------------------

func TestEdgeStatus_AgainstAMockWorker(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{Name: "w", Origin: m.srv.URL, SecurePath: m.path})

	if err := cmdEdgeStatus([]string{"--all", "--password", m.password, "--data", data}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := cmdEdgeStatus([]string{"--name", "w", "--password", m.password, "--data", data, "--json"}); err != nil {
		t.Fatalf("status --json: %v", err)
	}
	// Direct addressing, with no panel database in play at all.
	if err := cmdEdgeStatus([]string{"--origin", m.srv.URL, "--secure-path", m.path,
		"--password", m.password, "--data", t.TempDir()}); err != nil {
		t.Fatalf("status --origin: %v", err)
	}
}

func TestEdgeStatus_ReportsUnreachableEdges(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{Name: "w", Origin: m.srv.URL, SecurePath: m.path})
	// No password: the Worker's 401 must surface as a failure, not a blank row.
	err := cmdEdgeStatus([]string{"--all", "--data", data})
	if err == nil {
		t.Fatal("an edge that could not be read must not report as fine")
	}
	if exitCodeFor(err) != exitAuth {
		t.Errorf("want the auth exit code, got %d (%v)", exitCodeFor(err), err)
	}
	// --json still prints the rows before returning the failure.
	if err := cmdEdgeStatus([]string{"--all", "--data", data, "--json"}); err == nil {
		t.Error("--json must still report the failure")
	}
}

func TestOrNone(t *testing.T) {
	if orNone("") != "never" || orNone("  ") != "never" || orNone("x") != "x" {
		t.Error("orNone")
	}
}

// --- push -------------------------------------------------------------------

func TestEdgePush_FromAFile(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: m.srv.URL, SecurePath: m.path, PushToken: m.pushToken,
	})
	feed := writeFeed(t, sampleFeed())

	if err := cmdEdgePush([]string{"--all", "--feed", feed, "--data", data}); err != nil {
		t.Fatalf("push: %v", err)
	}
	m.mu.Lock()
	got := m.feed
	m.mu.Unlock()
	if got == nil {
		t.Fatal("the edge received nothing")
	}
	users, _ := got["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("the edge received %d user(s)", len(users))
	}
}

func TestEdgePush_DryRunSendsNothing(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: m.srv.URL, SecurePath: m.path, PushToken: m.pushToken,
	})
	feed := writeFeed(t, sampleFeed())
	if err := cmdEdgePush([]string{"--all", "--dry-run", "--feed", feed, "--data", data}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if err := cmdEdgePush([]string{"--all", "--dry-run", "--json", "--feed", feed, "--data", data}); err != nil {
		t.Fatalf("dry run --json: %v", err)
	}
	m.mu.Lock()
	sent := m.feed != nil
	m.mu.Unlock()
	if sent {
		t.Fatal("--dry-run sent the feed anyway")
	}
}

func TestEdgePush_WrongTokenIsExitSix(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: m.srv.URL, SecurePath: m.path, PushToken: "wrong",
	})
	err := cmdEdgePush([]string{"--all", "--feed", writeFeed(t, sampleFeed()), "--data", data})
	if err == nil {
		t.Fatal("a rejected feed must fail")
	}
	if exitCodeFor(err) != exitFeedRejected {
		t.Fatalf("want exit %d for a rejected feed, got %d (%v)", exitFeedRejected, exitCodeFor(err), err)
	}
}

func TestEdgePush_NoStoredToken(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{Name: "w", Origin: m.srv.URL, SecurePath: m.path})
	err := cmdEdgePush([]string{"--all", "--feed", writeFeed(t, sampleFeed()), "--data", data})
	if exitCodeFor(err) != exitFeedRejected {
		t.Fatalf("an edge with no push token must be reported, got %v", err)
	}
}

func TestEdgePush_DirectOrigin(t *testing.T) {
	m := newEdgeWorkerMock(t)
	if err := cmdEdgePush([]string{
		"--origin", m.srv.URL, "--secure-path", m.path, "--push-token", m.pushToken,
		"--feed", writeFeed(t, sampleFeed()), "--data", t.TempDir(),
	}); err != nil {
		t.Fatalf("direct push: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.feed == nil {
		t.Fatal("nothing arrived at the edge")
	}
}

func TestEdgePush_MalformedFeedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdEdgePush([]string{"--all", "--feed", p, "--data", t.TempDir()}); err == nil {
		t.Fatal("a malformed feed must be refused before anything is sent")
	}
	if err := cmdEdgePush([]string{"--all", "--feed", "/nonexistent.json", "--data", t.TempDir()}); err == nil {
		t.Fatal("a missing feed file must be refused")
	}
}

// TestFetchPanelFeed pulls the canonical feed from the panel over HTTP, which is
// the path that keeps the CLI from ever rebuilding a feed of its own.
func TestFetchPanelFeed(t *testing.T) {
	const token = "pull-token-abc"
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/edge/feed" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid feed pull token"}`))
			return
		}
		raw, _ := json.Marshal(sampleFeed())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer panel.Close()

	body, err := fetchPanelFeed(panel.URL, token, t.TempDir())
	if err != nil {
		t.Fatalf("fetchPanelFeed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"].(float64) != 1 {
		t.Fatalf("unexpected feed: %s", body)
	}

	if _, err := fetchPanelFeed(panel.URL, "wrong", t.TempDir()); err == nil {
		t.Fatal("a wrong pull token must fail")
	}
	if _, err := fetchPanelFeed("http://127.0.0.1:1", token, t.TempDir()); err == nil {
		t.Fatal("an unreachable panel must fail")
	}

	// With no token anywhere the CLI must say so rather than fetch unauthenticated.
	dir := edgeDataDir(t)
	if _, err := fetchPanelFeed(panel.URL, "", dir); err == nil {
		t.Fatal("with no pull token in the DB this must fail")
	}

	// A token stored in the panel DB is picked up automatically.
	db, _ := store.Open(filepath.Join(dir, "forgepanel.db"))
	if err := db.SetSetting("edge_feed_pull_token", token); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := fetchPanelFeed(panel.URL, "", dir); err != nil {
		t.Fatalf("the stored pull token was not used: %v", err)
	}
}

func TestEdgePush_ThroughThePanel(t *testing.T) {
	const token = "pull-token-abc"
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := json.Marshal(sampleFeed())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer panel.Close()
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: m.srv.URL, SecurePath: m.path, PushToken: m.pushToken,
	})
	if err := cmdEdgePush([]string{"--all", "--panel", panel.URL, "--pull-token", token, "--data", data}); err != nil {
		t.Fatalf("push through the panel: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.feed == nil {
		t.Fatal("the feed fetched from the panel never reached the edge")
	}
}

// --- rotate-path ------------------------------------------------------------

func TestEdgeRotatePath(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{Name: "w", Origin: m.srv.URL, SecurePath: m.path})

	// Refuses without --yes: every subscription URL dies on rotation.
	if err := cmdEdgeRotatePath([]string{"--name", "w", "--password", m.password, "--data", data}); err == nil {
		t.Fatal("rotate-path without --yes must refuse")
	}
	// Refuses without a password.
	if err := cmdEdgeRotatePath([]string{"--name", "w", "--yes", "--data", data}); err == nil {
		t.Fatal("rotate-path needs the edge admin password")
	}
	if err := cmdEdgeRotatePath([]string{"--name", "w", "--yes", "--password", m.password, "--data", data}); err != nil {
		t.Fatalf("rotate-path: %v", err)
	}
	// The new path is persisted, or every later command addresses a dead URL.
	db, _ := store.Open(filepath.Join(data, "forgepanel.db"))
	defer db.Close()
	d, err := db.EdgeDeploymentByName("w")
	if err != nil {
		t.Fatal(err)
	}
	if d.SecurePath != "freshpath23456789abcdefg" {
		t.Fatalf("the rotated path was not persisted: %q", d.SecurePath)
	}
}

func TestEdgeRotatePath_WrongPassword(t *testing.T) {
	m := newEdgeWorkerMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{Name: "w", Origin: m.srv.URL, SecurePath: m.path})
	err := cmdEdgeRotatePath([]string{"--name", "w", "--yes", "--password", "nope", "--data", data})
	if exitCodeFor(err) != exitAuth {
		t.Fatalf("want the auth exit code, got %d (%v)", exitCodeFor(err), err)
	}
}

// --- target resolution ------------------------------------------------------

func TestResolveEdgeTargets(t *testing.T) {
	data := edgeDataDir(t,
		&store.EdgeDeployment{Name: "a", Origin: "https://a.workers.dev", SecurePath: "pa"},
		&store.EdgeDeployment{Name: "b", Origin: "https://b.workers.dev", SecurePath: "pb"},
	)
	all, err := resolveEdgeTargets(data, "", true, "", "", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("--all = %v (%v)", all, err)
	}
	one, err := resolveEdgeTargets(data, "a", false, "", "", "")
	if err != nil || len(one) != 1 || one[0].Name != "a" {
		t.Fatalf("--name = %v (%v)", one, err)
	}
	direct, err := resolveEdgeTargets(t.TempDir(), "", false, "https://x.workers.dev/", "/p/", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if direct[0].Origin != "https://x.workers.dev" || direct[0].SecurePath != "p" || direct[0].PushToken != "tok" {
		t.Fatalf("--origin = %+v", direct[0])
	}
	if _, err := resolveEdgeTargets(data, "", false, "", "", ""); exitCodeFor(err) != exitUsage {
		t.Fatalf("no target at all is a usage error, got %v", err)
	}
	if _, err := resolveEdgeTargets(data, "nope", false, "", "", ""); !edge.IsNotFound(err) {
		t.Fatalf("an unregistered name is a not-found, got %v", err)
	}
}

func TestReadBundle_DefaultPath(t *testing.T) {
	// With no --bundle the CLI looks for the conventional build output; in a
	// temp cwd that is absent, and the error has to say how to produce it.
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	_, err = readBundle("")
	if err == nil || !strings.Contains(err.Error(), "forgeedge") {
		t.Fatalf("want a message naming the expected bundle path, got %v", err)
	}
}

func TestEdgeCreds_NoOAuthAllowed(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	_, err := edgeCreds(t.Context(), "", "", "", false)
	if !errors.Is(err, err) || exitCodeFor(err) != exitAuth {
		t.Fatalf("with no credential and OAuth disallowed this must be an auth failure, got %v", err)
	}
}

func TestEdgeCreds_ResolvesAccount(t *testing.T) {
	cf := newCFEdgeMock(t)
	c, err := edgeCreds(t.Context(), "test-token", "", cf.base(), false)
	if err != nil {
		t.Fatalf("edgeCreds: %v", err)
	}
	if c.AccountID != "acct-1" {
		t.Fatalf("a single visible account must be adopted, got %q", c.AccountID)
	}
	// An explicit account skips the lookup entirely.
	c, err = edgeCreds(t.Context(), "test-token", "explicit", cf.base(), false)
	if err != nil || c.AccountID != "explicit" {
		t.Fatalf("explicit account = %q (%v)", c.AccountID, err)
	}
	// The environment is honoured when no flag is given.
	t.Setenv("CF_API_TOKEN", "test-token")
	if _, err := edgeCreds(t.Context(), "", "acct-1", cf.base(), false); err != nil {
		t.Fatalf("CF_API_TOKEN was ignored: %v", err)
	}
}

func TestEdgeCreds_AmbiguousAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"a1","name":"One"},{"id":"a2","name":"Two"}]}`))
	}))
	defer srv.Close()
	_, err := edgeCreds(t.Context(), "t", "", srv.URL, false)
	if err == nil || !strings.Contains(err.Error(), "several accounts") {
		t.Fatalf("an ambiguous credential must ask for --account, got %v", err)
	}
	e, _ := edge.AsError(err)
	if e == nil || !strings.Contains(e.Remediation, "a1") {
		t.Errorf("the remediation should list the candidate accounts: %v", err)
	}
}

func TestEdgeCreds_NoAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
	}))
	defer srv.Close()
	_, err := edgeCreds(t.Context(), "t", "", srv.URL, false)
	if exitCodeFor(err) != exitAuth {
		t.Fatalf("a credential that sees no accounts is an auth problem, got %v", err)
	}
}

// The deploy path refuses --self-manage without an explicit API token, because
// the OAuth token it would otherwise use is short-lived and binding an expiring
// credential into a Worker produces a Deployment panel that silently rots.
//
// cmdEdgeUpdate calls the same edgeCreds with allowOAuth=true and re-binds
// whatever comes back as CF_API_TOKEN on every self-managed target, and carried
// no such refusal. `forgectl edge update --all` with no --api-token and no
// CF_API_TOKEN in the environment is the DEFAULT invocation — OAuth is the
// documented preferred flow — so the load-bearing half of the feature was the
// half with the guard missing.
//
// TestEdgeUpdate_ResendsTheSelfManageBinding always passes --api-token, so it is
// structurally blind to this.
func TestEdgeUpdate_RefusesToBindAnOAuthTokenIntoASelfManagedWorker(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: "https://w.acme.workers.dev",
		SecurePath: "path23456789abcdefghijkl", SelfManage: true,
	})
	bundle := writeBundle(t, "export default {v:2}")
	t.Setenv("CF_API_TOKEN", "")

	err := cmdEdgeUpdate([]string{
		"--name", "w", "--account", "acct-1",
		"--bundle", bundle, "--api-base", cf.base(), "--data", data, "--skip-verify",
	})
	if err == nil {
		t.Fatal("an OAuth-credentialled update was allowed to rebind a self-managed Worker")
	}
	if !strings.Contains(err.Error(), "API token") {
		t.Fatalf("refusal does not name the cause: %v", err)
	}
	// And it must refuse BEFORE uploading: a partial run that rebinds some
	// targets and then errors is worse than one that does nothing.
	if cf.binding("CF_API_TOKEN") != nil {
		t.Fatal("the Worker was rebound before the refusal")
	}
}

// A target that is NOT self-managed is untouched by the refusal: it binds no
// credential, so an OAuth token is fine and this is the ordinary update path.
func TestEdgeUpdate_AllowsOAuthForAWorkerThatBindsNoCredential(t *testing.T) {
	cf := newCFEdgeMock(t)
	data := edgeDataDir(t, &store.EdgeDeployment{
		Name: "w", Origin: "https://w.acme.workers.dev",
		SecurePath: "path23456789abcdefghijkl", SelfManage: false,
	})
	bundle := writeBundle(t, "export default {v:2}")
	if err := cmdEdgeUpdate([]string{
		"--name", "w", "--api-token", "cf-token", "--account", "acct-1",
		"--bundle", bundle, "--api-base", cf.base(), "--data", data, "--skip-verify",
	}); err != nil {
		t.Fatalf("an ordinary update was refused: %v", err)
	}
}
