package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// fakeWorker stands in for a deployed ForgeEdge Worker's config API.
type fakeWorker struct {
	mu  sync.Mutex
	cfg map[string]any
	// lastPut is the full document the panel wrote, which is where field loss
	// would show up.
	lastPut map[string]any
	putErr  string
	srv     *httptest.Server
}

func newFakeWorker(t *testing.T, cfg map[string]any) *fakeWorker {
	t.Helper()
	f := &fakeWorker{cfg: cfg}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/config") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			writeWorkerEnvelope(w, http.StatusOK, f.cfg)
		case http.MethodPut:
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			f.lastPut = in
			if f.putErr != "" {
				writeWorkerError(w, f.putErr)
				return
			}
			f.cfg = in
			writeWorkerEnvelope(w, http.StatusOK, f.cfg)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func writeWorkerEnvelope(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// The Worker's uniform ApiEnvelope (src/common/http.ts): the payload is
	// "body", not "data".
	json.NewEncoder(w).Encode(map[string]any{"success": true, "status": code, "body": body})
}

func writeWorkerError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{"success": false, "status": 400, "message": msg})
}

func (f *fakeWorker) put() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPut
}

// edgeServerWith registers a deployment pointing at the fake Worker, on a panel
// with a real owner session — these routes are admin-only.
func edgeServerWith(t *testing.T, f *fakeWorker) (*Server, string, uint) {
	t.Helper()
	s, token := adminAPI(t)
	d := &store.EdgeDeployment{
		Name: "w1", Target: "workers", Origin: f.srv.URL,
		SecurePath: "sp23456789abcdefghijklmn", PushToken: "push-token",
	}
	if err := s.db.CreateEdgeDeployment(d); err != nil {
		t.Fatal(err)
	}
	return s, token, d.ID
}

func doJSON(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// liveConfig is the shape a real Worker actually returns, captured from a
// deployed ForgeEdge on 2026-08-26 rather than invented.
func liveConfig() map[string]any {
	return map[string]any{
		"fingerprint": "chrome", "remarkPrefix": "ForgeEdge", "logLevel": "warning",
		"ports": []any{443.0, 8443.0}, "protocols": []any{"vless", "trojan"},
		"cleanIPs": []any{}, "proxyIPMode": "off", "enableIPv6": false,
		"vlessUUID":        "2dc69d57-70c0-48ee-b74c-8117176e1e12",
		"trojanPassword":   "_e2znP7rQCoiEdQwkDrXHBdr",
		"telegramBotToken": "8827947873:REAL-SECRET", "feedPullToken": "pull-secret",
		"warp": map[string]any{"remoteDNS": "1.1.1.1"},
	}
}

func TestEdgeConfigIsReadableFromThePanel(t *testing.T) {
	// The gap: WorkerClient.GetConfigRaw existed and the Telegram bot drove every
	// field through it, while the panel's own UI could edit nothing.
	f := newFakeWorker(t, liveConfig())
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "GET", edgeCfgPath(id), token, "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Config   map[string]any `json:"config"`
		Keys     []string       `json:"keys"`
		Redacted []string       `json:"redacted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)

	if len(out.Keys) != len(liveConfig()) {
		t.Fatalf("reported %d keys, want all %d the Worker holds", len(out.Keys), len(liveConfig()))
	}
	if out.Config["fingerprint"] != "chrome" {
		t.Errorf("fingerprint = %v", out.Config["fingerprint"])
	}
}

func TestSecretsAreNotSentToTheBrowser(t *testing.T) {
	// A Telegram bot token is a credential for a service that is not this one.
	f := newFakeWorker(t, liveConfig())
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "GET", edgeCfgPath(id), token, "")
	body := rec.Body.String()
	for _, secret := range []string{"8827947873:REAL-SECRET", "pull-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the response leaked %q", secret)
		}
	}
	// The UUID and trojan password are NOT redacted on purpose: they appear in
	// every subscription link the Worker hands out, so hiding them from the
	// operator who owns it protects nothing and breaks the field people most
	// often need to rotate.
	if !strings.Contains(body, "2dc69d57-70c0-48ee-b74c-8117176e1e12") {
		t.Error("the VLESS UUID was withheld; it is in every config link already")
	}
}

func TestAFieldThePanelDoesNotKnowSurvivesASave(t *testing.T) {
	// The failure this design exists to prevent. The Worker ships on its own
	// cadence and its config has grown a key at a time; a panel that wrote its
	// own idea of the whole document would silently delete every newer field on
	// the first save, and the operator would find out days later when something
	// stopped working.
	cfg := liveConfig()
	cfg["someFieldFromANewerWorker"] = "keep me"
	cfg["anotherUnknown"] = map[string]any{"nested": true}
	f := newFakeWorker(t, cfg)
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "PUT", edgeCfgPath(id), token, `{"fingerprint":"firefox"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	put := f.put()
	if put["someFieldFromANewerWorker"] != "keep me" {
		t.Fatalf("a field the panel does not know was deleted on save: %v", put["someFieldFromANewerWorker"])
	}
	if put["anotherUnknown"] == nil {
		t.Fatal("a nested unknown field was deleted on save")
	}
	if put["fingerprint"] != "firefox" {
		t.Errorf("the change was not applied: %v", put["fingerprint"])
	}
	// And everything else it did know must be intact too.
	if put["remarkPrefix"] != "ForgeEdge" {
		t.Errorf("an untouched known field was lost: %v", put["remarkPrefix"])
	}
}

func TestAnUntouchedSecretIsNotOverwrittenWithItsPlaceholder(t *testing.T) {
	// The editor sends the redaction sentinel straight back for a field the
	// operator never typed in. Writing it would replace a working credential
	// with the literal string "__unchanged__" — a bug that only surfaces when
	// the thing it broke is next used.
	f := newFakeWorker(t, liveConfig())
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "PUT", edgeCfgPath(id), token,
		`{"fingerprint":"safari","telegramBotToken":"__unchanged__"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	put := f.put()
	if put["telegramBotToken"] != "8827947873:REAL-SECRET" {
		t.Fatalf("the real secret was replaced with %v", put["telegramBotToken"])
	}
	if put["fingerprint"] != "safari" {
		t.Errorf("the real change was not applied: %v", put["fingerprint"])
	}
}

func TestASecretCanStillBeChangedDeliberately(t *testing.T) {
	f := newFakeWorker(t, liveConfig())
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "PUT", edgeCfgPath(id), token, `{"telegramBotToken":"1111:NEW"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := f.put()["telegramBotToken"]; got != "1111:NEW" {
		t.Fatalf("token = %v, want the new one", got)
	}
}

func TestTheWorkersOwnRejectionIsRelayed(t *testing.T) {
	// The Worker validates. Mirroring its schema in the panel would be a second
	// copy of the truth that drifts, so its rejection is the useful message.
	f := newFakeWorker(t, liveConfig())
	f.putErr = "fingerprint must be one of chrome, firefox, safari"
	s, token, id := edgeServerWith(t, f)

	rec := doJSON(t, s, "PUT", edgeCfgPath(id), token, `{"fingerprint":"netscape"}`)
	if rec.Code == 200 {
		t.Fatal("a value the Worker rejected was reported as saved")
	}
	if !strings.Contains(rec.Body.String(), "fingerprint must be one of") {
		t.Fatalf("the Worker's own reason was not relayed: %s", rec.Body.String())
	}
}

func TestAnEmptyPatchIsRefused(t *testing.T) {
	f := newFakeWorker(t, liveConfig())
	s, token, id := edgeServerWith(t, f)
	if rec := doJSON(t, s, "PUT", edgeCfgPath(id), token, `{}`); rec.Code == 200 {
		t.Fatal("an empty patch was accepted")
	}
	if f.put() != nil {
		t.Fatal("an empty patch still wrote to the Worker")
	}
}

func TestADeploymentWithNoPushTokenSaysWhatToDo(t *testing.T) {
	s, token := adminAPI(t)
	d := &store.EdgeDeployment{Name: "w2", Origin: "https://x.workers.dev",
		SecurePath: "sp23456789abcdefghijklmn"} // no push token
	if err := s.db.CreateEdgeDeployment(d); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, s, "GET", edgeCfgPath(d.ID), token, "")
	if rec.Code == 200 {
		t.Fatal("a deployment with no credential returned a config")
	}
	if !strings.Contains(rec.Body.String(), "push token") {
		t.Errorf("the error does not say what is missing: %s", rec.Body.String())
	}
}

func edgeCfgPath(id uint) string {
	return fmt.Sprintf("/api/admin/edge/deployments/%d/config", id)
}
