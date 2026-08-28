package edge

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// cfMock replays the api.cloudflare.com/client/v4 shapes the Workers control
// plane uses, envelope and all, so the client is exercised against the wire
// format it will actually meet rather than a convenient fiction.
type cfMock struct {
	mu sync.Mutex

	Accounts   []Account
	Scripts    map[string]ScriptInfo
	KV         map[string]KVNamespace // by id
	D1         map[string]D1Database  // by id
	Zones      []struct{ ID, Name string }
	Subdomain  string
	Domains    map[string][]string // worker name -> hostnames
	Requests   []string
	SubEnabled map[string]bool
	// Schedules is the cron trigger list per worker, exactly as Cloudflare
	// keeps it: attached to the script, and gone when the script is deleted.
	Schedules map[string][]string

	// LastUpload records the parsed metadata and script of the last PUT, which
	// is how keep_bindings and the SECURE_PATH binding are asserted.
	LastUpload   *uploadMetadata
	LastScript   string
	uploadFailed string

	// OnDeleteScript fires when a script is deleted, so a test can observe the
	// recreate path without reaching into the mock's state.
	OnDeleteScript func(name string)

	// Deny maps "METHOD /prefix" to a canned failure.
	Deny       map[string]apiMessage
	DenyStatus map[string]int

	nextID int
	server *httptest.Server
}

func newCFMock(t *testing.T) *cfMock {
	t.Helper()
	m := &cfMock{
		Accounts: []Account{{ID: "acct-1", Name: "Acme"}},
		Scripts:  map[string]ScriptInfo{}, KV: map[string]KVNamespace{},
		D1: map[string]D1Database{}, Domains: map[string][]string{},
		SubEnabled: map[string]bool{}, Schedules: map[string][]string{},
		Deny:       map[string]apiMessage{}, DenyStatus: map[string]int{},
		Subdomain: "acme",
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

// client returns a Client pointed at the mock, with retries and sleeps disabled
// so tests stay fast and deterministic.
func (m *cfMock) client() *Client {
	return &Client{Token: "test-token", AccountID: "acct-1",
		BaseURL: m.server.URL + "/client/v4", HTTP: m.server.Client(),
		MaxRetries: 1, Sleep: func(time.Duration) {}}
}

func (m *cfMock) writeEnvelope(w http.ResponseWriter, status int, result any, errs ...apiMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	raw, _ := json.Marshal(result)
	if result == nil {
		raw = []byte("null")
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": len(errs) == 0, "errors": errs, "messages": []apiMessage{},
		"result": json.RawMessage(raw),
	})
}

func (m *cfMock) denied(method, path string) (apiMessage, int, bool) {
	for key, msg := range m.Deny {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != method && parts[0] != "*" {
			continue
		}
		if !strings.HasPrefix(path, parts[1]) {
			continue
		}
		status := m.DenyStatus[key]
		if status == 0 {
			status = http.StatusForbidden
		}
		return msg, status, true
	}
	return apiMessage{}, 0, false
}

func (m *cfMock) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	m.mu.Lock()
	m.Requests = append(m.Requests, r.Method+" "+path)
	msg, status, isDenied := m.denied(r.Method, path)
	m.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer test-token" {
		m.writeEnvelope(w, http.StatusUnauthorized, nil, apiMessage{Code: 10000, Message: "Authentication error"})
		return
	}
	if isDenied {
		m.writeEnvelope(w, status, nil, msg)
		return
	}

	switch {
	case path == "/accounts":
		m.mu.Lock()
		accts := m.Accounts
		m.mu.Unlock()
		m.writeEnvelope(w, http.StatusOK, accts)
	case path == "/zones":
		m.mu.Lock()
		zones := m.Zones
		m.mu.Unlock()
		m.writeEnvelope(w, http.StatusOK, zones)
	case strings.HasPrefix(path, "/accounts/acct-1/workers/subdomain"):
		m.handleSubdomain(w, r)
	case strings.HasPrefix(path, "/accounts/acct-1/workers/domains"):
		m.handleWorkerDomains(w, r)
	case strings.HasPrefix(path, "/accounts/acct-1/workers/scripts"):
		m.handleScripts(w, r, strings.TrimPrefix(path, "/accounts/acct-1/workers/scripts"))
	case strings.HasPrefix(path, "/accounts/acct-1/storage/kv/namespaces"):
		m.handleKV(w, r, strings.TrimPrefix(path, "/accounts/acct-1/storage/kv/namespaces"))
	case strings.HasPrefix(path, "/accounts/acct-1/d1/database"):
		m.handleD1(w, r, strings.TrimPrefix(path, "/accounts/acct-1/d1/database"))
	case strings.HasPrefix(path, "/accounts/acct-1/pages/projects/"):
		m.writeEnvelope(w, http.StatusOK, map[string]any{"id": "p"})
	default:
		m.writeEnvelope(w, http.StatusNotFound, nil,
			apiMessage{Code: 7003, Message: "Could not route to " + path + ", perhaps your object identifier is invalid?"})
	}
}

func (m *cfMock) handleSubdomain(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		if m.Subdomain == "" {
			m.writeEnvelope(w, http.StatusNotFound, nil, apiMessage{Code: 10007, Message: "workers.api.error.subdomain_not_found"})
			return
		}
		m.writeEnvelope(w, http.StatusOK, map[string]any{"subdomain": m.Subdomain})
	case http.MethodPut:
		var body struct {
			Subdomain string `json:"subdomain"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.Subdomain = body.Subdomain
		m.writeEnvelope(w, http.StatusOK, map[string]any{"subdomain": body.Subdomain})
	}
}

func (m *cfMock) handleWorkerDomains(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		service := r.URL.Query().Get("service")
		out := []map[string]string{}
		for _, h := range m.Domains[service] {
			out = append(out, map[string]string{"hostname": h})
		}
		m.writeEnvelope(w, http.StatusOK, out)
	case http.MethodPut:
		var body struct {
			Hostname, Service, ZoneID string
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &struct {
			Hostname *string `json:"hostname"`
			Service  *string `json:"service"`
			ZoneID   *string `json:"zone_id"`
		}{&body.Hostname, &body.Service, &body.ZoneID})
		if body.ZoneID == "" {
			m.writeEnvelope(w, http.StatusBadRequest, nil, apiMessage{Code: 1004, Message: "zone_id is required"})
			return
		}
		m.Domains[body.Service] = append(m.Domains[body.Service], body.Hostname)
		m.writeEnvelope(w, http.StatusOK, map[string]any{"hostname": body.Hostname})
	}
}

func (m *cfMock) handleScripts(w http.ResponseWriter, r *http.Request, rest string) {
	rest = strings.TrimPrefix(rest, "/")
	name, sub, _ := strings.Cut(rest, "/")

	if sub == "schedules" {
		m.handleSchedules(w, r, name)
		return
	}

	if sub == "subdomain" && r.Method == http.MethodPost {
		m.mu.Lock()
		m.SubEnabled[name] = true
		m.mu.Unlock()
		m.writeEnvelope(w, http.StatusOK, map[string]any{"enabled": true})
		return
	}

	switch r.Method {
	case http.MethodGet:
		m.mu.Lock()
		info, ok := m.Scripts[name]
		m.mu.Unlock()
		if !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil,
				apiMessage{Code: 10007, Message: "workers.api.error.script_not_found"})
			return
		}
		m.writeEnvelope(w, http.StatusOK, info)
	case http.MethodPut:
		meta, script, err := parseUpload(r)
		if err != nil {
			m.mu.Lock()
			m.uploadFailed = err.Error()
			m.mu.Unlock()
			m.writeEnvelope(w, http.StatusBadRequest, nil, apiMessage{Code: 1004, Message: err.Error()})
			return
		}
		m.mu.Lock()
		m.LastUpload, m.LastScript = meta, script
		m.Scripts[name] = ScriptInfo{ID: name, ModifiedOn: "2026-08-07T09:14:22Z"}
		m.mu.Unlock()
		m.writeEnvelope(w, http.StatusOK, map[string]any{"id": name})
	case http.MethodDelete:
		m.mu.Lock()
		_, ok := m.Scripts[name]
		delete(m.Scripts, name)
		// Schedules live on the script, so deleting it drops them. Modelling
		// that is the point: it is why the deploy registers the cron after the
		// heal step rather than before it.
		delete(m.Schedules, name)
		if m.OnDeleteScript != nil {
			m.OnDeleteScript(name)
		}
		m.mu.Unlock()
		if !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil,
				apiMessage{Code: 10007, Message: "workers.api.error.script_not_found"})
			return
		}
		m.writeEnvelope(w, http.StatusOK, map[string]any{"id": name})
	}
}

// handleSchedules models PUT/GET .../scripts/{name}/schedules. The PUT body is
// a bare array of {cron} objects; the GET result wraps it in {"schedules":[…]},
// which is the asymmetry the client has to cope with.
func (m *cfMock) handleSchedules(w http.ResponseWriter, r *http.Request, name string) {
	switch r.Method {
	case http.MethodPut:
		var body []struct {
			Cron string `json:"cron"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			m.writeEnvelope(w, http.StatusBadRequest, nil,
				apiMessage{Code: 1004, Message: "schedules body is not a JSON array: " + err.Error()})
			return
		}
		crons := []string{}
		for _, b := range body {
			crons = append(crons, b.Cron)
		}
		m.mu.Lock()
		_, known := m.Scripts[name]
		if known {
			m.Schedules[name] = crons
		}
		m.mu.Unlock()
		if !known {
			m.writeEnvelope(w, http.StatusNotFound, nil,
				apiMessage{Code: 10007, Message: "workers.api.error.script_not_found"})
			return
		}
		m.writeEnvelope(w, http.StatusOK, map[string]any{"schedules": body})
	case http.MethodGet:
		m.mu.Lock()
		out := []map[string]string{}
		for _, c := range m.Schedules[name] {
			out = append(out, map[string]string{"cron": c})
		}
		m.mu.Unlock()
		m.writeEnvelope(w, http.StatusOK, map[string]any{"schedules": out})
	}
}

// parseUpload decodes the multipart body exactly as Cloudflare does, so a
// malformed metadata part or a wrong script content type is a test failure.
func parseUpload(r *http.Request) (*uploadMetadata, string, error) {
	ct := r.Header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		return nil, "", errUpload("expected multipart/form-data, got " + ct)
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var meta uploadMetadata
	var script string
	sawMeta, sawScript := false, false
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(part)
		switch part.FormName() {
		case "metadata":
			if err := json.Unmarshal(body, &meta); err != nil {
				return nil, "", errUpload("metadata is not JSON: " + err.Error())
			}
			sawMeta = true
		case "worker.js":
			if got := part.Header.Get("Content-Type"); got != "application/javascript+module" {
				return nil, "", errUpload("worker.js must be application/javascript+module, got " + got)
			}
			script = string(body)
			sawScript = true
		}
	}
	if !sawMeta || !sawScript {
		return nil, "", errUpload("upload needs both a metadata part and a worker.js part")
	}
	return &meta, script, nil
}

type uploadErr string

func (e uploadErr) Error() string { return string(e) }
func errUpload(s string) error    { return uploadErr(s) }

func (m *cfMock) handleKV(w http.ResponseWriter, r *http.Request, rest string) {
	id := strings.Trim(rest, "/")
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case r.Method == http.MethodGet:
		out := []KVNamespace{}
		for _, ns := range m.KV {
			out = append(out, ns)
		}
		m.writeEnvelope(w, http.StatusOK, out)
	case r.Method == http.MethodPost:
		var body struct {
			Title string `json:"title"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.nextID++
		ns := KVNamespace{ID: "kv" + string(rune('0'+m.nextID)), Title: body.Title}
		m.KV[ns.ID] = ns
		m.writeEnvelope(w, http.StatusOK, ns)
	case r.Method == http.MethodDelete:
		if _, ok := m.KV[id]; !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil, apiMessage{Code: 10009, Message: "namespace not found"})
			return
		}
		delete(m.KV, id)
		m.writeEnvelope(w, http.StatusOK, nil)
	}
}

func (m *cfMock) handleD1(w http.ResponseWriter, r *http.Request, rest string) {
	id := strings.Trim(rest, "/")
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.nextID++
		db := D1Database{UUID: "d1-" + body.Name, Name: body.Name}
		m.D1[db.UUID] = db
		m.writeEnvelope(w, http.StatusOK, db)
	case http.MethodDelete:
		delete(m.D1, id)
		m.writeEnvelope(w, http.StatusOK, nil)
	}
}

func (m *cfMock) snapshot() *cfMock {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m
}
