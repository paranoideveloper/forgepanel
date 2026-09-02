package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// desecMock replays desec.io/api/v1 shapes: bare JSON (no envelope), RRsets
// keyed by (subname, type), presentation-format values, and a 429 carrying
// Retry-After.
type desecMock struct {
	mu sync.Mutex
	// Domains by name.
	Domains map[string]desecDomain
	// RRsets by domain then "subname/TYPE".
	RRsets map[string]map[string]desecRRset
	// Status forces an HTTP status for "METHOD /prefix".
	Status map[string]int
	Detail map[string]string
	// Throttle429 makes the next N requests answer 429, exercising the retry.
	Throttle429 int
	AuthHeader  string
	Requests    []string
	server      *httptest.Server
}

func newDesecMock(t *testing.T) *desecMock {
	t.Helper()
	m := &desecMock{
		Domains: map[string]desecDomain{}, RRsets: map[string]map[string]desecRRset{},
		Status: map[string]int{}, Detail: map[string]string{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *desecMock) client() *Desec {
	return &Desec{
		Token: "desec-token", BaseURL: m.server.URL + "/api/v1",
		HTTP: m.server.Client(), MaxRetries: 2, Sleep: func(time.Duration) {},
	}
}

func (m *desecMock) addDomain(name string, minTTL int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Domains[name] = desecDomain{Name: name, MinimumTTL: minTTL}
	if m.RRsets[name] == nil {
		m.RRsets[name] = map[string]desecRRset{}
	}
}

func (m *desecMock) forced(method, path string) (int, string, bool) {
	for key, status := range m.Status {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != method && parts[0] != "*" {
			continue
		}
		if strings.HasPrefix(path, parts[1]) {
			return status, m.Detail[key], true
		}
	}
	return 0, "", false
}

func (m *desecMock) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	m.mu.Lock()
	m.AuthHeader = r.Header.Get("Authorization")
	m.Requests = append(m.Requests, r.Method+" "+path)
	if m.Throttle429 > 0 {
		m.Throttle429--
		m.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Request was throttled. Expected available in 1 second."})
		return
	}
	status, detail, forced := m.forced(r.Method, path)
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Token desec-token" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid token."})
		return
	}
	if forced {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
		return
	}

	switch {
	case path == "/domains/":
		m.mu.Lock()
		out := make([]desecDomain, 0, len(m.Domains))
		for _, d := range m.Domains {
			out = append(out, d)
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)

	case strings.Contains(path, "/rrsets"):
		m.handleRRsets(w, r, path)

	case strings.HasPrefix(path, "/domains/"):
		name := strings.Trim(strings.TrimPrefix(path, "/domains/"), "/")
		m.mu.Lock()
		d, ok := m.Domains[name]
		m.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
			return
		}
		_ = json.NewEncoder(w).Encode(d)

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
	}
}

func (m *desecMock) handleRRsets(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, "/domains/")
	idx := strings.Index(rest, "/rrsets")
	domain := rest[:idx]
	tail := strings.Trim(strings.TrimPrefix(rest[idx:], "/rrsets"), "/")

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Domains[domain]; !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
		return
	}
	minTTL := m.Domains[domain].MinimumTTL

	if tail == "" {
		switch r.Method {
		case http.MethodGet:
			wantType := strings.ToUpper(r.URL.Query().Get("type"))
			wantSub := r.URL.Query().Get("subname")
			hasSub := r.URL.Query().Has("subname")
			out := make([]desecRRset, 0)
			for _, rr := range m.RRsets[domain] {
				if wantType != "" && strings.ToUpper(rr.Type) != wantType {
					continue
				}
				if hasSub && rr.Subname != wantSub {
					continue
				}
				out = append(out, rr)
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var body desecRRset
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid body."})
				return
			}
			if minTTL > 0 && body.TTL < minTTL {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"detail": "Ensure this value is greater than or equal to " + itoaTest(minTTL) + " (ttl).",
				})
				return
			}
			body.Domain = domain
			m.RRsets[domain][rrsetID(body.Subname, body.Type)] = body
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(body)
		}
		return
	}

	parts := strings.Split(tail, "/")
	if len(parts) < 2 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
		return
	}
	subname := parts[0]
	if subname == "@" {
		subname = ""
	}
	key := rrsetID(subname, parts[1])
	switch r.Method {
	case http.MethodGet:
		rr, ok := m.RRsets[domain][key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
			return
		}
		_ = json.NewEncoder(w).Encode(rr)
	case http.MethodPatch, http.MethodPut:
		rr, ok := m.RRsets[domain][key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
			return
		}
		var body struct {
			Records []string `json:"records"`
			TTL     int      `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid body."})
			return
		}
		rr.Records = body.Records
		if body.TTL > 0 {
			rr.TTL = body.TTL
		}
		m.RRsets[domain][key] = rr
		_ = json.NewEncoder(w).Encode(rr)
	case http.MethodDelete:
		if _, ok := m.RRsets[domain][key]; !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Not found."})
			return
		}
		delete(m.RRsets[domain], key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
