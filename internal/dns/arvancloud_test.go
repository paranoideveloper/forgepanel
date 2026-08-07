package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// arvanMock replays napi.arvancloud.ir/cdn/4.0 shapes: a {data, meta} envelope,
// sub-names relative to the zone, and the polymorphic value object.
type arvanMock struct {
	mu      sync.Mutex
	Domains []arvanDomain
	Records map[string][]arvanRecord // by domain name
	// Status forces an HTTP status for "METHOD /prefix".
	Status  map[string]int
	Message map[string]string
	// AuthHeader records what the client actually sent.
	AuthHeader string
	nextID     int
	server     *httptest.Server
}

func newArvanMock(t *testing.T) *arvanMock {
	t.Helper()
	m := &arvanMock{
		Records: map[string][]arvanRecord{},
		Status:  map[string]int{}, Message: map[string]string{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *arvanMock) client() *Arvan {
	return &Arvan{APIKey: "secret-key", BaseURL: m.server.URL + "/cdn/4.0", HTTP: m.server.Client()}
}

func (m *arvanMock) addDomain(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Domains = append(m.Domains, arvanDomain{
		ID: "d-" + name, Name: name, Status: "active",
		NameServers: []string{"ns1.arvancdn.ir", "ns2.arvancdn.ir"},
	})
	if m.Records[name] == nil {
		m.Records[name] = []arvanRecord{}
	}
}

func (m *arvanMock) forced(method, path string) (int, string, bool) {
	for key, status := range m.Status {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != method && parts[0] != "*" {
			continue
		}
		if strings.HasPrefix(path, parts[1]) {
			return status, m.Message[key], true
		}
	}
	return 0, "", false
}

func (m *arvanMock) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/cdn/4.0")
	m.mu.Lock()
	m.AuthHeader = r.Header.Get("Authorization")
	status, message, forced := m.forced(r.Method, path)
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if forced {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": message})
		return
	}

	switch {
	case path == "/domains":
		m.mu.Lock()
		search := NormalizeDomain(r.URL.Query().Get("search"))
		out := make([]arvanDomain, 0)
		for _, d := range m.Domains {
			if search != "" && !strings.Contains(NormalizeDomain(d.Name), search) {
				continue
			}
			out = append(out, d)
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": out,
			"meta": map[string]int{"total": len(out), "current_page": 1, "last_page": 1, "per_page": 50},
		})

	case strings.Contains(path, "/dns-records"):
		m.handleRecords(w, r, path)

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "not found"})
	}
}

func (m *arvanMock) handleRecords(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, "/domains/")
	parts := strings.SplitN(rest, "/", 3)
	domain := parts[0]
	recordID := ""
	if len(parts) == 3 {
		recordID = parts[2]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Records[domain]; !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "domain not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		wantType := strings.ToLower(r.URL.Query().Get("type"))
		out := make([]arvanRecord, 0)
		for _, rec := range m.Records[domain] {
			if wantType != "" && strings.ToLower(rec.Type) != wantType {
				continue
			}
			out = append(out, rec)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": out,
			"meta": map[string]int{"total": len(out), "current_page": 1, "last_page": 1, "per_page": 100},
		})

	case http.MethodPost:
		var body arvanRecord
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "The given data was invalid."})
			return
		}
		m.nextID++
		body.ID = fmt.Sprintf("ar%03d", m.nextID)
		m.Records[domain] = append(m.Records[domain], body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body, "message": "record created"})

	case http.MethodPut:
		var body arvanRecord
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "The given data was invalid."})
			return
		}
		body.ID = recordID
		found := false
		for i, rec := range m.Records[domain] {
			if rec.ID == recordID {
				m.Records[domain][i] = body
				found = true
			}
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "record not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body, "message": "record updated"})

	case http.MethodDelete:
		kept := m.Records[domain][:0]
		found := false
		for _, rec := range m.Records[domain] {
			if rec.ID == recordID {
				found = true
				continue
			}
			kept = append(kept, rec)
		}
		m.Records[domain] = kept
		if !found {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "record not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "record deleted"})
	}
}

func rawValue(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestArvanVerifyAndAuthHeader(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")

	ident, err := m.client().VerifyCredentials(context.Background())
	requireNoError(t, err)
	requireContains(t, ident.Detail, "1 domain", "identity detail")
	if m.AuthHeader != "Apikey secret-key" {
		t.Fatalf("expected the Apikey prefix to be added, got %q", m.AuthHeader)
	}
}

// Operators paste the key with and without the prefix; both must work.
func TestArvanAcceptsPrefixedKey(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	c := m.client()
	c.APIKey = "Apikey secret-key"

	_, err := c.ListZones(context.Background())
	requireNoError(t, err)
	if m.AuthHeader != "Apikey secret-key" {
		t.Fatalf("expected the prefix not to be doubled, got %q", m.AuthHeader)
	}
}

func TestArvanRecordCRUDConvertsValueObject(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	c := m.client()
	ctx := context.Background()

	created, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 120, Proxied: true,
	})
	requireNoError(t, err)
	if created.Name != "ws.example.com" {
		t.Fatalf("expected the sub-name to be re-qualified, got %q", created.Name)
	}
	if !created.Proxied {
		t.Fatal("expected the Arvan cloud flag to map to Proxied")
	}
	// Arvan stores the sub-name only and the value as [{ip}].
	m.mu.Lock()
	stored := m.Records["example.com"][0]
	m.mu.Unlock()
	if stored.Name != "ws" {
		t.Fatalf("expected the stored sub-name to be relative, got %q", stored.Name)
	}
	requireContains(t, string(stored.Value), `"ip":"203.0.113.10"`, "stored value object")

	list, err := c.ListRecords(ctx, "example.com", RecordFilter{Type: TypeA, Name: "ws.example.com"})
	requireNoError(t, err)
	if len(list) != 1 || list[0].Content != "203.0.113.10" {
		t.Fatalf("unexpected list: %+v", list)
	}

	updated, err := c.UpdateRecord(ctx, "example.com", created.ID, Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.99", TTL: 120,
	})
	requireNoError(t, err)
	if updated.Content != "203.0.113.99" {
		t.Fatalf("unexpected update: %+v", updated)
	}

	requireNoError(t, c.DeleteRecord(ctx, "example.com", created.ID))
	list, err = c.ListRecords(ctx, "example.com", RecordFilter{})
	requireNoError(t, err)
	if len(list) != 0 {
		t.Fatalf("expected the record to be gone, got %+v", list)
	}
}

func TestArvanApexUsesAtSign(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	_, err := m.client().CreateRecord(context.Background(), "example.com", Record{
		Type: TypeA, Name: "example.com", Content: "203.0.113.10",
	})
	requireNoError(t, err)
	m.mu.Lock()
	stored := m.Records["example.com"][0]
	m.mu.Unlock()
	if stored.Name != "@" {
		t.Fatalf("expected the apex to be stored as @, got %q", stored.Name)
	}
}

func TestArvanDecodesEveryValueShape(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	m.mu.Lock()
	m.Records["example.com"] = []arvanRecord{
		{ID: "a1", Type: "a", Name: "ws", Value: rawValue(t, []map[string]string{{"ip": "203.0.113.10"}}), TTL: 120, Cloud: true},
		{ID: "c1", Type: "cname", Name: "cdn", Value: rawValue(t, map[string]string{"host": "edge.example.net"}), TTL: 120},
		{ID: "t1", Type: "txt", Name: "_acme-challenge", Value: rawValue(t, map[string]string{"text": "token-value"}), TTL: 120},
		{ID: "s1", Type: "srv", Name: "_grpc._tcp", Value: rawValue(t, map[string]any{"host": "edge.example.com", "port": 443, "priority": 10, "weight": 5}), TTL: 120},
		{ID: "n1", Type: "ns", Name: "sub", Value: rawValue(t, map[string]string{"host": "ns1.other.net"}), TTL: 3600},
	}
	m.mu.Unlock()

	recs, err := m.client().ListRecords(context.Background(), "example.com", RecordFilter{})
	requireNoError(t, err)
	if len(recs) != 5 {
		t.Fatalf("expected 5 records, got %d", len(recs))
	}
	byName := map[string]Record{}
	for _, r := range recs {
		byName[r.Name] = r
	}
	if got := byName["ws.example.com"]; got.Content != "203.0.113.10" || !got.Proxied {
		t.Fatalf("A record decoded wrong: %+v", got)
	}
	if got := byName["cdn.example.com"]; got.Content != "edge.example.net" {
		t.Fatalf("CNAME decoded wrong: %+v", got)
	}
	if got := byName["_acme-challenge.example.com"]; got.Content != "token-value" {
		t.Fatalf("TXT decoded wrong: %+v", got)
	}
	srv := byName["_grpc._tcp.example.com"]
	if srv.SRV == nil || srv.SRV.Port != 443 || srv.SRV.Priority != 10 || srv.SRV.Weight != 5 {
		t.Fatalf("SRV decoded wrong: %+v", srv.SRV)
	}
	if got := byName["sub.example.com"]; got.Content != "ns1.other.net" {
		t.Fatalf("NS decoded wrong: %+v", got)
	}
}

func TestArvanSetProxiedTogglesCloudFlag(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	c := m.client()
	ctx := context.Background()
	created, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10",
	})
	requireNoError(t, err)
	if created.Proxied {
		t.Fatal("expected the record to start un-proxied")
	}
	updated, err := c.SetProxied(ctx, "example.com", created.ID, true)
	requireNoError(t, err)
	if !updated.Proxied {
		t.Fatalf("expected the cloud flag to be set, got %+v", updated)
	}
}

func TestArvanErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		message string
		want    Kind
		needle  string
	}{
		{"unauthorized", http.StatusUnauthorized, "Unauthenticated.", KindAuth, "machine-user key"},
		{"forbidden", http.StatusForbidden, "This action is unauthorized.", KindPermission, "grant the machine user access"},
		{"not found", http.StatusNotFound, "Domain not found", KindNotFound, "ArvanCloud CDN panel"},
		{"validation", http.StatusUnprocessableEntity, "The given data was invalid.", KindValidation, "a → IPv4"},
		{"rate limit", http.StatusTooManyRequests, "Too Many Attempts.", KindRateLimit, "--bulk-count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newArvanMock(t)
			m.addDomain("example.com")
			m.Status["GET /domains"] = tc.status
			m.Message["GET /domains"] = tc.message
			_, err := m.client().ListZones(context.Background())
			e := requireKind(t, err, tc.want)
			requireContains(t, e.Remediation, tc.needle, tc.name+" remediation")
		})
	}
}

func TestArvanForbiddenNamesTheScope(t *testing.T) {
	m := newArvanMock(t)
	m.addDomain("example.com")
	m.Status["GET /domains"] = http.StatusForbidden
	m.Message["GET /domains"] = "This action is unauthorized."
	_, err := m.client().ListZones(context.Background())
	e := requireKind(t, err, KindPermission)
	if e.MissingScope == "" {
		t.Fatal("expected the missing scope to be named")
	}
}

func TestNewArvanRequiresKey(t *testing.T) {
	_, err := NewArvan(Credentials{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "api_key", "missing credential message")
}
