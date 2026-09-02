package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// cfMock replays the real api.cloudflare.com/client/v4 response shapes,
// envelope and all, so the client is exercised against the wire format it will
// actually meet rather than a convenient fiction.
type cfMock struct {
	mu sync.Mutex
	// Zones by id.
	Zones map[string]cfZone
	// Records by zone id then record id.
	Records map[string]map[string]cfRecord
	// Settings by zone id then setting id.
	Settings map[string]map[string]string
	// Deny maps "METHOD /path-prefix" to the error the mock returns, which is
	// how the scope-specific permission tests are driven.
	Deny map[string]cfMessage
	// DenyStatus is the HTTP status paired with Deny; defaults to 403.
	DenyStatus map[string]int
	// TokenStatus is the status the verify endpoint reports.
	TokenStatus string
	// AccountID, when set, is the only account id the verify endpoint accepts.
	AccountID string
	// Requests records every path hit, for assertions about pagination.
	Requests []string
	// PageSize forces pagination in zone/record listings.
	PageSize int
	nextID   int
	server   *httptest.Server
}

func newCFMock(t *testing.T) *cfMock {
	t.Helper()
	m := &cfMock{
		Zones: map[string]cfZone{}, Records: map[string]map[string]cfRecord{},
		Settings: map[string]map[string]string{}, Deny: map[string]cfMessage{},
		DenyStatus: map[string]int{}, TokenStatus: "active", PageSize: 50,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

// client returns a Cloudflare provider pointed at the mock with retries and
// sleeps disabled so tests stay fast and deterministic.
func (m *cfMock) client() *Cloudflare {
	return &Cloudflare{
		Token: "test-token", BaseURL: m.server.URL + "/client/v4",
		HTTP: m.server.Client(), MaxRetries: 1, Sleep: func(time.Duration) {},
	}
}

func (m *cfMock) addZone(id, name, status string, ns ...string) cfZone {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(ns) == 0 {
		ns = []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	}
	z := cfZone{ID: id, Name: name, Status: status, NameServers: ns}
	m.Zones[id] = z
	if m.Records[id] == nil {
		m.Records[id] = map[string]cfRecord{}
	}
	if m.Settings[id] == nil {
		m.Settings[id] = map[string]string{
			"ssl": "flexible", "always_use_https": "off", "min_tls_version": "1.0",
			"tls_1_3": "off", "grpc": "off", "websockets": "off",
		}
	}
	return z
}

func (m *cfMock) denied(method, path string) (cfMessage, int, bool) {
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
	return cfMessage{}, 0, false
}

func (m *cfMock) writeEnvelope(w http.ResponseWriter, status int, result any, info *cfResultInfo, errs ...cfMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	raw, _ := json.Marshal(result)
	if result == nil {
		raw = []byte("null")
	}
	env := map[string]any{
		"success": len(errs) == 0, "errors": errs, "messages": []cfMessage{},
		"result": json.RawMessage(raw),
	}
	if info != nil {
		env["result_info"] = info
	}
	_ = json.NewEncoder(w).Encode(env)
}

func (m *cfMock) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	m.mu.Lock()
	m.Requests = append(m.Requests, r.Method+" "+path+"?"+r.URL.RawQuery)
	deny := m.Deny
	_ = deny
	m.mu.Unlock()

	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		m.writeEnvelope(w, http.StatusUnauthorized, nil, nil,
			cfMessage{Code: 10000, Message: "Authentication error"})
		return
	}
	m.mu.Lock()
	msg, status, isDenied := m.denied(r.Method, path)
	m.mu.Unlock()
	if isDenied {
		m.writeEnvelope(w, status, nil, nil, msg)
		return
	}

	switch {
	case path == "/user/tokens/verify":
		m.handleVerify(w, "")
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/tokens/verify"):
		account := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/tokens/verify")
		m.handleVerify(w, account)
	case path == "/zones":
		m.handleListZones(w, r)
	case strings.HasPrefix(path, "/zones/") && strings.Contains(path, "/dns_records"):
		m.handleRecords(w, r, path)
	case strings.HasPrefix(path, "/zones/") && strings.Contains(path, "/settings/"):
		m.handleSettings(w, r, path)
	default:
		m.writeEnvelope(w, http.StatusNotFound, nil, nil,
			cfMessage{Code: 7003, Message: "Could not route to " + path + ", perhaps your object identifier is invalid?"})
	}
}

func (m *cfMock) handleVerify(w http.ResponseWriter, account string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if account != "" && m.AccountID != "" && account != m.AccountID {
		m.writeEnvelope(w, http.StatusNotFound, nil, nil,
			cfMessage{Code: 7003, Message: "Could not route to /accounts/" + account + "/tokens/verify, perhaps your object identifier is invalid?"})
		return
	}
	m.writeEnvelope(w, http.StatusOK, map[string]any{
		"id": "tok-123", "status": m.TokenStatus, "not_before": "2026-01-01T00:00:00Z",
		"expires_on": "2027-01-01T00:00:00Z",
	}, nil)
}

func (m *cfMock) handleListZones(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := NormalizeDomain(r.URL.Query().Get("name"))
	var all []cfZone
	for _, z := range m.Zones {
		if name != "" && NormalizeDomain(z.Name) != name {
			continue
		}
		all = append(all, z)
	}
	// Stable order so pagination assertions mean something.
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].Name < all[j-1].Name; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	page, perPage := pageParams(r, m.PageSize)
	slice, info := paginate(len(all), page, perPage)
	out := make([]cfZone, 0)
	for _, i := range slice {
		out = append(out, all[i])
	}
	m.writeEnvelope(w, http.StatusOK, out, info)
}

func (m *cfMock) handleRecords(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, "/zones/")
	parts := strings.SplitN(rest, "/", 3)
	zoneID := parts[0]
	recordID := ""
	if len(parts) == 3 {
		recordID = parts[2]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Zones[zoneID]; !ok {
		m.writeEnvelope(w, http.StatusNotFound, nil, nil,
			cfMessage{Code: 1003, Message: "Invalid or missing zone id."})
		return
	}

	switch r.Method {
	case http.MethodGet:
		if recordID != "" {
			rec, ok := m.Records[zoneID][recordID]
			if !ok {
				m.writeEnvelope(w, http.StatusNotFound, nil, nil,
					cfMessage{Code: 81044, Message: "Record does not exist."})
				return
			}
			m.writeEnvelope(w, http.StatusOK, rec, nil)
			return
		}
		wantType := strings.ToUpper(r.URL.Query().Get("type"))
		wantName := NormalizeDomain(r.URL.Query().Get("name"))
		var all []cfRecord
		for _, rec := range m.Records[zoneID] {
			if wantType != "" && strings.ToUpper(rec.Type) != wantType {
				continue
			}
			if wantName != "" && NormalizeDomain(rec.Name) != wantName {
				continue
			}
			all = append(all, rec)
		}
		for i := 1; i < len(all); i++ {
			for j := i; j > 0 && all[j].ID < all[j-1].ID; j-- {
				all[j], all[j-1] = all[j-1], all[j]
			}
		}
		page, perPage := pageParams(r, m.PageSize)
		slice, info := paginate(len(all), page, perPage)
		out := make([]cfRecord, 0)
		for _, i := range slice {
			out = append(out, all[i])
		}
		m.writeEnvelope(w, http.StatusOK, out, info)

	case http.MethodPost:
		var body cfRecord
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			m.writeEnvelope(w, http.StatusBadRequest, nil, nil,
				cfMessage{Code: 1004, Message: "DNS Validation Error"})
			return
		}
		for _, existing := range m.Records[zoneID] {
			if NormalizeDomain(existing.Name) == NormalizeDomain(body.Name) &&
				strings.EqualFold(existing.Type, body.Type) {
				m.writeEnvelope(w, http.StatusBadRequest, nil, nil,
					cfMessage{Code: 81053, Message: "An A, AAAA, or CNAME record with that host already exists."})
				return
			}
		}
		m.nextID++
		body.ID = fmt.Sprintf("rec%03d", m.nextID)
		if m.Records[zoneID] == nil {
			m.Records[zoneID] = map[string]cfRecord{}
		}
		m.Records[zoneID][body.ID] = body
		m.writeEnvelope(w, http.StatusOK, body, nil)

	case http.MethodPut, http.MethodPatch:
		if _, ok := m.Records[zoneID][recordID]; !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil, nil,
				cfMessage{Code: 81044, Message: "Record does not exist."})
			return
		}
		var body cfRecord
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			m.writeEnvelope(w, http.StatusBadRequest, nil, nil,
				cfMessage{Code: 1004, Message: "DNS Validation Error"})
			return
		}
		body.ID = recordID
		m.Records[zoneID][recordID] = body
		m.writeEnvelope(w, http.StatusOK, body, nil)

	case http.MethodDelete:
		if _, ok := m.Records[zoneID][recordID]; !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil, nil,
				cfMessage{Code: 81044, Message: "Record does not exist."})
			return
		}
		delete(m.Records[zoneID], recordID)
		m.writeEnvelope(w, http.StatusOK, map[string]string{"id": recordID}, nil)
	}
}

func (m *cfMock) handleSettings(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, "/zones/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 {
		m.writeEnvelope(w, http.StatusNotFound, nil, nil, cfMessage{Code: 7003, Message: "Could not route"})
		return
	}
	zoneID, setting := parts[0], parts[2]
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Zones[zoneID]; !ok {
		m.writeEnvelope(w, http.StatusNotFound, nil, nil, cfMessage{Code: 1003, Message: "Invalid or missing zone id."})
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, ok := m.Settings[zoneID][setting]
		if !ok {
			m.writeEnvelope(w, http.StatusNotFound, nil, nil,
				cfMessage{Code: 1006, Message: "Unable to find setting " + setting})
			return
		}
		m.writeEnvelope(w, http.StatusOK, map[string]any{"id": setting, "value": value, "editable": true}, nil)
	case http.MethodPatch:
		var body struct {
			Value any `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			m.writeEnvelope(w, http.StatusBadRequest, nil, nil, cfMessage{Code: 1004, Message: "Invalid value"})
			return
		}
		value := fmt.Sprint(body.Value)
		m.Settings[zoneID][setting] = value
		m.writeEnvelope(w, http.StatusOK, map[string]any{"id": setting, "value": value, "editable": true}, nil)
	}
}

func pageParams(r *http.Request, defaultPerPage int) (page, perPage int) {
	page, perPage = 1, defaultPerPage
	if v := r.URL.Query().Get("page"); v != "" {
		fmt.Sscanf(v, "%d", &page)
	}
	if perPage <= 0 {
		perPage = 50
	}
	if page <= 0 {
		page = 1
	}
	return page, perPage
}

func paginate(total, page, perPage int) ([]int, *cfResultInfo) {
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	idx := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		idx = append(idx, i)
	}
	return idx, &cfResultInfo{
		Page: page, PerPage: perPage, Count: len(idx),
		TotalCount: total, TotalPages: totalPages,
	}
}

// ---------------------------------------------------------------------------
// TLS test listener
