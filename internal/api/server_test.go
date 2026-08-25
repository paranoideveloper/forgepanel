package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	return New(&config.Config{PanelPort: 0, AdminPath: "/panel/test"})
}

func TestPreviewEndToEnd(t *testing.T) {
	s := testServer(t)
	body := `{"protocol":"vless","address":"1.2.3.4","port":443,
	  "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","remark":"t",
	  "transport":{"network":"tcp"},
	  "security":{"type":"reality","server_name":"www.microsoft.com","fingerprint":"chrome",
	    "reality":{"public_key":"AQ2Zr9m0Xr8s7t6u5v4w3x2y1z0aBcDeFgHiJkLmNo","short_id":"0123abcd"}}}`
	req := httptest.NewRequest(http.MethodPost, "/api/studio/preview", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var pr PreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatal(err)
	}
	if !pr.OK {
		t.Fatalf("preview not ok: %+v", pr.Errors)
	}
	if !strings.HasPrefix(pr.URI, "vless://") {
		t.Fatalf("bad uri: %q", pr.URI)
	}
	// The generated engine configs must be valid JSON and mention the protocol.
	for name, cfg := range map[string]string{"xray": pr.Xray, "singbox": pr.Singbox} {
		var v any
		if err := json.Unmarshal([]byte(cfg), &v); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
		if !strings.Contains(cfg, "vless") {
			t.Fatalf("%s does not mention vless", name)
		}
	}
	if !strings.Contains(pr.Clash, "reality-opts") {
		t.Fatalf("clash missing reality-opts: %s", pr.Clash)
	}
}

func TestProtocolsEndpoint(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/protocols", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var protos []protoMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &protos); err != nil {
		t.Fatal(err)
	}
	// Derived from the model rather than hardcoded: this assertion previously
	// pinned "14", which silently locked AmneziaWG out of the endpoint and made
	// adding any protocol a test failure in an unrelated package.
	if want := len(model.AllProtocols()); len(protos) != want {
		t.Fatalf("expected %d protocols (model.AllProtocols), got %d", want, len(protos))
	}
	// Every advertised protocol must carry an engine, or the UI shows a picker
	// entry that cannot be served.
	for _, p := range protos {
		if p.Engine == "" || p.Engine == model.EngineUnknown {
			t.Errorf("protocol %q advertised with engine %q", p.Proto, p.Engine)
		}
	}
}

func TestKeygenEndpoint(t *testing.T) {
	s := testServer(t)
	for _, kind := range []string{"reality", "uuid", "wireguard", "ssh", "shortid"} {
		req := httptest.NewRequest(http.MethodPost, "/api/keygen", strings.NewReader(`{"kind":"`+kind+`"}`))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("keygen %s: status %d: %s", kind, rec.Code, rec.Body.String())
		}
	}
}

func TestImportEndpoint(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/import",
		strings.NewReader(`{"text":"vless://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?type=ws&security=tls&sni=a.com#one"}`))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Count != 1 {
		t.Fatalf("expected 1 imported node, got %d", out.Count)
	}
}
