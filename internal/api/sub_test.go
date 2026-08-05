package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// subServer builds a DB-backed server with one user bound to one enabled inbound,
// and returns it with the user's subscription token.
func subServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := dbServerT(t)

	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "sub-test",
	}
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "g1", InboundIDs: []uint{in.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "alice", GroupID: g.ID, SubToken: "subtok123456",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)
	s.router = r
	return s, u.SubToken
}

func subGet(t *testing.T, s *Server, path, ua string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

// TestSubResponsesAreNotCacheable is the headline regression for §3's caching
// requirement: the body varies on the User-Agent while the URL stays constant, so
// without Vary and no-store an intermediate cache can hand one subscriber's
// config — and therefore their credentials — to a different subscriber.
func TestSubResponsesAreNotCacheable(t *testing.T) {
	s, tok := subServer(t)

	for _, path := range []string{
		"/sub/" + tok,
		"/sub/" + tok + "/clash",
		"/sub/" + tok + "/sing-box",
		"/sub/" + tok + "/links",
		"/sub/" + tok + "/json",
	} {
		rec := subGet(t, s, path, "curl/8")
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		vary := rec.Header().Get("Vary")
		if !strings.Contains(strings.ToLower(vary), "user-agent") {
			t.Errorf("%s: Vary=%q, must include User-Agent", path, vary)
		}
		cc := strings.ToLower(rec.Header().Get("Cache-Control"))
		if !strings.Contains(cc, "no-store") {
			t.Errorf("%s: Cache-Control=%q, must include no-store", path, cc)
		}
	}
}

// TestSingboxUserAgentGetsSingboxJSON: the format that used to fall through to
// base64 V2Ray output.
func TestSingboxUserAgentGetsSingboxJSON(t *testing.T) {
	s, tok := subServer(t)
	rec := subGet(t, s, "/sub/"+tok, "sing-box/1.13.15")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type=%q, want application/json", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, ok := doc["outbounds"]; !ok {
		t.Fatalf("sing-box config has no outbounds: %s", rec.Body.String())
	}
}

// TestSingboxAliases covers sing-box / singbox / sb.
func TestSingboxAliases(t *testing.T) {
	s, tok := subServer(t)
	for _, alias := range []string{"sing-box", "singbox", "sb"} {
		rec := subGet(t, s, "/sub/"+tok+"/"+alias, "")
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", alias, rec.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: not JSON: %v", alias, err)
		}
	}
}

// TestExplicitFormatBeatsUserAgent: an explicit path must win over sniffing.
func TestExplicitFormatBeatsUserAgent(t *testing.T) {
	s, tok := subServer(t)
	rec := subGet(t, s, "/sub/"+tok+"/clash", "sing-box/1.13.15")
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Fatalf("explicit /clash with a sing-box UA returned %q", ct)
	}
}

// TestUnsupportedExplicitFormatIsAnError: asking for a format we do not have must
// say so, not silently hand back a different one the client cannot read.
func TestUnsupportedExplicitFormatIsAnError(t *testing.T) {
	s, tok := subServer(t)
	rec := subGet(t, s, "/sub/"+tok+"/quantumult", "")
	if rec.Code == 200 {
		t.Fatalf("unsupported format silently served %d bytes of another format: %s",
			rec.Body.Len(), rec.Body.String())
	}
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported format: status %d, want 400 or 404", rec.Code)
	}
}

// TestUnknownUserAgentStillFallsBack: sniffing keeps its default.
func TestUnknownUserAgentStillFallsBack(t *testing.T) {
	s, tok := subServer(t)
	rec := subGet(t, s, "/sub/"+tok, "SomeBrandNewClient/1.0")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String())); err != nil {
		t.Fatalf("fallback is not base64 V2Ray output: %v", err)
	}
}

// TestExistingFormatsUnchanged pins the other renderers.
func TestExistingFormatsUnchanged(t *testing.T) {
	s, tok := subServer(t)
	for _, tc := range []struct{ path, wantCT string }{
		{"/sub/" + tok + "/clash", "yaml"},
		{"/sub/" + tok + "/links", "text/plain"},
		{"/sub/" + tok + "/json", "application/json"},
	} {
		rec := subGet(t, s, tc.path, "")
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", tc.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.wantCT) {
			t.Fatalf("%s: Content-Type=%q want %q", tc.path, ct, tc.wantCT)
		}
	}
}

// TestSubTokenGuessingIsRateLimited: subscription tokens are bearer credentials
// on an unauthenticated endpoint, so blind guessing must not be free.
func TestSubTokenGuessingIsRateLimited(t *testing.T) {
	s, _ := subServer(t)

	blocked := false
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/wrongtoken"+string(rune('a'+i%26)), nil)
		req.RemoteAddr = "198.51.100.44:5555"
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("unlimited subscription-token guesses were allowed")
	}
}

// TestValidTokenNotBlockedByAnotherSourcesGuessing: one abusive IP must not lock
// out a legitimate subscriber.
func TestValidTokenNotBlockedByAnotherSourcesGuessing(t *testing.T) {
	s, tok := subServer(t)
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/bogus"+string(rune('a'+i%26)), nil)
		req.RemoteAddr = "198.51.100.77:5555"
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
	}
	req := httptest.NewRequest(http.MethodGet, "/sub/"+tok, nil)
	req.RemoteAddr = "203.0.113.200:5555"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("legitimate subscriber got %d after another source was throttled", rec.Code)
	}
}


func TestMultiLocationSubscriptionLinks(t *testing.T) {
	s := dbServerT(t)

	n1 := &store.Node{Name: "us-east", Address: "useast.vpn.com", EnrollToken: "tok-useast", Enrolled: true}
	if err := s.db.CreateNode(n1); err != nil {
		t.Fatal(err)
	}

	n2 := &store.Node{Name: "eu-west", Address: "euwest.vpn.com", EnrollToken: "tok-euwest", Enrolled: true}
	if err := s.db.CreateNode(n2); err != nil {
		t.Fatal(err)
	}

	spec1 := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Remark: "US-Node", Address: "0.0.0.0", UUID: "11111111-1111-1111-1111-111111111111"}
	ib1, err := s.db.CreateInbound(spec1)
	if err != nil {
		t.Fatal(err)
	}
	ib1.NodeID = n1.ID
	if err := s.db.SaveInbound(ib1); err != nil {
		t.Fatal(err)
	}

	spec2 := &model.Node{Protocol: model.ProtoVLESS, Port: 8443, Remark: "EU-Node", Address: "0.0.0.0", UUID: "11111111-1111-1111-1111-111111111111"}
	ib2, err := s.db.CreateInbound(spec2)
	if err != nil {
		t.Fatal(err)
	}
	ib2.NodeID = n2.ID
	if err := s.db.SaveInbound(ib2); err != nil {
		t.Fatal(err)
	}

	g := &store.Group{Name: "multinode-g", InboundIDs: []uint{ib1.ID, ib2.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}

	u := &store.User{Username: "bob", GroupID: g.ID, SubToken: "multitok123", UUID: "11111111-1111-1111-1111-111111111111", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)
	s.router = r

	// Links
	rec := subGet(t, s, "/sub/multitok123/links", "")
	if rec.Code != 200 {
		t.Fatalf("expected 200 for links, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "@useast.vpn.com:443") || !strings.Contains(body, "@euwest.vpn.com:8443") {
		t.Fatalf("links format missing multi-node hostnames: %s", body)
	}

	// Clash
	rec = subGet(t, s, "/sub/multitok123/clash", "")
	if rec.Code != 200 {
		t.Fatalf("expected 200 for clash, got %d", rec.Code)
	}
	cbody := rec.Body.String()
	if !strings.Contains(cbody, "server: useast.vpn.com") || !strings.Contains(cbody, "server: euwest.vpn.com") {
		t.Fatalf("clash format missing multi-node hostnames: %s", cbody)
	}

	// JSON
	rec = subGet(t, s, "/sub/multitok123/json", "")
	if rec.Code != 200 {
		t.Fatalf("expected 200 for json, got %d", rec.Code)
	}
	var jsonNodes []*model.Node
	if err := json.Unmarshal(rec.Body.Bytes(), &jsonNodes); err != nil {
		t.Fatalf("failed to parse json sub response: %v", err)
	}
	if len(jsonNodes) != 2 {
		t.Fatalf("expected 2 nodes in json sub, got %d", len(jsonNodes))
	}
	hosts := map[string]bool{}
	for _, jn := range jsonNodes {
		hosts[jn.Address] = true
	}
	if !hosts["useast.vpn.com"] || !hosts["euwest.vpn.com"] {
		t.Fatalf("json sub missing multi-node addresses: %v", hosts)
	}
}
