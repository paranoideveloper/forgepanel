package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
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
	rec := subGet(t, s, "/sub/"+tok+"/nonexistentformat", "")
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

// TestSingboxSubscriptionHasUniqueTags is the regression for the "duplicate
// outbound/endpoint tag: proxy" bug: the per-node renderings all default their
// tag to "proxy", and the builder also emits a selector tagged "proxy" and a
// direct tagged "direct". Every emitted tag must be unique or the real sing-box
// core rejects the whole config.
func TestSingboxSubscriptionHasUniqueTags(t *testing.T) {
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoTrojan, Address: "b.example.com", Port: 443, Password: "pw1"},
		{Protocol: model.ProtoShadowsocks, Address: "c.example.com", Port: 443, Password: "pw2", Method: "2022-blake3-aes-128-gcm"},
		{Protocol: model.ProtoVMess, Address: "d.example.com", Port: 443, UUID: "66666666-7777-8888-9999-000000000000"},
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(singboxSubscription(nodes, routing.Options{}, routing.Fragment{}), &doc); err != nil {
		t.Fatalf("subscription is not valid JSON: %v", err)
	}
	seen := map[string]bool{}
	var selector map[string]any
	for _, o := range doc.Outbounds {
		tag, _ := o["tag"].(string)
		if tag == "" {
			t.Fatalf("outbound with empty tag: %v", o)
		}
		if seen[tag] {
			t.Fatalf("duplicate outbound tag %q — the real core rejects this", tag)
		}
		seen[tag] = true
		if o["type"] == "selector" {
			selector = o
		}
	}
	if selector == nil {
		t.Fatal("no selector outbound emitted")
	}
	// The selector must reference only tags that exist.
	for _, ref := range selector["outbounds"].([]any) {
		if !seen[ref.(string)] {
			t.Fatalf("selector references non-existent tag %q", ref)
		}
	}
}

// TestSingboxSubscriptionAcceptedByCore feeds the emitted subscription to the
// real `sing-box check`, the only authority on whether the config is valid. It
// skips cleanly when the binary is not installed, so CI without sing-box still
// passes while a machine that has it gets the real proof.
func TestSingboxSubscriptionAcceptedByCore(t *testing.T) {
	bin := findSingbox()
	if bin == "" {
		t.Skip("sing-box binary not found; skipping semantic validation")
	}
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoTrojan, Address: "b.example.com", Port: 443, Password: "pw1"},
		{Protocol: model.ProtoVMess, Address: "d.example.com", Port: 443, UUID: "66666666-7777-8888-9999-000000000000"},
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub.json")
	if err := os.WriteFile(cfg, singboxSubscription(nodes, routing.Options{}, routing.Fragment{}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box rejected the subscription: %v\n%s", err, out)
	}
}

// TestSingboxSubscriptionWithRoutingAcceptedByCore proves the routing preset
// (bypass Iran, block ads/malware/porn, block QUIC, direct LAN — rules AND remote
// rule-sets) produces a config the real sing-box core accepts.
func TestSingboxSubscriptionWithRoutingAcceptedByCore(t *testing.T) {
	bin := findSingbox()
	if bin == "" {
		t.Skip("sing-box binary not found; skipping semantic validation")
	}
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoTrojan, Address: "b.example.com", Port: 443, Password: "pw1"},
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub-routed.json")
	if err := os.WriteFile(cfg, singboxSubscription(nodes, routing.Preset("full"), routing.Fragment{}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box rejected the routed subscription: %v\n%s", err, out)
	}
}

// TestXraySubscriptionWithRoutingAcceptedByCore is the same proof for Xray.
func TestXraySubscriptionWithRoutingAcceptedByCore(t *testing.T) {
	bin := findXray()
	if bin == "" {
		t.Skip("xray binary not found; skipping semantic validation")
	}
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoTrojan, Address: "c.example.com", Port: 443, Password: "pw"},
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "xray-routed.json")
	if err := os.WriteFile(cfg, xraySubscription(nodes, routing.Preset("full"), routing.Fragment{Enabled: true, Packets: "tlshello", Length: "100-200", Interval: "10-20"}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("xray rejected the routed config: %v\n%s", err, out)
	}
}

// TestXraySubscriptionWithFragmentAcceptedByCore proves the TLS-fragment DPI
// evasion (dialerProxy → freedom fragment outbound) yields a config the real Xray
// core accepts, and that every proxy dials through the fragment outbound.
func TestXraySubscriptionWithFragmentAcceptedByCore(t *testing.T) {
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoTrojan, Address: "c.example.com", Port: 443, Password: "pw"},
	}
	frag := routing.Fragment{Enabled: true, Packets: "tlshello", Length: "100-200", Interval: "10-20"}
	raw := xraySubscription(nodes, routing.Options{}, frag)

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	var hasFragment, dialers int
	for _, o := range doc.Outbounds {
		if o["tag"] == "fragment" {
			hasFragment++
		}
		if ss, ok := o["streamSettings"].(map[string]any); ok {
			if sock, ok := ss["sockopt"].(map[string]any); ok && sock["dialerProxy"] == "fragment" {
				dialers++
			}
		}
	}
	if hasFragment != 1 {
		t.Fatalf("expected exactly one fragment outbound, got %d", hasFragment)
	}
	if dialers != 2 {
		t.Fatalf("expected both proxies to dial through fragment, got %d", dialers)
	}

	bin := findXray()
	if bin == "" {
		t.Skip("xray binary not found; skipping semantic validation")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "xray-frag.json")
	if err := os.WriteFile(cfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("xray rejected the fragmented config: %v\n%s", err, out)
	}
}

// TestFragmentFromQuery covers the query parsing + defaults.
func TestFragmentFromQuery(t *testing.T) {
	off := routing.FragmentFromQuery(nil, routing.Fragment{})
	if off.Enabled {
		t.Fatal("fragment should be off by default")
	}
	q := make(map[string][]string)
	q["fragment"] = []string{"1"}
	q["fragment_length"] = []string{"40-80"}
	on := routing.FragmentFromQuery(q, routing.FragmentPreset("medium"))
	if !on.Enabled || on.Length != "40-80" || on.Packets != "tlshello" {
		t.Fatalf("fragment query parse wrong: %+v", on)
	}
}

// TestClashWithRoutingShape checks the routing preset is spliced into the Clash
// document correctly: a rule-providers block, the preset rules before the single
// catch-all MATCH, and no duplicate rules: key.
func TestClashWithRoutingShape(t *testing.T) {
	nodes := []*model.Node{{Protocol: model.ProtoTrojan, Address: "a.example.com", Port: 443, Password: "pw"}}
	base, err := export.ClashYAML(nodes)
	if err != nil {
		t.Fatal(err)
	}
	out := clashWithRouting(base, routing.Preset("full"))
	if strings.Count(out, "\nrules:\n") != 1 {
		t.Fatalf("expected exactly one rules: block, got:\n%s", out)
	}
	if !strings.Contains(out, "rule-providers:") {
		t.Fatal("missing rule-providers block")
	}
	if !strings.Contains(out, "RULE-SET,ir-domains,DIRECT") {
		t.Fatal("missing Iran direct rule")
	}
	// The catch-all MATCH must appear exactly once and be the last rule line.
	if strings.Count(out, "MATCH,"+export.ClashProxySelector) != 1 {
		t.Fatalf("expected exactly one MATCH catch-all:\n%s", out)
	}
	idxMatch := strings.LastIndex(out, "MATCH,")
	idxRuleSet := strings.LastIndex(out, "RULE-SET,ir-domains,DIRECT")
	if idxRuleSet > idxMatch {
		t.Fatal("preset rules must come before the catch-all MATCH")
	}
	// Disabled preset returns the base untouched.
	if clashWithRouting(base, routing.Preset("off")) != base {
		t.Fatal("disabled routing must not modify the document")
	}
}

func findSingbox() string {
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/sing-box", "/usr/local/bin/sing-box"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestXraySubscriptionAcceptedByCore feeds the emitted xray client config to the
// real `xray run -test`, the authority on validity. Skips when xray is absent.
func TestXraySubscriptionAcceptedByCore(t *testing.T) {
	bin := findXray()
	if bin == "" {
		t.Skip("xray binary not found; skipping semantic validation")
	}
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoVMess, Address: "b.example.com", Port: 443, UUID: "66666666-7777-8888-9999-000000000000"},
		{Protocol: model.ProtoTrojan, Address: "c.example.com", Port: 443, Password: "pw"},
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(cfg, xraySubscription(nodes, routing.Options{}, routing.Fragment{}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("xray rejected the config: %v\n%s", err, out)
	}
}

// TestXraySubscriptionHasUniqueTags: xray also refuses duplicate outbound tags.
func TestXraySubscriptionHasUniqueTags(t *testing.T) {
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: model.ProtoVMess, Address: "b", Port: 443, UUID: "66666666-7777-8888-9999-000000000000"},
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(xraySubscription(nodes, routing.Options{}, routing.Fragment{}), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	seen := map[string]bool{}
	for _, o := range doc.Outbounds {
		tag, _ := o["tag"].(string)
		if tag == "" || seen[tag] {
			t.Fatalf("empty or duplicate outbound tag %q", tag)
		}
		seen[tag] = true
	}
	if !seen["direct"] || !seen["block"] {
		t.Fatal("missing freedom/blackhole outbounds")
	}
}

// TestSubscriptionUserinfoReflectsDB is the regression for the all-zeros header:
// it must report the user's real used/limit/expire.
func TestSubscriptionUserinfoReflectsDB(t *testing.T) {
	s := dbServerT(t)
	exp := time.Now().Add(48 * time.Hour)
	u := &store.User{
		Username: "quotauser", SubToken: "quotatok123", Status: store.StatusActive,
		UsedTraffic: 5 << 30, DataLimit: 100 << 30, ExpireAt: &exp,
	}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	got := s.subscriptionUserinfo("quotatok123")
	if !strings.Contains(got, "download=5368709120") {
		t.Errorf("used traffic missing from header: %q", got)
	}
	if !strings.Contains(got, "total=107374182400") {
		t.Errorf("data limit missing from header: %q", got)
	}
	if strings.Contains(got, "expire=0") {
		t.Errorf("expiry not reported: %q", got)
	}
}

func findXray() string {
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/local/bin/xray", "/usr/bin/xray"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestSubscriptionNameTemplate: a set naming template rewrites every node's
// remark with the interpolated values (flag from the inbound's country, name,
// protocol …); an unset template leaves the node's own remark untouched.
func TestSubscriptionNameTemplate(t *testing.T) {
	s := dbServerT(t)
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "203.0.113.9", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "Berlin", Country: "DE"}
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "g", InboundIDs: []uint{in.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "bob", GroupID: g.ID, SubToken: "toktoktoktok",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	// No template ⇒ the inbound's own remark is preserved.
	nodes := s.subscriptionNodes(u.SubToken, "vpn.example.com")
	if len(nodes) != 1 || nodes[0].Remark != "Berlin" {
		t.Fatalf("without a template, remark should be untouched: %+v", nodes)
	}

	// With a template ⇒ interpolated, flag included.
	if err := s.db.SetSetting("sub_name_template", "{FLAG} {NAME} · {PROTOCOL}"); err != nil {
		t.Fatal(err)
	}
	nodes = s.subscriptionNodes(u.SubToken, "vpn.example.com")
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	if want := "🇩🇪 Berlin · vless"; nodes[0].Remark != want {
		t.Fatalf("templated remark = %q, want %q", nodes[0].Remark, want)
	}
}

// The header used to hardcode "upload=0" and report the whole total under
// download, because the engine's separate uplink/downlink counters were summed
// before anything could see them. Clients display these two numbers verbatim.
func TestSubscriptionUserinfoReportsBothHalves(t *testing.T) {
	s, _ := adminAPI(t)
	u := &store.User{Username: "hdr", SubToken: "hdrtok", Status: store.StatusActive,
		UsedTraffic: 1000, UploadTraffic: 300, DownloadTraffic: 700, DataLimit: 5000}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	got := s.subscriptionUserinfo("hdrtok")
	if !strings.Contains(got, "upload=300") || !strings.Contains(got, "download=700") {
		t.Fatalf("userinfo = %q, want upload=300 and download=700", got)
	}
}

func TestSubscriptionUserinfoAlwaysSumsToTheBilledTotal(t *testing.T) {
	s, _ := adminAPI(t)
	// A remote node billed 1000 with no split available, so only part of the
	// usage is attributed.
	u := &store.User{Username: "part", SubToken: "parttok", Status: store.StatusActive,
		UsedTraffic: 1000, UploadTraffic: 200, DownloadTraffic: 100, DataLimit: 0}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	got := s.subscriptionUserinfo("parttok")
	// upload + download MUST equal the billed total, because that is what every
	// client shows as "used". Reporting only the attributed halves (200+100)
	// would show the user less usage than they have actually been charged for.
	if !strings.Contains(got, "upload=200") || !strings.Contains(got, "download=800") {
		t.Fatalf("userinfo = %q, want upload=200 and download=800 (the unattributed remainder)", got)
	}
}

// Three settings the subscription renderer reads on EVERY request — expand_sni,
// front_clean_ip and clean_ips — were readable by the renderer and writable only
// by the Preset Wizard, which set two of them as a side effect of applying a
// theme. An operator who had never run the wizard could not reach them at all,
// and one who had could not change them again without running it again.
func TestSubscriptionOutputSettingsRoundTripThroughTheSettingsEndpoint(t *testing.T) {
	s, token := adminAPI(t)

	// The defaults the readers document: expansion on, fronting off.
	code, body := doGET(t, s, "/api/admin/settings/subscription", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	var got struct {
		ExpandSNI    *bool   `json:"expand_sni"`
		FrontCleanIP *bool   `json:"front_clean_ip"`
		CleanIPs     *string `json:"clean_ips"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.ExpandSNI == nil || got.FrontCleanIP == nil || got.CleanIPs == nil {
		t.Fatalf("the settings endpoint does not report the three output settings at all: %s", body)
	}
	if !*got.ExpandSNI {
		t.Error("expand_sni defaults off; the reader documents it as on")
	}
	if *got.FrontCleanIP {
		t.Error("front_clean_ip defaults on; the reader documents it as off")
	}

	// Now change all three and confirm the RENDERER's own accessors see it —
	// asserting on the response alone would pass even if the write went to a
	// key nothing reads.
	code, body = realPost(t, s, "/api/admin/settings/subscription", token, map[string]any{
		"expand_sni": false, "front_clean_ip": true,
		"clean_ips": "104.16.0.1, 104.17.0.1\n104.18.0.1",
	})
	if code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	if s.subExpandSNI() {
		t.Error("subExpandSNI still reports on after being turned off")
	}
	if !s.subFrontCleanIP() {
		t.Error("subFrontCleanIP still reports off after being turned on")
	}
	ips := s.subCleanIPs()
	if len(ips) != 3 || ips[0] != "104.16.0.1" || ips[2] != "104.18.0.1" {
		t.Errorf("subCleanIPs = %v, want the three that were saved", ips)
	}
}

// expand_sni defaults ON and its reader treats anything other than "0" as on, so
// the off case must be written as exactly "0". A boolean stored as "false" would
// read back as ON and the setting would appear not to save.
func TestExpandSNIOffIsStoredAsTheReaderExpects(t *testing.T) {
	s, token := adminAPI(t)
	if code, body := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"expand_sni": false}); code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	if raw := s.db.GetSetting("sub_expand_sni"); raw != "0" {
		t.Fatalf("sub_expand_sni = %q; subExpandSNI reads anything but %q as ON", raw, "0")
	}
	// And back on again, so the control is not one-way.
	if code, _ := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"expand_sni": true}); code != 200 {
		t.Fatal("turning it back on failed")
	}
	if !s.subExpandSNI() {
		t.Error("expand_sni could be turned off but not back on")
	}
}

// A field left out of the request must not be reset. The endpoint takes pointers
// for exactly this reason, and a save from one card must not clear what another
// card set.
func TestAnAbsentOutputSettingIsLeftAlone(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"clean_ips": "104.16.0.1"}); code != 200 {
		t.Fatal("first save failed")
	}
	if code, _ := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"routing_preset": "iran"}); code != 200 {
		t.Fatal("second save failed")
	}
	if ips := s.subCleanIPs(); len(ips) != 1 || ips[0] != "104.16.0.1" {
		t.Errorf("clean IPs = %v; a save that never mentioned them cleared them", ips)
	}
}

// fragServer builds a DB-backed server whose one node carries REALITY, and
// returns it with the user's subscription token.
//
// It deliberately does NOT reuse subServer: that helper's node has a zero
// model.Security, so render.SingboxOutbounds emits no tls object at all and a
// fragmentation assertion would have nothing to bite on. REALITY is what this
// panel mostly emits, and `sing-box check` accepts record_fragment alongside a
// reality block.
func fragServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := dbServerT(t)
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "frag-test",
		Security: model.Security{Type: model.SecReality, ServerName: "www.datadoghq.com",
			Reality: &model.Reality{PublicKey: "cGduOK89ZpWRLbUJzusILckHmnkZvxsrNNVReOIV7lA", ShortID: "aabb"}},
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
		UUID: n.UUID, Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)
	s.router = r
	return s, u.SubToken
}

// singboxFragmentCounts fetches a sing-box subscription and reports how many of
// its outbounds carry a tls object and how many of those are fragmented.
func singboxFragmentCounts(t *testing.T, s *Server, token string) (tlsOuts, fragged int) {
	t.Helper()
	rec := subGet(t, s, "/sub/"+token+"/sing-box", "")
	if rec.Code != 200 {
		t.Fatalf("sub returned %d: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("subscription is not valid JSON: %v", err)
	}
	for _, o := range doc.Outbounds {
		tls, ok := o["tls"].(map[string]any)
		if !ok || tls == nil {
			continue
		}
		tlsOuts++
		if tls["record_fragment"] == true {
			fragged++
		}
	}
	if tlsOuts == 0 {
		t.Fatal("no outbound carries a tls object; the fixture is wrong, not the renderer")
	}
	return tlsOuts, fragged
}

// TestSingboxSubscriptionFragmentsWhenPanelToggleIsOn is the regression for the
// panel's TLS-fragment toggle lying to sing-box subscribers.
//
// The panel presents "TLS Fragment" as a subscription default and the hint under
// it claimed it applied to every generated sing-box / Xray / Clash config. Only
// the Xray renderer ever read it: a sing-box subscriber ticked the box, saved,
// and got a config with no fragmentation whatsoever — no error, no warning, just
// a DPI-evasion feature that was off while the panel said it was on.
func TestSingboxSubscriptionFragmentsWhenPanelToggleIsOn(t *testing.T) {
	s, token := fragServer(t)
	if err := s.knobs().SetAll(map[string]string{"sub_fragment_default": "true"}); err != nil {
		t.Fatal(err)
	}
	tlsOuts, fragged := singboxFragmentCounts(t, s, token)
	if fragged != tlsOuts {
		t.Fatalf("%d of %d TLS outbounds fragmented: the panel's TLS-fragment toggle is on and "+
			"sing-box subscribers still get an unfragmented config", fragged, tlsOuts)
	}

	// And the fragmented document must still be one the real core will run.
	bin := findSingbox()
	if bin == "" {
		return
	}
	rec := subGet(t, s, "/sub/"+token+"/sing-box", "")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub-frag.json")
	if err := os.WriteFile(cfg, rec.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the fragmented subscription: %v\n%s", err, out)
	}
}

// TestFragmentCoreSelectionExcludesTheCoresNotChosen proves the per-core list is
// enforced by BOTH renderers rather than being a preference the panel stores and
// nothing reads. A core the operator has excluded must come out unfragmented
// while the other still fragments — otherwise the checkboxes are decoration.
func TestFragmentCoreSelectionExcludesTheCoresNotChosen(t *testing.T) {
	s, token := fragServer(t)

	xrayHasFragment := func() bool {
		rec := subGet(t, s, "/sub/"+token+"/xray", "")
		if rec.Code != 200 {
			t.Fatalf("xray sub returned %d: %s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("xray subscription is not valid JSON: %v", err)
		}
		for _, o := range doc.Outbounds {
			if o["tag"] == "fragment" {
				return true
			}
		}
		return false
	}

	if err := s.knobs().SetAll(map[string]string{
		"sub_fragment_default": "true", "sub_fragment_cores": "xray"}); err != nil {
		t.Fatal(err)
	}
	if _, fragged := singboxFragmentCounts(t, s, token); fragged != 0 {
		t.Fatalf("sing-box is not in the core list and %d outbounds were fragmented anyway", fragged)
	}
	if !xrayHasFragment() {
		t.Fatal("xray is in the core list and got no fragment outbound")
	}

	if err := s.knobs().SetAll(map[string]string{"sub_fragment_cores": "sing-box"}); err != nil {
		t.Fatal(err)
	}
	tlsOuts, fragged := singboxFragmentCounts(t, s, token)
	if fragged != tlsOuts {
		t.Fatalf("sing-box is the only core listed and only %d of %d TLS outbounds fragmented", fragged, tlsOuts)
	}
	if xrayHasFragment() {
		t.Fatal("xray is not in the core list and got a fragment outbound anyway")
	}
}

// TestFragmentSeverityAndCoresRoundTripThroughTheSettingsEndpoint: the severity
// and the core list are operator settings, so they have to be readable and
// writable through the same endpoint the card uses — and a core that cannot
// fragment has to be refused by name rather than stored and ignored.
func TestFragmentSeverityAndCoresRoundTripThroughTheSettingsEndpoint(t *testing.T) {
	s, token := adminAPI(t)

	code, body := doGET(t, s, "/api/admin/settings/subscription", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	var got struct {
		FragmentLevel  *string  `json:"fragment_level"`
		FragmentLevels []string `json:"fragment_levels"`
		FragmentCores  *string  `json:"fragment_cores"`
		Supported      []string `json:"fragment_cores_supported"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.FragmentLevel == nil || got.FragmentCores == nil {
		t.Fatalf("the settings endpoint does not report the fragment severity or core list: %s", body)
	}
	if *got.FragmentLevel != "medium" {
		t.Errorf("fragment_level defaults to %q; medium is the shipped behaviour", *got.FragmentLevel)
	}
	if len(got.FragmentLevels) != 3 {
		t.Errorf("fragment_levels = %v, want the three the validator accepts", got.FragmentLevels)
	}
	// Clash must not be offered: mihomo cannot fragment.
	if len(got.Supported) != 2 || got.Supported[0] != "xray" || got.Supported[1] != "sing-box" {
		t.Errorf("fragment_cores_supported = %v, want exactly the cores that can fragment", got.Supported)
	}

	// Asserting on the renderer's own accessors, not the response: a write to a
	// key nothing reads would pass the response check.
	code, body = realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"fragment_level": "aggressive", "fragment_cores": "sing-box"})
	if code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	if s.subFragmentLevel() != "aggressive" {
		t.Errorf("subFragmentLevel = %q after saving aggressive", s.subFragmentLevel())
	}
	if cores := s.subFragmentCores(); len(cores) != 1 || cores[0] != "sing-box" {
		t.Errorf("subFragmentCores = %v after saving sing-box", cores)
	}
	if def := s.fragmentDefaults(); def.Length != routing.FragmentPreset("aggressive").Length {
		t.Errorf("fragmentDefaults did not pick up the severity: %+v", def)
	}

	// A core that cannot fragment is refused by name, so the card can mark the
	// field instead of showing a sentence about a card with a dozen of them.
	code, body = realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"fragment_cores": "xray, clash"})
	if code != 400 {
		t.Fatalf("POST of an unfragmentable core returned %d: %s", code, body)
	}
	if !strings.Contains(body, "sub_fragment_cores") {
		t.Errorf("the refusal does not name the offending key: %s", body)
	}
	if cores := s.subFragmentCores(); len(cores) != 1 || cores[0] != "sing-box" {
		t.Errorf("a refused save changed the stored core list to %v", cores)
	}
}
