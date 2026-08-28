package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The bundle has always carried a sing-box config alongside the xray one, and
// the heartbeat sent only the xray half — so every hysteria2, tuic, anytls,
// shadowtls and wireguard inbound vanished the moment it was assigned to a
// remote node. The panel listed it, the node never served it, nothing said why.
func TestHeartbeatSendsBothEngineConfigs(t *testing.T) {
	s, token := adminAPI(t)

	n := &store.Node{Name: "edge", Address: "203.0.113.9", EnrollToken: "tok", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	// A sing-box protocol on that node's address.
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"hysteria2","address":"203.0.113.9","port":8443,"remark":"hy2","password":"pw"}`); code != 200 && code != 201 {
		t.Fatalf("creating the hy2 inbound: %d %s", code, b)
	}

	code, body := doPOST(t, s, "/api/node/heartbeat", "", `{"token":"tok"}`)
	if code != 200 {
		t.Fatalf("heartbeat: %d %s", code, body)
	}
	var resp struct {
		XrayConfig    string `json:"xray_config"`
		SingboxConfig string `json:"singbox_config"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SingboxConfig == "" {
		t.Fatal("the node was sent no sing-box config; its hysteria2 inbound would never be served")
	}
	if !strings.Contains(resp.SingboxConfig, "hysteria2") {
		t.Errorf("the sing-box config does not contain the inbound: %s", resp.SingboxConfig)
	}
}

func TestAnXrayOnlyNodeIsSentNoSingboxConfig(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "x", Address: "198.51.100.4", EnrollToken: "tok2", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"vless","address":"198.51.100.4","port":8443,"remark":"v"}`); code != 200 && code != 201 {
		t.Fatalf("%d: %s", code, b)
	}

	_, body := doPOST(t, s, "/api/node/heartbeat", "", `{"token":"tok2"}`)
	var resp struct {
		SingboxConfig string `json:"singbox_config"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	// BuildMulti always emits a syntactically valid sing-box document, even an
	// empty one. Sending that would have the node download the binary and
	// supervise a core listening on nothing.
	if resp.SingboxConfig != "" {
		t.Fatalf("an xray-only node was sent a sing-box config: %s", resp.SingboxConfig)
	}
}

// The sing-box stats section is a STARTUP requirement, not a hint: a stock
// sing-box refuses to start with it ("v2ray api is not included in this build").
// So the panel must only ask for it from a node that says its binary can serve
// it — and the panel cannot detect that itself, because the capability belongs
// to the binary installed on the node.
func TestTheStatsSectionIsOnlySentToACapableNode(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "edge", Address: "203.0.113.9", EnrollToken: "tok", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"hysteria2","address":"203.0.113.9","port":8443,"remark":"hy2","password":"pw"}`); code != 200 && code != 201 {
		t.Fatalf("%d: %s", code, b)
	}

	singbox := func(beat string) string {
		_, body := doPOST(t, s, "/api/node/heartbeat", "", beat)
		var resp struct {
			SingboxConfig string `json:"singbox_config"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.SingboxConfig
	}

	// A stock binary: no stats section, or the core refuses to start and takes
	// every sing-box inbound on that node down — strictly worse than leaving
	// them unmetered, which is the state they were already in.
	if cfg := singbox(`{"token":"tok","singbox_stats":false}`); strings.Contains(cfg, "v2ray_api") {
		t.Fatalf("a stats section was sent to a node that cannot serve it: %s", cfg)
	}
	// A ForgePanel build: the section is included, and its users are enumerated —
	// `stats: {enabled: true}` alone collects nothing and returns an empty
	// response, which is indistinguishable from "no traffic yet".
	cfg := singbox(`{"token":"tok","singbox_stats":true}`)
	if !strings.Contains(cfg, "v2ray_api") {
		t.Fatalf("a capable node was sent no stats section; its traffic stays unmetered: %s", cfg)
	}
}

// Node.Healthy was written true on register and on every heartbeat and never
// written false anywhere in the tree, so the flag the API served meant "this
// node has checked in at least once". The UI badge reads it directly: a node
// that died an hour ago still said Online, right next to a last_seen column
// saying "1h ago".
func TestNodeListDerivesLivenessFromLastSeen(t *testing.T) {
	s, token := adminAPI(t)

	long := time.Now().Add(-2 * time.Hour)
	just := time.Now().Add(-5 * time.Second)
	// Stored flags are deliberately the WRONG way round: the point is that the
	// response is derived from last_seen, not read back from the column.
	dead := &store.Node{Name: "dead", Address: "203.0.113.10", EnrollToken: "t-dead",
		Enrolled: true, Healthy: true, LastSeen: &long}
	live := &store.Node{Name: "live", Address: "203.0.113.11", EnrollToken: "t-live",
		Enrolled: true, Healthy: false, LastSeen: &just}
	never := &store.Node{Name: "never", Address: "203.0.113.12", EnrollToken: "t-never",
		Enrolled: true, Healthy: true}
	for _, n := range []*store.Node{dead, live, never} {
		if err := s.db.SaveNode(n); err != nil {
			t.Fatal(err)
		}
	}

	code, body := doGET(t, s, "/api/admin/nodes", token)
	if code != 200 {
		t.Fatalf("listing nodes: %d %s", code, body)
	}
	var got []struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{}
	for _, n := range got {
		healthy[n.Name] = n.Healthy
	}
	if healthy["dead"] {
		t.Error("a node silent for two hours is reported healthy; the Online badge means nothing")
	}
	if !healthy["live"] {
		t.Error("a node that heartbeated five seconds ago is reported unhealthy")
	}
	if healthy["never"] {
		t.Error("a node that has never reported is reported healthy")
	}
}

// The heartbeat built the node's config with nil outbounds and nil rules, so
// the panel's own box enforced the operator's routing table and every remote
// node enforced none of it.
func TestHeartbeatShipsRoutingRulesToTheNode(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "edge", Address: "203.0.113.20", EnrollToken: "tok-r", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"vless","address":"203.0.113.20","port":8443,"remark":"v"}`); code != 200 && code != 201 {
		t.Fatalf("creating the node's inbound: %d %s", code, b)
	}
	mkOutbound(t, s, token, "hole", "blackhole")
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"block-private","ip":["geoip:private"],"outbound_tag":"hole","enabled":true}`); code != 200 {
		t.Fatalf("creating the rule: %d %s", code, b)
	}

	code, body := doPOST(t, s, "/api/node/heartbeat", "", `{"token":"tok-r"}`)
	if code != 200 {
		t.Fatalf("heartbeat: %d %s", code, body)
	}
	var resp struct {
		XrayConfig string `json:"xray_config"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	// Assert the operator's own tag, not the protocol: the built-in "block"
	// outbound every config carries is a blackhole too, so grepping for the
	// protocol name passes on a config that has no operator outbound in it at
	// all — which is exactly the broken state this test exists to catch.
	if !strings.Contains(resp.XrayConfig, `"hole"`) {
		t.Errorf("the node was sent no \"hole\" outbound, so it cannot enforce the rule: %s", resp.XrayConfig)
	}
	if !strings.Contains(resp.XrayConfig, "geoip:private") {
		t.Errorf("the node was sent no block-private rule; its metadata endpoint stays reachable: %s", resp.XrayConfig)
	}
}

// A rule scoped to inbounds that live on other machines can never match on this
// node, and shipping it puts a list of other nodes' inbound names into a config
// on a machine that has no reason to hold them.
func TestNodeRoutingRulesAreScopedToTheNodesOwnInbounds(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "edge", Address: "203.0.113.30", EnrollToken: "tok-s", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	// One inbound on this node, one on a different machine entirely.
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"vless","address":"203.0.113.30","port":8443,"remark":"mine"}`); code != 200 && code != 201 {
		t.Fatalf("%d: %s", code, b)
	}
	if code, b := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"vless","address":"198.51.100.77","port":9443,"remark":"theirs"}`); code != 200 && code != 201 {
		t.Fatalf("%d: %s", code, b)
	}
	mkOutbound(t, s, token, "hole", "blackhole")
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"elsewhere","domain":["only-there.example"],"inbound_tags":["in-9443"],"outbound_tag":"hole","enabled":true}`); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"here","domain":["right-here.example"],"inbound_tags":["in-8443"],"outbound_tag":"hole","enabled":true}`); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}

	_, body := doPOST(t, s, "/api/node/heartbeat", "", `{"token":"tok-s"}`)
	var resp struct {
		XrayConfig string `json:"xray_config"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.XrayConfig, "right-here.example") {
		t.Errorf("the rule scoped to this node's own inbound was dropped: %s", resp.XrayConfig)
	}
	if strings.Contains(resp.XrayConfig, "only-there.example") || strings.Contains(resp.XrayConfig, "in-9443") {
		t.Errorf("a rule scoped to another node's inbound was shipped here: %s", resp.XrayConfig)
	}
}

// An operator outbound is a full proxy definition: a Trojan relay carries its
// password, a SOCKS hop its credentials. Making routing reach nodes originally
// shipped the WHOLE outbound set to every node — so a node with one inbound and
// no applicable rule received the credentials for every relay the operator had
// ever configured, on a machine with no use for them, written to disk for the
// lifetime of the enrolment. Nodes previously received no outbounds at all, so
// that was a new exposure created by making routing reach nodes, not one it
// inherited.
//
// Set up through the API rather than the store, both because that is how an
// operator creates routing and because the store's field types are unexported.
// The first version of this test called the filter helper directly and PASSED
// with the call site reverted — it was testing a function nothing was obliged
// to use.
func TestANodeOnlyGetsTheOutboundsItsOwnRulesName(t *testing.T) {
	s, token := adminAPI(t)

	for _, body := range []map[string]any{
		{"tag": "secret-relay", "protocol": "trojan", "enabled": true,
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": "1.2.3.4", "port": 443, "password": "THE-RELAY-PASSWORD"}}}},
		{"tag": "hole", "protocol": "blackhole", "enabled": true, "settings": map[string]any{}},
	} {
		if code, resp := realPost(t, s, "/api/admin/routing/outbounds", token, body); code != 200 && code != 201 {
			t.Fatalf("saving outbound %v: %d %s", body["tag"], code, resp)
		}
	}
	// One rule, naming only "hole". "secret-relay" is configured and referenced
	// by nothing.
	if code, resp := realPost(t, s, "/api/admin/routing/rules", token, map[string]any{
		"name": "block-private", "enabled": true, "ip": []string{"geoip:private"}, "outbound_tag": "hole",
	}); code != 200 && code != 201 {
		t.Fatalf("saving rule: %d %s", code, resp)
	}

	outs, rules := s.nodeRoutingSpecs(nil)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want the one unscoped rule", rules)
	}
	for _, o := range outs {
		if strings.Contains(string(o.Settings), "THE-RELAY-PASSWORD") {
			t.Fatal("an unreferenced relay's password was sent to a node that cannot use it")
		}
	}
	if len(outs) != 1 || outs[0].Tag != "hole" {
		t.Fatalf("outbounds = %v, want only the one the surviving rule names", outs)
	}
}

// A node with no applicable rules must receive no operator outbounds at all —
// not "all of them, because no filtering ran".
func TestANodeWithNoApplicableRulesGetsNoOperatorOutbounds(t *testing.T) {
	s, token := adminAPI(t)
	if code, resp := realPost(t, s, "/api/admin/routing/outbounds", token, map[string]any{
		"tag": "secret-relay", "protocol": "trojan", "enabled": true,
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "1.2.3.4", "port": 443, "password": "THE-RELAY-PASSWORD"}}},
	}); code != 200 && code != 201 {
		t.Fatalf("saving outbound: %d %s", code, resp)
	}
	// No rules saved at all: the len(rules)==0 path.
	outs, rules := s.nodeRoutingSpecs(nil)
	if len(outs) != 0 || len(rules) != 0 {
		t.Fatalf("a node with no rules received %d outbound(s) and %d rule(s)", len(outs), len(rules))
	}
}
