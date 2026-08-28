package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
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

// The enrolment command the panel PRINTS has to work on the panel it was
// printed by. On a self-signed panel — the only case where the panel bothers to
// compute a fingerprint at all — it did not:
//
//	curl -fsSL https://<panel>/node-install.sh | ... PANEL_FINGERPRINT=... bash
//	curl: (60) SSL certificate problem: self-signed certificate
//
// The script knows to pass -k once it holds a fingerprint. The curl that FETCHES
// the script did not, so it died before any pinning logic existed on the node.
// Measured on a real host: enrolment could never complete on a panel without a
// domain, which is every panel on first run.
//
// A bare -k would fetch the pinning script over an unverified connection, so an
// attacker who can MITM that one request serves a script with no pin and the
// fingerprint becomes decoration. The peer is pinned by public key instead.
func TestTheEnrolCommandCanFetchItsOwnInstallScript(t *testing.T) {
	s, token := adminAPI(t)
	// A self-signed panel: a cert on disk and no domain, which is first-run
	// state. Written explicitly, because without it panelCertFingerprint returns
	// "" and this test SKIPS — reporting ok while asserting nothing, which is
	// the failure mode this repo has been bitten by before.
	writeSelfSignedPanelCert(t, s)

	code, body := realPost(t, s, "/api/admin/nodes/enroll", token,
		map[string]any{"name": "node-a", "address": "203.0.113.9"})
	if code != 201 {
		t.Fatalf("enrol returned %d: %s", code, body)
	}
	var out struct {
		EnrollCommand string `json:"enroll_command"`
		Fingerprint   string `json:"panel_fingerprint"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Fingerprint == "" {
		t.Fatal("the panel computed no fingerprint for its own self-signed certificate")
	}

	// The script fetch must not be a plain `curl -fsSL https://...` — that is
	// the exact command that fails.
	if !strings.Contains(out.EnrollCommand, "--pinnedpubkey sha256//") {
		t.Errorf("the script fetch is unpinned, so it cannot verify a self-signed panel:\n%s",
			out.EnrollCommand)
	}
	if !strings.Contains(out.EnrollCommand, "-k ") {
		t.Errorf("the script fetch will refuse the panel's own certificate:\n%s", out.EnrollCommand)
	}
	// -k without a pin is the wrong fix and must never be what ships.
	if strings.Contains(out.EnrollCommand, "-k ") && !strings.Contains(out.EnrollCommand, "--pinnedpubkey") {
		t.Error("the script fetch skips verification with nothing pinning the peer")
	}
	// And the pin has to be the panel's actual key, not any old base64.
	want := s.panelCertPubkeyPin()
	if want == "" || !strings.Contains(out.EnrollCommand, "sha256//"+want) {
		t.Errorf("the pin is not this panel's public key (want sha256//%s):\n%s", want, out.EnrollCommand)
	}
}

// A panel with a real certificate must NOT ship -k: skipping verification when
// the system trust store would do the job is a downgrade nobody asked for.
func TestAPanelWithADomainShipsNoPinAndNoInsecureFlag(t *testing.T) {
	s, token := adminAPI(t)
	p := s.cfg.Panel()
	p.Domain = "panel.example.com"

	code, body := realPost(t, s, "/api/admin/nodes/enroll", token,
		map[string]any{"name": "node-b", "address": "203.0.113.10"})
	if code != 201 {
		t.Fatalf("enrol returned %d: %s", code, body)
	}
	var out struct {
		EnrollCommand string `json:"enroll_command"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.EnrollCommand, "-k ") || strings.Contains(out.EnrollCommand, "--pinnedpubkey") {
		t.Errorf("a CA-certificate panel still ships verification-skipping flags:\n%s", out.EnrollCommand)
	}
}

// writeSelfSignedPanelCert puts a real certificate where panelCertFingerprint
// and panelCertPubkeyPin look for one.
func writeSelfSignedPanelCert(t *testing.T, s *Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "forgepanel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.cfg.DataDir, "certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "self.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Every TLS-terminating inbound assigned to a node was built with an EMPTY
// certificate path, so the core on that node refused the entire config:
//
//	FATAL initialize inbound[0]: missing certificate
//
// That is every hysteria2, TUIC, AnyTLS and ShadowTLS inbound — the whole
// sing-box protocol family — plus any TLS xray inbound. The panel accepted them,
// listed them, delivered them, and the node rejected them every ten seconds
// forever while reporting itself healthy. Measured on a real node.
func TestANodeIsGivenACertificatePathItCanActuallyUse(t *testing.T) {
	certPath, keyPath := nodeCertPaths("/var/lib/forgepanel")
	if certPath == "" || keyPath == "" {
		t.Fatal("a node is given no certificate path, so every TLS inbound on it is refused")
	}
	// Same layout the panel uses for itself, so an operator finds the same thing
	// in the same place on either machine.
	if !strings.HasSuffix(certPath, "/certs/self.crt") || !strings.HasSuffix(keyPath, "/certs/self.key") {
		t.Errorf("cert=%q key=%q, want the panel's own <data>/certs/self.{crt,key} layout", certPath, keyPath)
	}
	// An agent that does not report its data directory must still get a usable
	// path rather than an empty one.
	c2, k2 := nodeCertPaths("")
	if c2 != filepath.Join(defaultNodeDataDir, "certs", "self.crt") || k2 == "" {
		t.Errorf("an agent reporting no data dir got cert=%q key=%q", c2, k2)
	}
	// And a custom data directory has to be honoured, or the path names a file
	// that is not there on that machine.
	if c3, _ := nodeCertPaths("/srv/fp"); c3 != "/srv/fp/certs/self.crt" {
		t.Errorf("a custom data dir produced %q", c3)
	}
}

// The end-to-end shape: a sing-box inbound assigned to a node must arrive with
// a certificate path in it. Asserting on nodeCertPaths alone would pass with the
// heartbeat still calling BuildMultiFor("", "").
func TestTheHeartbeatShipsASingboxConfigCarryingACertificate(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/nodes/enroll", token,
		map[string]any{"name": "n1", "address": "203.0.113.20"})
	if code != 201 {
		t.Fatalf("enrol: %d %s", code, body)
	}
	var en struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &en); err != nil {
		t.Fatal(err)
	}

	// A hysteria2 inbound on that node's address: TLS-terminating, sing-box.
	if code, b := realPost(t, s, "/api/admin/inbounds", token, map[string]any{
		"protocol": "hysteria2", "address": "203.0.113.20", "port": 26443,
		"remark": "hy2", "security": map[string]any{"type": "tls"},
		"hysteria2": map[string]any{"up_mbps": 100, "down_mbps": 100},
		"enabled":   true,
	}); code != 201 && code != 200 {
		t.Fatalf("create inbound: %d %s", code, b)
	}

	code, body = realPost(t, s, "/api/node/heartbeat", "", map[string]any{
		"token": en.Token, "data_dir": "/var/lib/forgepanel",
	})
	if code != 200 {
		t.Fatalf("heartbeat: %d %s", code, body)
	}
	var hb struct {
		SingboxConfig string `json:"singbox_config"`
	}
	if err := json.Unmarshal([]byte(body), &hb); err != nil {
		t.Fatal(err)
	}
	if hb.SingboxConfig == "" {
		t.Fatal("the node was sent no sing-box config for its hysteria2 inbound")
	}
	if !strings.Contains(hb.SingboxConfig, "/certs/self.crt") {
		t.Errorf("the sing-box config names no certificate, so the node will refuse it:\n%s",
			hb.SingboxConfig)
	}
}

// A hysteria2 hop range is two things: a hint in the client's share link, and
// firewall redirects that send the whole range at the port the core listens on.
// The panel installed the redirects for its own inbounds and nothing installed
// them on a node — so an inbound assigned to a node handed clients a link
// advertising mport=30000-30100 with none of those ports redirected. The tunnel
// worked until the client hopped, and then broke. Measured on a real node:
// sing-box listening on the base port, nft ruleset empty.
func TestTheHeartbeatShipsHysteria2HopRangesToTheNode(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/nodes/enroll", token,
		map[string]any{"name": "hopnode", "address": "203.0.113.30"})
	if code != 201 {
		t.Fatalf("enrol: %d %s", code, body)
	}
	var en struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &en); err != nil {
		t.Fatal(err)
	}

	if code, b := realPost(t, s, "/api/admin/inbounds", token, map[string]any{
		"protocol": "hysteria2", "address": "203.0.113.30", "port": 27443,
		"remark": "hop", "security": map[string]any{"type": "tls"},
		"hysteria2": map[string]any{
			"up_mbps": 200, "down_mbps": 200,
			"port_hopping": "30000-30100", "port_hop_interval": 30,
		},
		"enabled": true,
	}); code != 201 && code != 200 {
		t.Fatalf("create inbound: %d %s", code, b)
	}

	code, body = realPost(t, s, "/api/node/heartbeat", "", map[string]any{"token": en.Token})
	if code != 200 {
		t.Fatalf("heartbeat: %d %s", code, body)
	}
	var hb struct {
		PortHops map[int]string `json:"port_hops"`
	}
	if err := json.Unmarshal([]byte(body), &hb); err != nil {
		t.Fatal(err)
	}
	if got := hb.PortHops[27443]; got != "30000-30100" {
		t.Fatalf("the node was sent port_hops %v; without the range it advertises a hop it cannot serve",
			hb.PortHops)
	}
}

// A range belongs only to the protocol whose client hops. Shipping one for
// anything else installs redirects nothing dials.
func TestOnlyHysteria2InboundsContributeAHopRange(t *testing.T) {
	vless := &model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443}
	hy2 := &model.Node{Protocol: model.ProtoHysteria2, Address: "a", Port: 27443,
		Hysteria2: &model.Hysteria2Options{PortHopping: "30000-30100"}}
	plain := &model.Node{Protocol: model.ProtoHysteria2, Address: "a", Port: 28443,
		Hysteria2: &model.Hysteria2Options{}}

	got := nodePortHops([]engine.InboundSpec{{Node: vless}, {Node: hy2}, {Node: plain}})
	if len(got) != 1 || got[27443] != "30000-30100" {
		t.Fatalf("hops = %v, want only the hysteria2 inbound that has a range", got)
	}
}

// The unit the installer writes must grant CAP_NET_ADMIN, or the agent cannot
// install a redirect however correctly the panel describes it.
func TestTheNodeUnitGrantsTheCapabilityPortHoppingNeeds(t *testing.T) {
	s, _ := adminAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/node-install.sh", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("node-install.sh returned %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CAP_NET_ADMIN") {
		t.Error("the node unit grants no CAP_NET_ADMIN, so a hop range on this node can never be installed")
	}
}
