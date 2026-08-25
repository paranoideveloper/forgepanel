package api

import (
	"encoding/json"
	"strings"
	"testing"

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
