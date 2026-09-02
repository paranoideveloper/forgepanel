package api

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
)

// goldenNodes is a fixed, deterministic matrix used to golden-file every
// subscription format. Deterministic identities (no random keys) so the golden
// output is stable and any byte change is a deliberate, reviewed change.
func goldenNodes() []*model.Node {
	return []*model.Node{
		{Protocol: model.ProtoVMess, Remark: "vmess-ws", Address: "a.example.com", Port: 443,
			UUID:      "11111111-2222-3333-4444-555555555555",
			Transport: model.Transport{Network: model.NetWS, Path: "/ws", Host: "a.example.com"},
			Security:  model.Security{Type: model.SecTLS, ServerName: "a.example.com"}},
		{Protocol: model.ProtoTrojan, Remark: "trojan", Address: "b.example.com", Port: 443,
			Password: "trojanpass", Security: model.Security{Type: model.SecTLS, ServerName: "b.example.com"}},
		{Protocol: model.ProtoShadowsocks, Remark: "ss", Address: "c.example.com", Port: 8388,
			Method: "2022-blake3-aes-128-gcm", Password: "MTIzNDU2Nzg5MDEyMzQ1Ng=="},
		{Protocol: model.ProtoSOCKS, Remark: "socks", Address: "d.example.com", Port: 1080,
			Username: "u", Password: "p"},
		{Protocol: model.ProtoHTTP, Remark: "http", Address: "e.example.com", Port: 8080,
			Username: "hu", Password: "hp"},
	}
}

// TestSubscriptionFormatsStructural validates every format's structure and
// golden-files it. Set UPDATE_GOLDEN=1 to regenerate.
func TestSubscriptionFormatsStructural(t *testing.T) {
	nodes := goldenNodes()
	clashYAML, err := export.ClashYAML(nodes)
	if err != nil {
		t.Fatalf("clash: %v", err)
	}
	outputs := map[string][]byte{
		"v2ray":       []byte(base64.StdEncoding.EncodeToString([]byte(plainLinks(nodes)))),
		"links":       []byte(plainLinks(nodes)),
		"clash":       []byte(clashYAML),
		"sing-box":    singboxSubscription(nodes, routing.Options{}, routing.Fragment{}),
		"xray":        xraySubscription(nodes, routing.Options{}, routing.Fragment{}),
		"surge":       surgeSubscription(nodes),
		"loon":        loonSubscription(nodes),
		"quantumultx": quantumultxSubscription(nodes),
	}

	// Structural assertions.
	if _, err := base64.StdEncoding.DecodeString(string(outputs["v2ray"])); err != nil {
		t.Errorf("v2ray not valid base64: %v", err)
	}
	for _, f := range []string{"sing-box", "xray"} {
		var j any
		if err := json.Unmarshal(outputs[f], &j); err != nil {
			t.Errorf("%s not valid JSON: %v", f, err)
		}
	}
	if !strings.Contains(string(outputs["surge"]), "[Proxy]") {
		t.Error("surge missing [Proxy] header")
	}
	if !strings.Contains(string(outputs["quantumultx"]), "[server_local]") {
		t.Error("quantumultx missing [server_local] header")
	}
	// No nil/undefined leaks in any format.
	for f, b := range outputs {
		for _, bad := range []string{"<nil>", "undefined", "%!"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s output leaks %q", f, bad)
			}
		}
	}

	// Golden files.
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	for f, b := range outputs {
		path := filepath.Join("testdata", "golden", f+".golden")
		if update {
			os.WriteFile(path, b, 0o644)
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing golden for %s (run UPDATE_GOLDEN=1): %v", f, err)
		}
		if string(want) != string(b) {
			t.Errorf("%s output changed vs golden — if intended, regenerate with UPDATE_GOLDEN=1", f)
		}
	}
}
