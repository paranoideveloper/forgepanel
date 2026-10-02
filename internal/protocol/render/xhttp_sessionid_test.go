package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Xray v26.6.22+ reads the XHTTP session ID placement only as sessionIDPlacement /
// sessionIDKey; every earlier core reads only sessionPlacement / sessionKey. A
// config carrying one spelling means "header" to one core and the default
// "path" to the other, and the two ends never find each other's session.
func TestXHTTPSessionPlacementIsWrittenForOldAndNewCores(t *testing.T) {
	n := &model.Node{
		Remark: "xh", Protocol: model.ProtoVLESS, Address: "127.0.0.1", Port: 31001,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetXHTTP, Path: "/x",
			SessionPlacement: "header", SessionKey: "X-Sess"},
	}
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	var got struct {
		StreamSettings struct {
			XHTTPSettings map[string]any `json:"xhttpSettings"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	x := got.StreamSettings.XHTTPSettings
	for k, want := range map[string]string{
		"sessionIDPlacement": "header", "sessionPlacement": "header",
		"sessionIDKey": "X-Sess", "sessionKey": "X-Sess",
	} {
		if x[k] != want {
			t.Errorf("%s = %v, want %q (all: %v)", k, x[k], want, x)
		}
	}
}

// Xray v26.7.11 defaults a REALITY server to refusing clients that do not report
// Xray v26.3.27+, which locks out every sing-box based app. The server must say
// "0.0.0" explicitly; a client outbound must not carry it at all.
func TestARealityServerAcceptsEveryClientVersion(t *testing.T) {
	n := &model.Node{
		Remark: "r", Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision",
		Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, ServerName: "www.cloudflare.com",
			Reality: &model.Reality{PrivateKey: "SFPpqRAojigVouHHutvXFHPVM0E-jjiupFJzQQ_GAl4",
				PublicKey: "Fr0bYwQYRo509PG-gi03ouAvLrBmrBndtaJyQ2VWlBo", ShortIDs: []string{"c6875c0dc249d397"},
				Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}}},
	}
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	if !strings.Contains(string(raw), `"minClientVer":"0.0.0"`) {
		t.Fatalf("server REALITY has no explicit minClientVer: %s", raw)
	}
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), "minClientVer") {
		t.Fatalf("a client outbound carries the server-only minClientVer: %s", raw)
	}
}
