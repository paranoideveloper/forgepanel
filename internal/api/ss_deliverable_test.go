package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
)

// Shadowsocks over httpupgrade and xhttp is deliverable — through a
// subscription that carries a client CONFIG rather than a share link.
//
// The ss:// URI scheme can express a transport only through SIP003's plugin
// field, and neither v2ray-plugin nor xray-plugin implements those two modes.
// That is a limit of the URI, not of the protocol: the inbound runs, the core
// serves it, and an Xray client configured with the matching streamSettings
// connects. The Xray and JSON subscription formats carry exactly that.
func TestShadowsocksOnTransportsWithNoLinkIsStillDeliverable(t *testing.T) {
	for _, net := range []model.Network{model.NetHTTPUpgrade, model.NetXHTTP} {
		n := &model.Node{
			Remark: "ss-" + string(net), Protocol: model.ProtoShadowsocks,
			Address: "edge.example.com", Port: 443,
			Method: "2022-blake3-aes-128-gcm", Password: "hzQTq6OOqLCwxtin5RJ6jg==",
			Transport: model.Transport{Network: net, Path: "/tunnel", Host: "edge.example.com"},
			Security:  model.Security{Type: model.SecTLS, ServerName: "edge.example.com"},
		}

		// No share link, and the refusal must say where to get it instead.
		if _, err := export.URI(n); err == nil {
			t.Errorf("%s: a share link was produced; a bare ss:// describes plain TCP", net)
		} else if !strings.Contains(err.Error(), "subscription") {
			t.Errorf("%s: the refusal does not point at the subscription: %v", net, err)
		}

		// …but the Xray subscription carries the whole thing.
		raw := xraySubscription([]*model.Node{n}, routing.Options{}, routing.Fragment{})
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("%s: subscription is not JSON: %v", net, err)
		}
		outs, _ := cfg["outbounds"].([]any)
		var found bool
		for _, o := range outs {
			m, _ := o.(map[string]any)
			if m["protocol"] != "shadowsocks" {
				continue
			}
			found = true
			ss, _ := m["streamSettings"].(map[string]any)
			if ss == nil {
				t.Errorf("%s: the outbound carries no streamSettings, so the transport is lost", net)
				continue
			}
			if ss["network"] != string(net) {
				t.Errorf("%s: subscription says network=%v", net, ss["network"])
			}
			key := map[model.Network]string{
				model.NetHTTPUpgrade: "httpupgradeSettings", model.NetXHTTP: "xhttpSettings",
			}[net]
			ts, _ := ss[key].(map[string]any)
			if ts == nil || ts["path"] != "/tunnel" {
				t.Errorf("%s: %s missing or pathless: %v", net, key, ts)
			}
		}
		if !found {
			t.Errorf("%s: no shadowsocks outbound in the subscription at all", net)
		}
	}
}
