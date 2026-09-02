package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func TestExpandSNIRotation(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, Remark: "Vision",
		Flow: "xtls-rprx-vision", Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, ServerName: "a.com",
			Reality: &model.Reality{PublicKey: "pk", ShortID: "sid",
				ServerNames: []string{"aparat.ir", "discord.com", "chatgpt.com"}}},
	}
	out := expandNodeVariations(n, nil, true, false)
	if len(out) != 3 {
		t.Fatalf("expected 3 SNI variations, got %d", len(out))
	}
	seen := map[string]bool{}
	for _, c := range out {
		seen[c.Security.ServerName] = true
		if len(c.Security.Reality.ServerNames) != 1 {
			t.Errorf("client link should carry exactly its one SNI, got %v", c.Security.Reality.ServerNames)
		}
		if c.Security.Reality.PublicKey != "pk" {
			t.Errorf("shared reality key lost in a variation")
		}
	}
	for _, sni := range []string{"aparat.ir", "discord.com", "chatgpt.com"} {
		if !seen[sni] {
			t.Errorf("missing SNI variation %q", sni)
		}
	}
	// The original node must be untouched (no mutation bleed).
	if len(n.Security.Reality.ServerNames) != 3 {
		t.Errorf("expansion mutated the source node's serverNames")
	}
}

func TestExpandCleanIPFronting(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "edge.example.com", Port: 2096, Remark: "WS-TLS",
		Transport: model.Transport{Network: model.NetWS, Path: "/w"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "edge.example.com"},
	}
	out := expandNodeVariations(n, []string{"104.18.1.1", "172.64.2.2"}, true, true)
	if len(out) != 3 { // the domain entry + 2 clean IPs
		t.Fatalf("expected 3 (domain + 2 IPs), got %d", len(out))
	}
	if out[1].Address != "104.18.1.1" || out[1].Security.ServerName != "edge.example.com" {
		t.Errorf("clean-IP variation must dial the IP but keep the domain SNI: %+v", out[1].Security)
	}
}

func TestExpandNoRotationYieldsOne(t *testing.T) {
	// Single-SNI reality, and non-CDN, must stay exactly one config.
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443,
		Security: model.Security{Type: model.SecReality, Reality: &model.Reality{ServerNames: []string{"only.com"}}}}
	if got := len(expandNodeVariations(n, []string{"104.18.1.1"}, true, true)); got != 1 {
		t.Fatalf("single-SNI reality should yield 1, got %d", got)
	}
	// Expansion disabled → one, even with many SNIs.
	n2 := &model.Node{Protocol: model.ProtoVLESS, Security: model.Security{Type: model.SecReality,
		Reality: &model.Reality{ServerNames: []string{"a.com", "b.com"}}}}
	if got := len(expandNodeVariations(n2, nil, false, false)); got != 1 {
		t.Fatalf("expansion off should yield 1, got %d", got)
	}
}
