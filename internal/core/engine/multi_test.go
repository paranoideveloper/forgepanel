package engine

import (
	"encoding/json"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"strings"
	"testing"
)

func TestBuildMultiExpandsClients(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443, UUID: "tmpl", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	sp := InboundSpec{Node: n, Clients: []ClientCred{{Email: "u1", UUID: "11111111-2222-3333-4444-555555555555"}, {Email: "u2", UUID: "66666666-7777-8888-9999-000000000000"}}}
	b, err := BuildMulti([]InboundSpec{sp}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(b.Xray, &cfg)
	s := string(b.Xray)
	if !strings.Contains(s, "u1") || !strings.Contains(s, "u2") {
		t.Fatal("both users must be clients in served config")
	}
	if !strings.Contains(s, "statsUserUplink") {
		t.Fatal("per-user stats policy must be enabled")
	}
}

func TestApplySingboxUsersNameTags(t *testing.T) {
	users := func(proto model.Protocol, clients []ClientCred) []any {
		in := jobj{}
		applySingboxUsers(in, &model.Node{Protocol: proto}, clients)
		arr, _ := in["users"].([]any)
		return arr
	}
	// Hysteria2 + TUIC must now carry a "name" (regression: they had none, so
	// sing-box could not attribute per-user traffic).
	for _, proto := range []model.Protocol{model.ProtoHysteria2, model.ProtoTUIC} {
		arr := users(proto, []ClientCred{{Email: "alice@x", Password: "p", UUID: "u1"}})
		if len(arr) != 1 {
			t.Fatalf("%s: want 1 user", proto)
		}
		m := arr[0].(jobj)
		if m["name"] != "alice@x" {
			t.Fatalf("%s: name=%v want alice@x", proto, m["name"])
		}
	}
	// Missing email => stable non-empty fallback; duplicates de-duplicated.
	arr := users(model.ProtoHysteria2, []ClientCred{
		{Password: "p", UUID: "abc"}, // no email -> hashed "user-<digest>", NOT the raw uuid
		{Email: "dup", Password: "p"},
		{Email: "dup", Password: "p"}, // collision -> dup-1
	})
	names := map[string]bool{}
	for _, u := range arr {
		n, _ := u.(jobj)["name"].(string)
		if n == "" {
			t.Fatal("blank name emitted")
		}
		if n == "user-abc" || strings.Contains(n, "abc") {
			t.Fatalf("fallback name must not expose the raw uuid: %q", n)
		}
		if names[n] {
			t.Fatalf("duplicate name %q", n)
		}
		names[n] = true
	}
	if !names["dup"] || !names["dup-1"] {
		t.Fatalf("email collision de-dup wrong: %v", names)
	}
}
