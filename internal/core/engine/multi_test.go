package engine

import (
	"bytes"
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

// TestHysteria2UsersHaveNoUUID pins the bug where a uuid field on a sing-box
// hysteria2 user made sing-box reject the whole config ("json: unknown field
// uuid"), taking the engine down so the inbound served nothing. Hysteria2 users
// are {name, password} only; TUIC users legitimately carry uuid.
func TestHysteria2UsersHaveNoUUID(t *testing.T) {
	usersFor := func(proto model.Protocol) jobj {
		in := jobj{}
		applySingboxUsers(in, &model.Node{Protocol: proto},
			[]ClientCred{{Email: "u", Password: "p", UUID: "2842501c-d4ec-4593-b4a1-c6375c3ed2f4"}})
		return in["users"].([]any)[0].(jobj)
	}
	if hy2 := usersFor(model.ProtoHysteria2); hy2["uuid"] != nil {
		t.Fatalf("hysteria2 user must NOT carry uuid (sing-box rejects it), got %v", hy2)
	}
	if tuic := usersFor(model.ProtoTUIC); tuic["uuid"] == nil {
		t.Fatalf("tuic user must carry uuid, got %v", tuic)
	}
}

func TestApplySingboxUsersAnyTLSShadowTLS(t *testing.T) {
	// Regression: AnyTLS/ShadowTLS used to hit default:return, so all users shared
	// one template password. Now each gets its own {name,password}.
	for _, proto := range []model.Protocol{model.ProtoAnyTLS, model.ProtoShadowTLS} {
		in := jobj{}
		applySingboxUsers(in, &model.Node{Protocol: proto}, []ClientCred{
			{Email: "a@x", Password: "pw-a"},
			{Email: "b@x", Password: "pw-b"},
		})
		arr, ok := in["users"].([]any)
		if !ok || len(arr) != 2 {
			t.Fatalf("%s: expected 2 users, got %v", proto, in["users"])
		}
		seen := map[string]string{}
		for _, u := range arr {
			m := u.(jobj)
			name, _ := m["name"].(string)
			pw, _ := m["password"].(string)
			if name == "" || pw == "" {
				t.Fatalf("%s: blank name/password: %v", proto, m)
			}
			seen[name] = pw
		}
		if seen["a@x"] != "pw-a" || seen["b@x"] != "pw-b" {
			t.Fatalf("%s: per-user passwords wrong: %v", proto, seen)
		}
	}
}

// TestEngineConfigsCarryOpaqueUserTags pins the privacy property behind the
// per-user stats tag: the identifier that reaches generated engine configs (and
// therefore engine logs and metrics labels) is the panel's opaque per-client
// tag, never a contact address. The panel resolves it back to the user through
// its own database — see job.UserEmail / parseUserEmail, which produce and
// consume "u<ID>". "email" is Xray's field name for the stats key, not an
// instruction to put a mailbox there.
func TestEngineConfigsCarryOpaqueUserTags(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555"}
	// What internal/api/engines.go actually passes: job.UserEmail(u.ID).
	sp := InboundSpec{Node: n, Clients: []ClientCred{
		{Email: "u1", UUID: "11111111-2222-3333-4444-555555555555"},
		{Email: "u2", UUID: "66666666-7777-8888-9999-000000000000"},
	}}
	b, err := BuildMulti([]InboundSpec{sp}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{b.Xray, b.Singbox} {
		if bytes.Contains(blob, []byte("@")) {
			t.Fatalf("engine config contains an '@' — a contact address may have "+
				"leaked into a stats tag:\n%s", blob)
		}
	}
	if !bytes.Contains(b.Xray, []byte(`"email": "u1"`)) {
		t.Fatalf("xray config lost the opaque per-user tag:\n%s", b.Xray)
	}
}

// TestSingboxUserNamesAreUniqueAndStable: names must not collide within an
// inbound, and must not change between regenerations, or per-user stats would be
// merged or reset.
func TestSingboxUserNamesAreUniqueAndStable(t *testing.T) {
	clients := []ClientCred{{Email: "u1"}, {Email: "u1"}, {Email: ""}, {Email: ""}}
	first := map[string]bool{}
	var firstNames []string
	seen := map[string]int{}
	for i, cl := range clients {
		name := singboxUserName(cl, i, seen)
		if name == "" {
			t.Fatalf("client %d got an empty name", i)
		}
		if first[name] {
			t.Fatalf("duplicate name %q within one inbound", name)
		}
		first[name] = true
		firstNames = append(firstNames, name)
	}
	// Regenerate: identical input must yield identical names.
	seen2 := map[string]int{}
	for i, cl := range clients {
		if got := singboxUserName(cl, i, seen2); got != firstNames[i] {
			t.Fatalf("name for client %d changed across regeneration: %q -> %q",
				i, firstNames[i], got)
		}
	}
}

// TestSingboxUserNameNeverLeaksCredentials: the name appears in engine logs and
// stats, so it must never be the client's authentication secret.
func TestSingboxUserNameNeverLeaksCredentials(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	const pw = "s3cr3t-password"
	name := singboxUserName(ClientCred{UUID: uuid, Password: pw}, 0, map[string]int{})
	if strings.Contains(name, uuid) || strings.Contains(name, pw) {
		t.Fatalf("stats name leaks a credential: %q", name)
	}
}

func TestBuildMultiZeroClientsRendersEmptyArray(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443, UUID: "tmpl", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	sp := InboundSpec{Node: n, Clients: []ClientCred{}}
	b, err := BuildMulti([]InboundSpec{sp}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}

	var cfg struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []map[string]any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(b.Xray, &cfg); err != nil {
		t.Fatalf("failed to unmarshal xray config: %v", err)
	}

	if len(cfg.Inbounds) == 0 {
		t.Fatal("expected at least 1 inbound")
	}

	var vlessClients []map[string]any
	found := false
	for _, in := range cfg.Inbounds {
		if in.Protocol == "vless" {
			vlessClients = in.Settings.Clients
			found = true
			break
		}
	}
	if !found {
		t.Fatal("vless inbound not found in config")
	}
	if vlessClients == nil {
		t.Fatal("expected clients array to be non-nil [] (rendered as [])")
	}
	if len(vlessClients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(vlessClients))
	}
}

// TestSocksHTTPPerUserAccounts pins the fix where SOCKS/HTTP inbounds kept the
// single template account (settings.accounts) instead of one per assigned user —
// so a user's subscription credential (set by stampIdentity) could never
// authenticate. Each user must get their own {user,pass} account.
func TestSocksHTTPPerUserAccounts(t *testing.T) {
	for _, proto := range []model.Protocol{model.ProtoSOCKS, model.ProtoHTTP} {
		in := jobj{"settings": jobj{"accounts": []any{jobj{"user": "tmpl", "pass": "tmpl"}}}}
		applyXrayClients(in, &model.Node{Protocol: proto}, []ClientCred{
			{Username: "alice", Password: "pa"}, {Username: "bob", Password: "pb"},
		})
		accts, _ := in["settings"].(jobj)["accounts"].([]any)
		if len(accts) != 2 {
			t.Fatalf("%s: want 2 per-user accounts, got %d (%v)", proto, len(accts), accts)
		}
		got := map[string]string{}
		for _, a := range accts {
			m := a.(jobj)
			got[m["user"].(string)] = m["pass"].(string)
		}
		if got["alice"] != "pa" || got["bob"] != "pb" {
			t.Fatalf("%s: per-user creds wrong: %v", proto, got)
		}
		if proto == model.ProtoSOCKS && in["settings"].(jobj)["auth"] != "password" {
			t.Fatalf("socks: auth must be password when accounts present")
		}
	}
	// No usernames -> keep the rendered config untouched (don't force auth).
	in := jobj{"settings": jobj{}}
	applyXrayClients(in, &model.Node{Protocol: model.ProtoSOCKS}, []ClientCred{{Email: "x", UUID: "u"}})
	if _, has := in["settings"].(jobj)["accounts"]; has {
		t.Fatal("socks: no-username clients must not add accounts")
	}
}

// TestShadowsocks2022PerUserPSK: an SS-2022 inbound must materialise one derived
// PSK per user (keyed by email for stats) while keeping the server PSK at the
// inbound level, so each user authenticates with "serverPSK:userPSK". A non-2022
// method has no per-user identity and must be left as the single shared key.
func TestShadowsocks2022PerUserPSK(t *testing.T) {
	const method = model.SS2022AES128
	clients := []ClientCred{{Email: "u1"}, {Email: "u2"}}

	// xray: settings.clients, one per user, distinct passwords, server PSK kept.
	xin := jobj{"settings": jobj{"method": method, "password": "SERVERPSK"}}
	applyXrayClients(xin, &model.Node{Protocol: model.ProtoShadowsocks, Method: method}, clients)
	xc, _ := xin["settings"].(jobj)["clients"].([]any)
	if len(xc) != 2 {
		t.Fatalf("xray: want 2 SS-2022 clients, got %d", len(xc))
	}
	if xin["settings"].(jobj)["password"] != "SERVERPSK" {
		t.Fatal("xray: the inbound server PSK must be preserved")
	}
	p0 := xc[0].(jobj)["password"].(string)
	p1 := xc[1].(jobj)["password"].(string)
	if p0 == p1 {
		t.Fatal("xray: two users got the SAME PSK — not per-user")
	}
	// The materialised PSK must equal what the subscription derives for that email.
	if p0 != model.DeriveSSUserPSK("u1", method) {
		t.Fatal("xray: user PSK does not match the deterministic derivation the sub uses")
	}

	// sing-box: users[], same guarantees.
	sin := jobj{"password": "SERVERPSK"}
	applySingboxUsers(sin, &model.Node{Protocol: model.ProtoShadowsocks, Method: method}, clients)
	su, _ := sin["users"].([]any)
	if len(su) != 2 {
		t.Fatalf("sing-box: want 2 SS-2022 users, got %d", len(su))
	}
	if su[0].(jobj)["password"].(string) != model.DeriveSSUserPSK("u1", method) {
		t.Fatal("sing-box: user PSK does not match the derivation")
	}

	// Non-2022 SS: no per-user expansion, the shared key is untouched.
	nin := jobj{"settings": jobj{"method": model.SSAES256GCM, "password": "SHARED"}}
	applyXrayClients(nin, &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SSAES256GCM}, clients)
	if _, has := nin["settings"].(jobj)["clients"]; has {
		t.Fatal("non-2022 SS must NOT get a per-user clients array")
	}
}
