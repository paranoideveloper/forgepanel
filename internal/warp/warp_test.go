package warp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// The reserved bytes are the difference between a tunnel that carries traffic
// and one that handshakes and then silently drops every packet, so the decode
// is pinned against the Worker's reservedFromClientID — the two halves of this
// project must agree byte for byte or the same account works through one and
// not the other.
func TestReservedMatchesTheWorkersDecoding(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		want     []int
	}{
		// Standard base64: "AQID" -> 0x01 0x02 0x03.
		{"standard base64", "AQID", []int{1, 2, 3}},
		// base64url. Cloudflare has returned both, and '-'/'_' decode to
		// different bytes than '+'/'/' would, so a decoder that does not
		// substitute produces a plausible-looking WRONG triple.
		{"base64url", "-_8=", []int{251, 255, 0}},
		// Short input is zero-padded: the field is fixed-width and both cores
		// reject a two-element reserved outright.
		{"short", "AQ==", []int{1, 0, 0}},
		{"empty", "", []int{0, 0, 0}},
		// Garbage must not panic and must not produce a partial triple.
		{"not base64", "!!!!", []int{0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ReservedFromClientID(tc.id)
			if len(got) != 3 {
				t.Fatalf("reserved must always be exactly 3 bytes, got %v", got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("ReservedFromClientID(%q) = %v, want %v", tc.id, got, tc.want)
				}
			}
		})
	}
}

// '-_8=' is base64url. Decoded as if it were standard base64 the substitution
// is skipped and the bytes differ — this asserts the two are actually distinct,
// so the case above is testing something.
func TestBase64URLAndStandardWouldDifferWithoutSubstitution(t *testing.T) {
	if got := ReservedFromClientID("-_8="); got[0] == 0 && got[1] == 0 {
		t.Fatal("base64url input decoded to zeros, so the '-'/'_' substitution is not happening")
	}
}

func TestRegisterReadsTheNestedRegistrationShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("registration must be POST, got %s", r.Method)
		}
		if ua := r.Header.Get("User-Agent"); ua != "okhttp/3.12.1" {
			t.Errorf("the API only answers the WARP client's user agent, got %q", ua)
		}
		var got map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		if got["key"] == nil || got["key"] == "" {
			t.Error("registration must send our public key, or Cloudflare has no peer to configure")
		}
		_, _ = w.Write([]byte(`{
			"id":"dev-1","token":"tok-1",
			"config":{"client_id":"AQID",
			  "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8::1"}},
			  "peers":[{"public_key":"PEERPUB"}]},
			"account":{"license":"lic","warp_plus":false,"premium_data":0,"account_type":"free"}}`))
	}))
	defer srv.Close()
	old := RegBase
	RegBase = srv.URL
	defer func() { RegBase = old }()

	acct, err := Register(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acct.PeerPublicKey != "PEERPUB" {
		t.Errorf("peer public key = %q", acct.PeerPublicKey)
	}
	if acct.DeviceID != "dev-1" || acct.Token != "tok-1" {
		t.Errorf("device id/token not captured: %q %q — without them no license can ever be attached",
			acct.DeviceID, acct.Token)
	}
	// The prefix matters: these become interface addresses, and a bare address
	// is not a valid one.
	if acct.V4 != "172.16.0.2/32" || acct.V6 != "2606:4700:110:8::1/128" {
		t.Errorf("addresses = %q %q, want them carried with their prefix", acct.V4, acct.V6)
	}
	if acct.Endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want the default so the account is dialable as registered", acct.Endpoint)
	}
}

// The regression guard for a defect that shipped in the first draft of this
// file: Cloudflare returns the account NESTED under "account" when registering
// and FLAT at the top level when a license is updated. Decoding the second with
// the first's shape reads warp_plus from a field that is not there, so every
// successful activation reports "still not WARP+".
func TestActivateLicenseReadsTheFlatAccountShape(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body["license"] != "LICENSE-KEY" {
			t.Errorf("license body = %v, want the key under \"license\"", body)
		}
		// Flat, exactly as Cloudflare answers, including role as a STRING —
		// declaring it a bool made the whole decode fail.
		_, _ = w.Write([]byte(`{"id":"dev-1","warp_plus":true,"premium_data":1000,
			"quota":1000,"role":"child","created":"","updated":"",
			"referral_count":0,"referral_renewal_countdown":0}`))
	}))
	defer srv.Close()
	old := RegBase
	RegBase = srv.URL + "/v0a4005/reg"
	defer func() { RegBase = old }()

	acct := Account{PrivateKey: "k", PeerPublicKey: "p", DeviceID: "dev-1", Token: "tok-1"}
	got, err := ActivateLicense(context.Background(), srv.Client(), acct, "LICENSE-KEY")
	if err != nil {
		t.Fatalf("ActivateLicense: %v", err)
	}
	if !got.Premium {
		t.Fatal("warp_plus was true in the reply and Premium is false — the flat account shape is not being read")
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT (Cloudflare's UpdateAccount)", gotMethod)
	}
	if gotPath != "/v0a4005/reg/dev-1/account" {
		t.Errorf("path = %s, want /v0a4005/reg/{deviceId}/account", gotPath)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("auth = %q, want the device token as a bearer", gotAuth)
	}
}

// A key that is well-formed but spent or already bound comes back 200 with
// warp_plus still false. Reporting that as success tells the operator they have
// a plan they do not have.
func TestASpentLicenseIsAFailureEvenThoughCloudflareAnswers200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"dev-1","warp_plus":false,"premium_data":0,"quota":0,"role":"free"}`))
	}))
	defer srv.Close()
	old := RegBase
	RegBase = srv.URL + "/reg"
	defer func() { RegBase = old }()

	_, err := ActivateLicense(context.Background(), srv.Client(),
		Account{DeviceID: "dev-1", Token: "t"}, "SPENT")
	if err == nil {
		t.Fatal("a 200 with warp_plus false was reported as a successful activation")
	}
}

func TestActivateLicenseRefusesAnAccountItCannotIdentify(t *testing.T) {
	_, err := ActivateLicense(context.Background(), nil, Account{}, "KEY")
	if err == nil {
		t.Fatal("activating without a device id or token must fail before any request is made")
	}
}

// Xray reads the dialling key from PrivateKey and sing-box reads it from
// PeerPrivateKey. Setting only one produces a config that renders, validates,
// and carries nothing on whichever core was not considered — so this asserts
// through BOTH real renderers rather than on the struct.
func TestTheOutboundRendersOnBothCores(t *testing.T) {
	acct := Account{
		PrivateKey: "OURKEY", PeerPublicKey: "CFPUB", ClientID: "AQID",
		V4: "172.16.0.2/32", V6: "2606:4700:110:8::1/128",
		Endpoint: "162.159.192.1:2408",
	}
	n, err := Node(acct)
	if err != nil {
		t.Fatalf("Node: %v", err)
	}

	out, err := render.XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	if out["protocol"] != "wireguard" {
		t.Fatalf("xray protocol = %v, want wireguard", out["protocol"])
	}
	// Xray nests the protocol's own fields under "settings"; asserting at the
	// top level passes nil comparisons and proves nothing.
	x, ok := out["settings"].(map[string]any)
	if !ok {
		t.Fatalf("xray settings is %T, not an object", out["settings"])
	}
	if x["secretKey"] != "OURKEY" {
		t.Errorf("xray secretKey = %v, want our private key", x["secretKey"])
	}
	if r, ok := x["reserved"].([]int); !ok || len(r) != 3 || r[0] != 1 {
		t.Errorf("xray reserved = %v, want the decoded client id; without it Cloudflare drops the session", x["reserved"])
	}
	if x["mtu"] != DefaultMTU {
		t.Errorf("xray mtu = %v, want %d — WireGuard's default black-holes large packets through WARP", x["mtu"], DefaultMTU)
	}
	peers, ok := x["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("xray peers = %v, want exactly one", x["peers"])
	}
	peer, _ := peers[0].(map[string]any)
	if peer["publicKey"] != "CFPUB" {
		t.Errorf("xray peer publicKey = %v", peer["publicKey"])
	}
	if peer["endpoint"] != "162.159.192.1:2408" {
		t.Errorf("xray peer endpoint = %v, want the account's endpoint", peer["endpoint"])
	}

	sb, err := render.SingboxOutbounds(n)
	if err != nil {
		t.Fatalf("SingboxOutbounds: %v", err)
	}
	if len(sb) == 0 {
		t.Fatal("sing-box rendered no outbound")
	}
	if sb[0]["private_key"] != "OURKEY" {
		t.Errorf("sing-box private_key = %v, want our private key — it reads PeerPrivateKey, not PrivateKey, "+
			"so setting only one field yields a silent, non-carrying outbound here", sb[0]["private_key"])
	}
	if sb[0]["peer_public_key"] != "CFPUB" {
		t.Errorf("sing-box peer_public_key = %v", sb[0]["peer_public_key"])
	}
	if sb[0]["server"] != "162.159.192.1" || sb[0]["server_port"] != 2408 {
		t.Errorf("sing-box endpoint = %v:%v, want the account's endpoint", sb[0]["server"], sb[0]["server_port"])
	}
}

func TestNodeRefusesAnAccountThatCannotDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		acct Account
	}{
		{"no key", Account{PeerPublicKey: "p", V4: "172.16.0.2/32"}},
		{"no peer", Account{PrivateKey: "k", V4: "172.16.0.2/32"}},
		{"no address", Account{PrivateKey: "k", PeerPublicKey: "p"}},
		{"bad endpoint", Account{PrivateKey: "k", PeerPublicKey: "p", V4: "1.2.3.4/32", Endpoint: "nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Node(tc.acct); err == nil {
				t.Fatal("built an outbound from an account that cannot carry traffic")
			}
		})
	}
}

// Rotation exists to change the address a censor sees. Returning the address
// already in use would make a scheduled rotation a no-op that still logs.
func TestRotationNeverReturnsTheEndpointInUse(t *testing.T) {
	for _, cur := range Endpoints {
		for i := 0; i < 20; i++ {
			if got := NextEndpoint(cur); got == cur {
				t.Fatalf("NextEndpoint(%q) returned the current endpoint", cur)
			}
		}
	}
	// A pool of one has nowhere to go, and must say so by staying put rather
	// than returning empty.
	old := Endpoints
	Endpoints = []string{"only:1"}
	defer func() { Endpoints = old }()
	if got := NextEndpoint("only:1"); got != "only:1" {
		t.Errorf("with a single-entry pool NextEndpoint = %q, want it unchanged", got)
	}
}
