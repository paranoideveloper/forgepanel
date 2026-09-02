package export

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The URI exporter reaches the security block directly and never goes through
// Node.SNI(), which is how the first version of this fix landed in a function
// the broken path does not call. The link is what the operator actually pastes
// into a client, so this asserts on the link.
//
// Measured on a live panel: an imported inbound with server_name=slashdot.org
// and serverNames=[www.cloudflare.com] produced a link that failed with "reality
// verification failed", while the identical client with www.cloudflare.com
// connected immediately.
func TestRealityLinkCarriesAnSNITheServerAccepts(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "972f1d1c-08e5-4485-a888-65688b5c7557", Flow: "xtls-rprx-vision",
		Security: model.Security{
			Type: model.SecReality, ServerName: "slashdot.org", Fingerprint: "firefox",
			Reality: &model.Reality{
				Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
				PublicKey: "GfOmSfw8Xx1eSuVdvjJgh0OS6dGKWNZ89KYF9SXwWQw", ShortID: "fd55b698ee8c3629",
			},
		},
	}
	n.Normalize()
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "sni=slashdot.org") {
		t.Errorf("the link advertises an SNI the server refuses; it cannot connect:\n%s", uri)
	}
	if !strings.Contains(uri, "sni=www.cloudflare.com") {
		t.Errorf("the link does not carry a server name this inbound accepts:\n%s", uri)
	}
}

// An SNI the server DOES accept is the operator's choice and must survive.
func TestRealityLinkKeepsAnAcceptedServerName(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "972f1d1c-08e5-4485-a888-65688b5c7557",
		Security: model.Security{
			Type: model.SecReality, ServerName: "www.microsoft.com",
			Reality: &model.Reality{
				ServerNames: []string{"www.cloudflare.com", "www.microsoft.com"},
				PublicKey:   "GfOmSfw8Xx1eSuVdvjJgh0OS6dGKWNZ89KYF9SXwWQw", ShortID: "fd55b698ee8c3629",
			},
		},
	}
	n.Normalize()
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "sni=www.microsoft.com") {
		t.Errorf("the operator's own server name was replaced:\n%s", uri)
	}
}

// Shadowsocks over WebSocket must be described the way a client can read it:
// SIP003's plugin field naming v2ray-plugin, with mux disabled.
//
// The first version of this emitted type/path/security query parameters, the
// same ones every other protocol's link carries. Nothing standard reads those
// on an ss:// URI, so a client parses SIP002, finds no plugin, and dials plain
// TCP Shadowsocks — the panel showing the inbound serving the whole time.
//
// mux=0 is load-bearing. v2ray-plugin defaults to mux=1 and wraps the stream in
// v2ray's mux protocol, which a plain Shadowsocks inbound does not speak: the
// WebSocket upgrade succeeds and the session dies reading metadata. Verified
// against a live deployment — mux=1 carried nothing, mux=0 connected every time.
func TestShadowsocksOverWebSocketIsExportedAsAPluginLink(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoShadowsocks, Address: "edge.example.com", Port: 443,
		Method: "2022-blake3-aes-128-gcm", Password: "hzQTq6OOqLCwxtin5RJ6jg==",
		Transport: model.Transport{Network: model.NetWS, Path: "/tunnel", Host: "edge.example.com"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "edge.example.com"},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := url.QueryUnescape(uri)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"plugin=v2ray-plugin", "tls", "mux=0", "host=edge.example.com", "path=/tunnel"} {
		if !strings.Contains(dec, want) {
			t.Errorf("link is missing %q, so no client can dial it: %s", want, dec)
		}
	}
	// The xray-style parameters must NOT be there: they are not read on an
	// ss:// URI and their presence was the original defect.
	if strings.Contains(dec, "type=ws") {
		t.Errorf("link still carries the query parameters nothing reads: %s", dec)
	}
}

// A plain TCP Shadowsocks link must stay the bare SIP002 form. Adding query
// parameters to it would be noise at best, and some clients are strict.
func TestPlainShadowsocksKeepsItsBareLink(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
		Method: "aes-256-gcm", Password: "pw",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecNone},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "?") {
		t.Errorf("a plain shadowsocks link grew a query string: %s", uri)
	}
}

// The external-plugin form describes its own transport and must win.
func TestAShadowsocksPluginLinkIsNotOverwrittenByTransportParams(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
		Method: "aes-256-gcm", Password: "pw",
		Transport: model.Transport{Network: model.NetWS, Path: "/x"},
		SSPlugin:  &model.SSPluginOptions{Name: "v2ray-plugin", Opts: "tls;host=example.com"},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "plugin=v2ray-plugin") {
		t.Fatalf("plugin lost: %s", uri)
	}
	if strings.Contains(uri, "type=ws") {
		t.Errorf("native transport params were added alongside a plugin: %s", uri)
	}
}

// A VMess link over XHTTP must carry the path and Host, like every other
// path-carrying transport. Omitting them yields a well-formed link to a server
// that never answers — and behind a shared port, where the path is the only
// thing identifying the inbound, it cannot possibly connect.
func TestVMessOverXHTTPCarriesItsPathAndHost(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVMess, Address: "edge.example.com", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetXHTTP, Path: "/tunnel", Host: "edge.example.com"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "edge.example.com"},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["net"] != "xhttp" {
		t.Fatalf("net=%v", m["net"])
	}
	if m["path"] != "/tunnel" {
		t.Errorf("path=%q — a client cannot reach the inbound without it", m["path"])
	}
	if m["host"] != "edge.example.com" {
		t.Errorf("host=%q", m["host"])
	}
}
