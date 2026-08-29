package export

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// uriQuery re-parses an exported link's query so assertions can be made on the
// individual parameters rather than on a brittle whole-string comparison.
func uriQuery(t *testing.T, uri string) url.Values {
	t.Helper()
	body := uri
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	i := strings.Index(body, "?")
	if i < 0 {
		return url.Values{}
	}
	q, err := url.ParseQuery(body[i+1:])
	if err != nil {
		t.Fatalf("exported link has an unparseable query: %v (%s)", err, uri)
	}
	return q
}

func mustExport(t *testing.T, n *model.Node) string {
	t.Helper()
	uri, err := URI(n)
	if err != nil {
		t.Fatalf("URI(%s): %v", n.Protocol, err)
	}
	return uri
}

func wantParams(t *testing.T, q url.Values, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("query %q = %q, want %q (full query: %v)", k, got, v, q)
		}
	}
}

func wantNoParams(t *testing.T, q url.Values, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := q[k]; ok {
			t.Errorf("query must not contain %q, got %q", k, q.Get(k))
		}
	}
}

// ---------------------------------------------------------------------------
// hostPort / frag
// ---------------------------------------------------------------------------

func TestHostPortBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":       "1.2.3.4:443",
		"example.com":   "example.com:443",
		"2001:db8::1":   "[2001:db8::1]:443",
		"[2001:db8::1]": "[2001:db8::1]:443", // already bracketed, not double-wrapped
	}
	for addr, want := range cases {
		if got := hostPort(addr, 443); got != want {
			t.Errorf("hostPort(%q,443) = %q, want %q", addr, got, want)
		}
	}
}

func TestFrag(t *testing.T) {
	if got := frag(""); got != "" {
		t.Errorf("frag(\"\") = %q, want empty", got)
	}
	if got := frag("My Node"); got != "#My%20Node" {
		t.Errorf("frag = %q", got)
	}
	if got := frag("🇮🇷"); !strings.HasPrefix(got, "#%") {
		t.Errorf("frag = %q, want a percent-escaped fragment", got)
	}
}

func TestEncodeQueryEmpty(t *testing.T) {
	if got := encodeQuery(url.Values{}); got != "" {
		t.Errorf("encodeQuery(empty) = %q", got)
	}
	if got := encodeQuery(url.Values{"b": {"2"}, "a": {"1"}}); got != "a=1&b=2" {
		t.Errorf("encodeQuery = %q, want deterministically sorted keys", got)
	}
}

// ---------------------------------------------------------------------------
// transportSecurityParams: every transport and every security layer
// ---------------------------------------------------------------------------

func TestTransportSecurityParamsPerTransport(t *testing.T) {
	cases := []struct {
		name   string
		tr     model.Transport
		want   map[string]string
		absent []string
	}{
		{"tcp bare", model.Transport{Network: model.NetTCP},
			map[string]string{"type": "tcp"}, []string{"headerType", "host", "path"}},
		{"tcp http obfs", model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"},
			map[string]string{"type": "tcp", "headerType": "http", "host": "fake.example.com", "path": "/camo"}, nil},
		{"tcp non-http obfs is not a link parameter", model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "srtp"}},
			map[string]string{"type": "tcp"}, []string{"headerType"}},
		{"ws", model.Transport{Network: model.NetWS, Path: "/ws", Host: "cdn.example.com"},
			map[string]string{"type": "ws", "path": "/ws", "host": "cdn.example.com"}, nil},
		{"ws bare", model.Transport{Network: model.NetWS},
			map[string]string{"type": "ws"}, []string{"path", "host"}},
		{"httpupgrade", model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "hu.example.com"},
			map[string]string{"type": "httpupgrade", "path": "/hu", "host": "hu.example.com"}, nil},
		{"grpc gun", model.Transport{Network: model.NetGRPC, ServiceName: "svc"},
			map[string]string{"type": "grpc", "serviceName": "svc", "mode": "gun"}, nil},
		{"grpc multi", model.Transport{Network: model.NetGRPC, ServiceName: "svc", MultiMode: true},
			map[string]string{"type": "grpc", "mode": "multi"}, nil},
		{"grpc without a service name", model.Transport{Network: model.NetGRPC},
			map[string]string{"type": "grpc", "mode": "gun"}, []string{"serviceName"}},
		{"xhttp", model.Transport{Network: model.NetXHTTP, Path: "/xh", Host: "x.example.com", XHTTPMode: "stream-up"},
			map[string]string{"type": "xhttp", "path": "/xh", "host": "x.example.com", "mode": "stream-up"}, nil},
		{"xhttp auto mode is the default and is not emitted", model.Transport{Network: model.NetXHTTP, XHTTPMode: "auto"},
			map[string]string{"type": "xhttp"}, []string{"mode", "path", "host"}},
		{"h2", model.Transport{Network: model.NetH2, Path: "/h2", Host: "h.example.com"},
			map[string]string{"type": "h2", "path": "/h2", "host": "h.example.com"}, nil},
		{"h2 bare", model.Transport{Network: model.NetH2},
			map[string]string{"type": "h2"}, []string{"path", "host"}},
		{"mkcp", model.Transport{Network: model.NetMKCP, Seed: "s33d", HeaderObfs: &model.Header{Type: "srtp"}},
			map[string]string{"type": "kcp", "seed": "s33d", "headerType": "srtp"}, nil},
		{"mkcp bare", model.Transport{Network: model.NetMKCP},
			map[string]string{"type": "kcp"}, []string{"seed", "headerType"}},
		{"quic", model.Transport{Network: model.NetQUIC, QUICSecurity: "aes-128-gcm", QUICKey: "qk", HeaderObfs: &model.Header{Type: "utp"}},
			map[string]string{"type": "quic", "quicSecurity": "aes-128-gcm", "key": "qk", "headerType": "utp"}, nil},
		{"quic with security none", model.Transport{Network: model.NetQUIC, QUICSecurity: "none"},
			map[string]string{"type": "quic"}, []string{"quicSecurity", "key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID, Transport: c.tr}
			n.Normalize()
			q := uriQuery(t, mustExport(t, n))
			wantParams(t, q, c.want)
			wantNoParams(t, q, c.absent...)
		})
	}
}

func TestTransportSecurityParamsSecurityLayers(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 80, UUID: testUUID}
		n.Normalize()
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"security": "none"})
		wantNoParams(t, q, "sni", "alpn", "fp", "pbk")
	})
	t.Run("tls with every knob", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com", ALPN: []string{"h2", "http/1.1"},
				Fingerprint: "firefox", AllowInsecure: true, ECH: &model.ECH{Enabled: true, ConfigList: "ECHCFG"}}}
		n.Normalize()
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"security": "tls", "sni": "a.example.com",
			"alpn": "h2,http/1.1", "fp": "firefox", "allowInsecure": "1", "ech": "ECHCFG"})
	})
	t.Run("tls minimal", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecTLS}}
		n.Normalize()
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"security": "tls"})
		wantNoParams(t, q, "sni", "alpn", "fp", "allowInsecure", "ech")
	})
	t.Run("reality", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com", Fingerprint: "safari",
				ALPN: []string{"h2"},
				Reality: &model.Reality{PublicKey: "PK", PrivateKey: "SERVER-ONLY-SK", ShortID: "0123abcd",
					SpiderX: "/spider", MLDSA65Verify: "VERIFY", MLDSA65Seed: "SERVER-ONLY-SEED",
					Dest: "www.apple.com:443", ServerNames: []string{"www.apple.com"}}}}
		n.Normalize()
		uri := mustExport(t, n)
		q := uriQuery(t, uri)
		wantParams(t, q, map[string]string{"security": "reality", "sni": "www.apple.com", "fp": "safari",
			"pbk": "PK", "sid": "0123abcd", "spx": "/spider", "pqv": "VERIFY", "alpn": "h2"})
		// Server-only secrets must never reach a client link.
		if strings.Contains(uri, "SERVER-ONLY-SK") || strings.Contains(uri, "SERVER-ONLY-SEED") {
			t.Fatalf("a server-only REALITY secret leaked into the client link: %s", uri)
		}
	})
	t.Run("reality defaults the fingerprint and hides the default spiderX", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com",
				Reality: &model.Reality{PublicKey: "PK", ShortIDs: []string{"00ff", "0123abcd"}}}}
		n.Normalize() // sets SpiderX to "/"
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"fp": "chrome", "sid": "00ff"})
		wantNoParams(t, q, "spx", "pqv")
	})
	t.Run("reality without a block", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com"}}
		n.Normalize()
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"security": "reality"})
		wantNoParams(t, q, "pbk", "sid")
	})
}

// ---------------------------------------------------------------------------
// per-protocol link shape
// ---------------------------------------------------------------------------

func TestVLESSURIShape(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
		Flow: "xtls-rprx-vision", Encryption: "mlkem768x25519plus", Remark: "My Node",
		Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	uri := mustExport(t, n)
	if !strings.HasPrefix(uri, "vless://"+testUUID+"@1.2.3.4:443?") {
		t.Fatalf("uri = %s", uri)
	}
	if !strings.HasSuffix(uri, "#My%20Node") {
		t.Errorf("fragment missing from %s", uri)
	}
	wantParams(t, uriQuery(t, uri), map[string]string{"flow": "xtls-rprx-vision", "encryption": "mlkem768x25519plus"})

	// The default encryption "none" is implicit and is not emitted.
	plain := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID}
	plain.Normalize()
	wantNoParams(t, uriQuery(t, mustExport(t, plain)), "encryption", "flow")
}

func TestTrojanAndAnyTLSURIShape(t *testing.T) {
	tj := &model.Node{Protocol: model.ProtoTrojan, Address: "1.2.3.4", Port: 443, Password: "p@ss word/!",
		Flow: "xtls-rprx-vision", Security: model.Security{Type: model.SecTLS, ServerName: "t.example.com"},
		Transport: model.Transport{Network: model.NetTCP}}
	tj.Normalize()
	uri := mustExport(t, tj)
	if !strings.HasPrefix(uri, "trojan://"+url.QueryEscape("p@ss word/!")+"@1.2.3.4:443?") {
		t.Fatalf("trojan uri = %s", uri)
	}
	// Normalize strips flow from non-VLESS protocols, so it must not appear.
	wantNoParams(t, uriQuery(t, uri), "flow")

	at := &model.Node{Protocol: model.ProtoAnyTLS, Address: "7.7.7.7", Port: 443, Password: "anypw", Remark: "AT",
		Security: model.Security{Type: model.SecTLS, ServerName: "any.example.com"},
		AnyTLS:   &model.AnyTLSOptions{PaddingScheme: []string{"stop=8", "0=30-30"}}}
	at.Normalize()
	atURI := mustExport(t, at)
	if !strings.HasPrefix(atURI, "anytls://anypw@7.7.7.7:443?") {
		t.Fatalf("anytls uri = %s", atURI)
	}
	wantParams(t, uriQuery(t, atURI), map[string]string{"padding_scheme": "stop=8\n0=30-30", "sni": "any.example.com"})

	// No padding scheme means no parameter.
	bare := &model.Node{Protocol: model.ProtoAnyTLS, Address: "7.7.7.7", Port: 443, Password: "pw"}
	bare.Normalize()
	wantNoParams(t, uriQuery(t, mustExport(t, bare)), "padding_scheme")
}

func TestVMessURIPerTransport(t *testing.T) {
	decode := func(t *testing.T, uri string) map[string]any {
		t.Helper()
		if !strings.HasPrefix(uri, "vmess://") {
			t.Fatalf("uri = %s", uri)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "vmess://"))
		if err != nil {
			t.Fatalf("vmess payload is not standard base64: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("vmess payload is not JSON: %v (%s)", err, raw)
		}
		return m
	}
	base := func(tr model.Transport, sec model.Security) *model.Node {
		n := &model.Node{Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Remark: "VM", Transport: tr, Security: sec}
		n.Normalize()
		return n
	}
	t.Run("envelope", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetTCP}, model.Security{})))
		for k, want := range map[string]any{"v": "2", "ps": "VM", "add": "1.2.3.4", "port": "443",
			"id": testUUID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": ""} {
			if m[k] != want {
				t.Errorf("%q = %v, want %v", k, m[k], want)
			}
		}
	})
	t.Run("ws", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetWS, Host: "cdn.example.com", Path: "/vm"}, model.Security{})))
		if m["net"] != "ws" || m["host"] != "cdn.example.com" || m["path"] != "/vm" {
			t.Fatalf("vmess ws = %v", m)
		}
	})
	t.Run("httpupgrade", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetHTTPUpgrade, Host: "hu.example.com", Path: "/hu"}, model.Security{})))
		if m["net"] != "httpupgrade" || m["host"] != "hu.example.com" {
			t.Fatalf("vmess httpupgrade = %v", m)
		}
	})
	t.Run("grpc gun and multi", func(t *testing.T) {
		gun := decode(t, mustExport(t, base(model.Transport{Network: model.NetGRPC, ServiceName: "svc"}, model.Security{})))
		if gun["net"] != "grpc" || gun["path"] != "svc" || gun["type"] != "gun" {
			t.Fatalf("vmess grpc = %v", gun)
		}
		multi := decode(t, mustExport(t, base(model.Transport{Network: model.NetGRPC, ServiceName: "svc", MultiMode: true}, model.Security{})))
		if multi["type"] != "multi" {
			t.Errorf("vmess grpc multi type = %v", multi["type"])
		}
	})
	t.Run("h2", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetH2, Host: "h.example.com", Path: "/h2"}, model.Security{})))
		if m["net"] != "h2" || m["host"] != "h.example.com" || m["path"] != "/h2" {
			t.Fatalf("vmess h2 = %v", m)
		}
	})
	t.Run("tcp http obfs", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetTCP,
			HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"}, model.Security{})))
		if m["net"] != "tcp" || m["type"] != "http" || m["host"] != "fake.example.com" || m["path"] != "/camo" {
			t.Fatalf("vmess tcp obfs = %v", m)
		}
	})
	t.Run("mkcp", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetMKCP, Seed: "s33d",
			HeaderObfs: &model.Header{Type: "wechat-video"}}, model.Security{})))
		if m["net"] != "kcp" || m["type"] != "wechat-video" || m["path"] != "s33d" {
			t.Fatalf("vmess mkcp = %v", m)
		}
		bare := decode(t, mustExport(t, base(model.Transport{Network: model.NetMKCP, Seed: "s33d"}, model.Security{})))
		if bare["type"] != "none" {
			t.Errorf("vmess mkcp without obfs type = %v, want none", bare["type"])
		}
	})
	t.Run("tls", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetTCP},
			model.Security{Type: model.SecTLS, ServerName: "s.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}})))
		if m["tls"] != "tls" || m["sni"] != "s.example.com" || m["fp"] != "chrome" || m["alpn"] != "h2,http/1.1" {
			t.Fatalf("vmess tls = %v", m)
		}
	})
	t.Run("reality", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetTCP},
			model.Security{Type: model.SecReality, ServerName: "www.apple.com", Fingerprint: "chrome",
				Reality: &model.Reality{PublicKey: "PK", ShortID: "0123abcd"}})))
		if m["tls"] != "reality" || m["pbk"] != "PK" || m["sid"] != "0123abcd" || m["sni"] != "www.apple.com" {
			t.Fatalf("vmess reality = %v", m)
		}
	})
	t.Run("reality without a block", func(t *testing.T) {
		m := decode(t, mustExport(t, base(model.Transport{Network: model.NetTCP},
			model.Security{Type: model.SecReality, ServerName: "www.apple.com"})))
		if m["tls"] != "reality" {
			t.Fatalf("vmess reality = %v", m)
		}
		if _, ok := m["pbk"]; ok {
			t.Errorf("pbk = %v, want absent", m["pbk"])
		}
	})
}

func TestNetForVMess(t *testing.T) {
	cases := map[model.Network]string{
		model.NetH2: "h2", model.NetHTTPUpgrade: "httpupgrade", model.NetMKCP: "kcp",
		model.NetTCP: "tcp", model.NetWS: "ws", model.NetGRPC: "grpc", model.NetXHTTP: "xhttp",
	}
	for net, want := range cases {
		if got := netForVMess(net); got != want {
			t.Errorf("netForVMess(%q) = %q, want %q", net, got, want)
		}
	}
}

func TestShadowsocksURI(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
		Method: model.SSAES256GCM, Password: "pw", Remark: "SS"}
	n.Normalize()
	uri := mustExport(t, n)
	userinfo := strings.TrimSuffix(strings.TrimPrefix(uri, "ss://"), "@1.2.3.4:8388#SS")
	raw, err := base64.RawURLEncoding.DecodeString(userinfo)
	if err != nil {
		t.Fatalf("userinfo is not raw-url base64: %v (%s)", err, uri)
	}
	if string(raw) != model.SSAES256GCM+":pw" {
		t.Fatalf("userinfo decodes to %q", raw)
	}
	// SIP003 plugin, with and without options.
	withOpts := n.Clone()
	withOpts.SSPlugin = &model.SSPluginOptions{Name: "v2ray-plugin", Opts: "mode=websocket;tls"}
	wantParams(t, uriQuery(t, mustExport(t, withOpts)), map[string]string{"plugin": "v2ray-plugin;mode=websocket;tls"})

	nameOnly := n.Clone()
	nameOnly.SSPlugin = &model.SSPluginOptions{Name: "obfs-local"}
	wantParams(t, uriQuery(t, mustExport(t, nameOnly)), map[string]string{"plugin": "obfs-local"})

	// An empty plugin name emits no parameter at all.
	empty := n.Clone()
	empty.SSPlugin = &model.SSPluginOptions{}
	if uri := mustExport(t, empty); strings.Contains(uri, "?") {
		t.Errorf("an empty plugin block produced a query: %s", uri)
	}
}

func TestSOCKSAndHTTPURIs(t *testing.T) {
	t.Run("socks with credentials", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080, Username: "u", Password: "p", Remark: "S"}
		n.Normalize()
		uri := mustExport(t, n)
		want := "socks://" + base64.RawURLEncoding.EncodeToString([]byte("u:p")) + "@1.2.3.4:1080#S"
		if uri != want {
			t.Fatalf("uri = %q, want %q", uri, want)
		}
	})
	t.Run("socks without credentials", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080}
		n.Normalize()
		if uri := mustExport(t, n); uri != "socks://1.2.3.4:1080" {
			t.Fatalf("uri = %q", uri)
		}
	})
	t.Run("http with credentials", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8080, Username: "u", Password: "p@ss"}
		n.Normalize()
		if uri := mustExport(t, n); uri != "http://u:p%40ss@1.2.3.4:8080" {
			t.Fatalf("uri = %q", uri)
		}
	})
	t.Run("https without credentials", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8443, Security: model.Security{Type: model.SecTLS}}
		n.Normalize()
		if uri := mustExport(t, n); uri != "https://1.2.3.4:8443" {
			t.Fatalf("uri = %q, want the https scheme for a TLS proxy", uri)
		}
	})
}

func TestHysteria2URIParameters(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoHysteria2, Address: "1.2.3.4", Port: 443, Password: "p@ss", Remark: "HY",
		Security: model.Security{Type: model.SecTLS, ServerName: "hy.example.com", AllowInsecure: true, PinSHA256: []string{"PIN"}},
		Hysteria2: &model.Hysteria2Options{ObfsType: "salamander", ObfsPassword: "opw",
			PortHopping: "20000-50000", PortHopInterval: 30, UpMbps: 100, DownMbps: 200}}
	n.Normalize()
	uri := mustExport(t, n)
	if !strings.HasPrefix(uri, "hysteria2://p%40ss@1.2.3.4:443?") || !strings.HasSuffix(uri, "#HY") {
		t.Fatalf("uri = %s", uri)
	}
	wantParams(t, uriQuery(t, uri), map[string]string{"sni": "hy.example.com", "insecure": "1",
		"obfs": "salamander", "obfs-password": "opw", "mport": "20000-50000",
		"hop_interval": "30", "up": "100", "down": "200", "pinSHA256": "PIN"})

	bare := &model.Node{Protocol: model.ProtoHysteria2, Address: "1.2.3.4", Port: 443, Password: "pw"}
	bare.Normalize()
	bareURI := mustExport(t, bare)
	if strings.Contains(bareURI, "?") {
		t.Errorf("a bare hysteria2 node produced a query: %s", bareURI)
	}
}

func TestTUICURIParameters(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoTUIC, Address: "1.2.3.4", Port: 443, UUID: testUUID, Password: "p@ss", Remark: "T",
		Security: model.Security{Type: model.SecTLS, ServerName: "t.example.com", ALPN: []string{"h3"}, AllowInsecure: true},
		TUIC:     &model.TUICOptions{CongestionControl: "cubic", UDPRelayMode: "quic"}}
	n.Normalize()
	uri := mustExport(t, n)
	if !strings.HasPrefix(uri, "tuic://"+testUUID+":p%40ss@1.2.3.4:443?") {
		t.Fatalf("uri = %s", uri)
	}
	wantParams(t, uriQuery(t, uri), map[string]string{"sni": "t.example.com", "alpn": "h3",
		"allow_insecure": "1", "congestion_control": "cubic", "udp_relay_mode": "quic"})
}

func TestWireGuardURI(t *testing.T) {
	t.Run("uses the server private key when present", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820, Remark: "WG",
			WireGuard: &model.WireGuardOptions{PrivateKey: "SK=", PeerPrivateKey: "CLI-SK=", PublicKey: "PK=",
				PreSharedKey: "PSK=", LocalAddress: []string{"10.0.0.2/32", "fd00::2/128"}, MTU: 1380, Reserved: []int{1, 2, 3}}}
		n.Normalize()
		uri := mustExport(t, n)
		if !strings.HasPrefix(uri, "wireguard://"+url.QueryEscape("SK=")+"@1.2.3.4:51820?") {
			t.Fatalf("uri = %s", uri)
		}
		wantParams(t, uriQuery(t, uri), map[string]string{"publickey": "PK=", "presharedkey": "PSK=",
			"address": "10.0.0.2/32,fd00::2/128", "mtu": "1380", "reserved": "1,2,3"})
	})
	t.Run("falls back to the peer private key", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820,
			WireGuard: &model.WireGuardOptions{PeerPrivateKey: "CLI-SK", PublicKey: "PK"}}
		n.Normalize()
		uri := mustExport(t, n)
		if !strings.HasPrefix(uri, "wireguard://CLI-SK@") {
			t.Fatalf("uri = %s", uri)
		}
		wantNoParams(t, uriQuery(t, uri), "presharedkey", "address", "reserved")
	})
}

func TestBrookURIModes(t *testing.T) {
	// The parameter naming the server is called after the MODE, and for every
	// mode except a plain server its value is a URL with a scheme — and, for the
	// WebSocket modes, the path. Taken from the pinned binary's own output:
	//
	//	brook link -s ws://1.2.3.4:9999/mypath -p pw
	//	  -> brook://wsserver?password=pw&wsserver=ws%3A%2F%2F1.2.3.4%3A9999%2Fmypath
	//
	// Emitting server=host:port for all four, as this did, produced a link
	// missing both the parameter the client reads and the path the server routes
	// on — for three of the four modes.
	for _, tc := range []struct{ mode, key, want string }{
		{"server", "server", "1.2.3.4:9999"},
		{"wsserver", "wsserver", "ws://1.2.3.4:9999/tunnel"},
		{"wssserver", "wssserver", "wss://1.2.3.4:9999/tunnel"},
		{"quicserver", "quicserver", "quic://1.2.3.4:9999"},
	} {
		n := &model.Node{Protocol: model.ProtoBrook, Address: "1.2.3.4", Port: 9999, Password: "pw", Remark: "B",
			Brook: &model.BrookOptions{Mode: tc.mode, Path: "/tunnel"}}
		n.Normalize()
		uri := mustExport(t, n)
		if !strings.HasPrefix(uri, "brook://"+tc.mode+"?") || !strings.HasSuffix(uri, "#B") {
			t.Fatalf("uri = %s", uri)
		}
		wantParams(t, uriQuery(t, uri), map[string]string{"password": "pw", tc.key: tc.want})
	}
	// A node with no Brook block defaults to the plain server mode.
	n := &model.Node{Protocol: model.ProtoBrook, Address: "1.2.3.4", Port: 9999, Password: "pw"}
	n.Normalize()
	if uri := mustExport(t, n); !strings.HasPrefix(uri, "brook://server?") {
		t.Fatalf("uri = %s, want the server default", uri)
	}
}

func TestSSHAndForgeDNSURIs(t *testing.T) {
	t.Run("ssh", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoSSH, Address: "1.2.3.4", Port: 22, Remark: "SSH",
			SSH: &model.SSHOptions{User: "root", Password: "SECRET", PrivateKey: "SECRET-KEY"}}
		n.Normalize()
		uri := mustExport(t, n)
		if uri != "ssh://root@1.2.3.4:22#SSH" {
			t.Fatalf("uri = %q", uri)
		}
		if strings.Contains(uri, "SECRET") {
			t.Fatal("the ssh:// link must not embed credentials")
		}
	})
	t.Run("ssh without a user", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoSSH, Address: "1.2.3.4", Port: 22}
		n.Normalize()
		if uri := mustExport(t, n); uri != "ssh://1.2.3.4:22" {
			t.Fatalf("uri = %q", uri)
		}
	})
	t.Run("forgedns", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoForgeDNS, Address: "t.example.com", Port: 53, Remark: "DNS",
			ForgeDNS: &model.ForgeDNSOptions{Adapter: "stormdns", Zone: "t.example.com", Key: "psk",
				RRType: "TXT", NSHost: "ns1.example.com"}}
		n.Normalize()
		uri := mustExport(t, n)
		if !strings.HasPrefix(uri, "forgedns://stormdns@t.example.com?") || !strings.HasSuffix(uri, "#DNS") {
			t.Fatalf("uri = %s", uri)
		}
		wantParams(t, uriQuery(t, uri), map[string]string{"key": "psk", "rr": "TXT", "ns": "ns1.example.com"})
	})
	t.Run("forgedns minimal", func(t *testing.T) {
		n := &model.Node{Protocol: model.ProtoForgeDNS, Address: "z.example.com", Port: 53,
			ForgeDNS: &model.ForgeDNSOptions{Adapter: "masterdns", Zone: "z.example.com"}}
		n.Normalize() // RRType defaults to TXT, so "rr" is always present
		q := uriQuery(t, mustExport(t, n))
		wantParams(t, q, map[string]string{"rr": "TXT"})
		wantNoParams(t, q, "key", "ns")
	})
}

func TestURIRejectsProtocolsWithoutAStandaloneLink(t *testing.T) {
	t.Run("shadowtls", func(t *testing.T) {
		_, err := URI(&model.Node{Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443,
			ShadowTLS: &model.ShadowTLSOptions{Password: "hs"}})
		if err == nil {
			t.Fatal("URI accepted shadowtls")
		}
		if !strings.Contains(err.Error(), "no standalone URI") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("amneziawg", func(t *testing.T) {
		_, err := URI(&model.Node{Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
			AmneziaWG: &model.AmneziaWGOptions{}})
		if err == nil {
			t.Fatal("URI accepted amneziawg; it is exported as an awg-quick config, not a link")
		}
		if !strings.Contains(err.Error(), "unsupported protocol") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if _, err := URI(&model.Node{Protocol: model.Protocol("carrier-pigeon"), Address: "a", Port: 1}); err == nil {
			t.Fatal("URI accepted an unknown protocol")
		}
	})
}

func TestURIDoesNotMutateItsInput(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
		Transport: model.Transport{Network: ""}, Security: model.Security{Type: ""}}
	before := n.Clone()
	if _, err := URI(n); err != nil {
		t.Fatalf("URI: %v", err)
	}
	if !reflect.DeepEqual(before, n) {
		t.Fatalf("URI mutated its input\nbefore: %+v\nafter:  %+v", before, n)
	}
}

func TestSortedKeys(t *testing.T) {
	got := SortedKeys(map[string]int{"c": 3, "a": 1, "b": 2})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("SortedKeys = %v", got)
	}
	if got := SortedKeys(map[string]any{}); len(got) != 0 {
		t.Fatalf("SortedKeys(empty) = %v", got)
	}
}
