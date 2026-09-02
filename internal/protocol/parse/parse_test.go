package parse

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func mustURI(t *testing.T, raw string) *model.Node {
	t.Helper()
	n, err := URI(raw)
	if err != nil {
		t.Fatalf("URI(%q): %v", raw, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// scheme dispatch
// ---------------------------------------------------------------------------

func TestURISchemeDispatch(t *testing.T) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(
		`{"v":"2","ps":"vm","add":"1.2.3.4","port":"443","id":"`+testUUID+`","net":"tcp"}`))
	cases := []struct {
		raw       string
		wantProto model.Protocol
		wantAddr  string
		wantPort  int
	}{
		{"vless://" + testUUID + "@1.2.3.4:443?type=tcp&security=none", model.ProtoVLESS, "1.2.3.4", 443},
		{vmess, model.ProtoVMess, "1.2.3.4", 443},
		{"trojan://pw@1.2.3.4:443", model.ProtoTrojan, "1.2.3.4", 443},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@1.2.3.4:8388", model.ProtoShadowsocks, "1.2.3.4", 8388},
		{"socks://1.2.3.4:1080", model.ProtoSOCKS, "1.2.3.4", 1080},
		{"socks5://1.2.3.4:1080", model.ProtoSOCKS, "1.2.3.4", 1080},
		{"http://1.2.3.4:8080", model.ProtoHTTP, "1.2.3.4", 8080},
		{"https://1.2.3.4:8443", model.ProtoHTTP, "1.2.3.4", 8443},
		{"hysteria2://pw@1.2.3.4:443", model.ProtoHysteria2, "1.2.3.4", 443},
		{"hy2://pw@1.2.3.4:443", model.ProtoHysteria2, "1.2.3.4", 443},
		{"tuic://" + testUUID + ":pw@1.2.3.4:443", model.ProtoTUIC, "1.2.3.4", 443},
		{"anytls://pw@1.2.3.4:443", model.ProtoAnyTLS, "1.2.3.4", 443},
		{"wireguard://sk@1.2.3.4:51820?publickey=pk", model.ProtoWireGuard, "1.2.3.4", 51820},
		{"wg://sk@1.2.3.4:51820?publickey=pk", model.ProtoWireGuard, "1.2.3.4", 51820},
		{"brook://server?password=pw&server=1.2.3.4%3A9999", model.ProtoBrook, "1.2.3.4", 9999},
		{"ssh://root@1.2.3.4:22", model.ProtoSSH, "1.2.3.4", 22},
		{"forgedns://stormdns@t.example.com", model.ProtoForgeDNS, "t.example.com", 53},
		// The scheme match is case-insensitive.
		{"VLESS://" + testUUID + "@1.2.3.4:443", model.ProtoVLESS, "1.2.3.4", 443},
	}
	for _, c := range cases {
		t.Run(string(c.wantProto)+"/"+c.raw[:min(12, len(c.raw))], func(t *testing.T) {
			n := mustURI(t, c.raw)
			if n.Protocol != c.wantProto {
				t.Errorf("protocol = %q, want %q", n.Protocol, c.wantProto)
			}
			if n.Address != c.wantAddr {
				t.Errorf("address = %q, want %q", n.Address, c.wantAddr)
			}
			if n.Port != c.wantPort {
				t.Errorf("port = %d, want %d", n.Port, c.wantPort)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestURIRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantSub string
	}{
		{"empty", "", "not a URI"},
		{"no scheme separator", "vless:1.2.3.4:443", "not a URI"},
		{"unsupported scheme", "carrier-pigeon://a:1", "unsupported scheme"},
		{"vless without port", "vless://" + testUUID + "@1.2.3.4", "missing port"},
		{"vless bad port", "vless://" + testUUID + "@1.2.3.4:https", "bad port"},
		{"vless bad query", "vless://" + testUUID + "@1.2.3.4:443?a=%zz", "bad query"},
		{"vless unterminated ipv6", "vless://" + testUUID + "@[::1:443", "bad IPv6 literal"},
		{"vless ipv6 without port", "vless://" + testUUID + "@[::1]", "missing port"},
		{"trojan without port", "trojan://pw@1.2.3.4", "missing port"},
		{"vmess not base64", "vmess://!!!!not-base64!!!!", "base64"},
		{"vmess not json", "vmess://" + base64.StdEncoding.EncodeToString([]byte("plain text")), "json"},
		{"ss legacy not base64", "ss://!!!!", "ss:"},
		{"ss legacy without host", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")), "malformed legacy link"},
		{"ss sip002 without port", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@1.2.3.4", "missing port"},
		{"ss legacy bad hostport", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw@1.2.3.4")), "missing port"},
		{"socks without port", "socks://1.2.3.4", "missing port"},
		{"http malformed", "http://[::1", "missing ']'"},
		{"hysteria2 without port", "hysteria2://pw@1.2.3.4", "missing port"},
		{"tuic without port", "tuic://" + testUUID + ":pw@1.2.3.4", "missing port"},
		{"anytls without port", "anytls://pw@1.2.3.4", "missing port"},
		{"wireguard without port", "wireguard://sk@1.2.3.4", "missing port"},
		{"brook without server", "brook://server?password=pw", "brook:"},
		{"ssh without port", "ssh://root@1.2.3.4", "missing port"},
		{"forgedns without adapter", "forgedns://t.example.com", "expected adapter@zone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := URI(c.raw)
			if err == nil {
				t.Fatalf("URI(%q) = %+v, want an error", c.raw, n)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("URI(%q) = %v, want it to mention %q", c.raw, err, c.wantSub)
			}
		})
	}
}

func TestTruncKeepsErrorsShort(t *testing.T) {
	long := strings.Repeat("x", 100)
	if got := trunc(long); len([]rune(got)) != 49 || !strings.HasSuffix(got, "…") {
		t.Fatalf("trunc(100 chars) = %q (%d runes), want 48 chars plus an ellipsis", got, len([]rune(got)))
	}
	if got := trunc("short"); got != "short" {
		t.Fatalf("trunc(%q) = %q, want it unchanged", "short", got)
	}
}

// ---------------------------------------------------------------------------
// low-level splitters
// ---------------------------------------------------------------------------

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  string
	}{
		{"1.2.3.4:443", "1.2.3.4", 443, ""},
		{"example.com:8443", "example.com", 8443, ""},
		{"example.com:8443/", "example.com", 8443, ""},
		{"[2001:db8::1]:443", "2001:db8::1", 443, ""},
		{"example.com", "example.com", 0, "missing port"},
		{"example.com:https", "", 0, "bad port"},
		{"[2001:db8::1", "", 0, "bad IPv6 literal"},
		{"[2001:db8::1]443", "2001:db8::1", 0, "missing port"},
	}
	for _, c := range cases {
		host, port, err := splitHostPort(c.in)
		if c.wantErr != "" {
			if err == nil {
				t.Errorf("splitHostPort(%q) = (%q,%d,nil), want error %q", c.in, host, port, c.wantErr)
			} else if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("splitHostPort(%q) error = %v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitHostPort(%q): %v", c.in, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestDecodeFragment(t *testing.T) {
	cases := map[string]string{
		"plain":                    "plain",
		"with%20space":             "with space",
		"%F0%9F%87%AE%F0%9F%87%B7": "🇮🇷",
		"a+b":                      "a+b", // PathUnescape keeps "+" literal
		"%zz":                      "%zz", // undecodable input is passed through verbatim
	}
	for in, want := range cases {
		if got := decodeFragment(in); got != want {
			t.Errorf("decodeFragment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseLinkSplitsUserQueryFragment(t *testing.T) {
	l, err := parseLink("vless://user%40name@[2001:db8::1]:443?type=ws&path=%2Fws#My%20Node", "vless")
	if err != nil {
		t.Fatalf("parseLink: %v", err)
	}
	if l.user != "user%40name" {
		t.Errorf("user = %q, want the raw userinfo", l.user)
	}
	if l.host != "2001:db8::1" || l.port != 443 {
		t.Errorf("host:port = %q:%d", l.host, l.port)
	}
	if l.query.Get("type") != "ws" || l.query.Get("path") != "/ws" {
		t.Errorf("query = %v", l.query)
	}
	if l.frag != "My Node" {
		t.Errorf("fragment = %q, want %q", l.frag, "My Node")
	}
	// No query at all still yields a usable (empty) url.Values.
	l2, err := parseLink("vless://u@a.com:1", "vless")
	if err != nil {
		t.Fatalf("parseLink without query: %v", err)
	}
	if l2.query == nil || len(l2.query) != 0 {
		t.Errorf("query = %v, want an empty non-nil url.Values", l2.query)
	}
}

// ---------------------------------------------------------------------------
// transport / security query parameters
// ---------------------------------------------------------------------------

func TestApplyTransportSecurityNetworks(t *testing.T) {
	cases := []struct {
		name  string
		query string
		check func(*testing.T, *model.Node)
	}{
		{"ws", "type=ws&path=/ws&host=cdn.example.com", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetWS || n.Transport.Path != "/ws" || n.Transport.Host != "cdn.example.com" {
				t.Errorf("ws transport = %+v", n.Transport)
			}
		}},
		{"httpupgrade", "type=httpupgrade&path=/hu&host=hu.example.com", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetHTTPUpgrade || n.Transport.Path != "/hu" || n.Transport.Host != "hu.example.com" {
				t.Errorf("httpupgrade transport = %+v", n.Transport)
			}
		}},
		{"grpc gun", "type=grpc&serviceName=svc&mode=gun", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetGRPC || n.Transport.ServiceName != "svc" || n.Transport.MultiMode {
				t.Errorf("grpc transport = %+v", n.Transport)
			}
		}},
		{"grpc multi via gun alias", "type=gun&serviceName=svc&mode=multi", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetGRPC || !n.Transport.MultiMode {
				t.Errorf("gun alias transport = %+v", n.Transport)
			}
		}},
		{"xhttp", "type=xhttp&path=/xh&host=x.example.com&mode=stream-up", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetXHTTP || n.Transport.XHTTPMode != "stream-up" || n.Transport.Path != "/xh" {
				t.Errorf("xhttp transport = %+v", n.Transport)
			}
		}},
		{"splithttp alias leaves mode to Normalize", "type=splithttp&path=/xh", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetXHTTP || n.Transport.Path != "/xh" {
				t.Errorf("splithttp transport = %+v, want xhttp", n.Transport)
			}
			if n.Transport.XHTTPMode != "" {
				t.Errorf("mode = %q; with no mode= parameter the parser must leave it unset", n.Transport.XHTTPMode)
			}
			// Normalize is what supplies the "auto" default.
			n.Normalize()
			if n.Transport.XHTTPMode != "auto" {
				t.Errorf("mode after Normalize = %q, want auto", n.Transport.XHTTPMode)
			}
		}},
		{"h2", "type=h2&path=/h2&host=h2.example.com", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetH2 || n.Transport.Path != "/h2" || n.Transport.Host != "h2.example.com" {
				t.Errorf("h2 transport = %+v", n.Transport)
			}
		}},
		{"http alias of h2", "type=http&path=/h2", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetH2 {
				t.Errorf("http alias network = %q, want h2", n.Transport.Network)
			}
		}},
		{"kcp", "type=kcp&seed=s33d&headerType=srtp", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetMKCP || n.Transport.Seed != "s33d" {
				t.Errorf("kcp transport = %+v", n.Transport)
			}
			if n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "srtp" {
				t.Errorf("kcp header obfs = %+v", n.Transport.HeaderObfs)
			}
		}},
		{"mkcp alias without obfs", "type=mkcp&seed=s33d&headerType=none", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetMKCP {
				t.Errorf("network = %q, want kcp", n.Transport.Network)
			}
			if n.Transport.HeaderObfs != nil {
				t.Errorf("headerType=none must not create an obfuscation block: %+v", n.Transport.HeaderObfs)
			}
		}},
		{"quic", "type=quic&quicSecurity=aes-128-gcm&key=qk&headerType=utp", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetQUIC || n.Transport.QUICSecurity != "aes-128-gcm" || n.Transport.QUICKey != "qk" {
				t.Errorf("quic transport = %+v", n.Transport)
			}
			if n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "utp" {
				t.Errorf("quic header obfs = %+v", n.Transport.HeaderObfs)
			}
		}},
		{"quic security none", "type=quic&quicSecurity=none", func(t *testing.T, n *model.Node) {
			if n.Transport.QUICSecurity != "" {
				t.Errorf("quicSecurity = %q, want it treated as unset", n.Transport.QUICSecurity)
			}
		}},
		{"tcp with http obfs", "type=tcp&headerType=http&host=fake.example.com&path=/camo", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetTCP {
				t.Errorf("network = %q, want tcp", n.Transport.Network)
			}
			if n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "http" {
				t.Fatalf("tcp header obfs = %+v", n.Transport.HeaderObfs)
			}
			if n.Transport.Host != "fake.example.com" || n.Transport.Path != "/camo" {
				t.Errorf("tcp obfs host/path = %q %q", n.Transport.Host, n.Transport.Path)
			}
		}},
		{"missing type means tcp", "security=none", func(t *testing.T, n *model.Node) {
			if n.Transport.Network != model.NetTCP {
				t.Errorf("network = %q, want tcp", n.Transport.Network)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q, err := url.ParseQuery(c.query)
			if err != nil {
				t.Fatalf("bad test query: %v", err)
			}
			n := &model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: testUUID}
			applyTransportSecurity(n, q)
			c.check(t, n)
		})
	}
}

func TestApplyTransportSecuritySecurityLayer(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		q, _ := url.ParseQuery("security=tls&sni=s.example.com&alpn=h2,http/1.1&fp=firefox&allowInsecure=1&ech=ECHCFG")
		n := &model.Node{Protocol: model.ProtoVLESS}
		applyTransportSecurity(n, q)
		s := n.Security
		if s.Type != model.SecTLS || s.ServerName != "s.example.com" || s.Fingerprint != "firefox" || !s.AllowInsecure {
			t.Fatalf("tls security = %+v", s)
		}
		if !reflect.DeepEqual(s.ALPN, []string{"h2", "http/1.1"}) {
			t.Errorf("alpn = %v", s.ALPN)
		}
		if s.ECH == nil || !s.ECH.Enabled || s.ECH.ConfigList != "ECHCFG" {
			t.Errorf("ech = %+v", s.ECH)
		}
	})
	t.Run("xtls alias and allowInsecure=true", func(t *testing.T) {
		q, _ := url.ParseQuery("security=xtls&allowInsecure=true")
		n := &model.Node{Protocol: model.ProtoVLESS}
		applyTransportSecurity(n, q)
		if n.Security.Type != model.SecTLS || !n.Security.AllowInsecure {
			t.Fatalf("xtls security = %+v", n.Security)
		}
	})
	t.Run("reality", func(t *testing.T) {
		q, _ := url.ParseQuery("security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=0123abcd&spx=%2Fspider&pqv=VERIFY&alpn=h2")
		n := &model.Node{Protocol: model.ProtoVLESS}
		applyTransportSecurity(n, q)
		s := n.Security
		if s.Type != model.SecReality || s.ServerName != "www.apple.com" || s.Fingerprint != "chrome" {
			t.Fatalf("reality security = %+v", s)
		}
		if !reflect.DeepEqual(s.ALPN, []string{"h2"}) {
			t.Errorf("alpn = %v", s.ALPN)
		}
		r := s.Reality
		if r == nil || r.PublicKey != "PUBKEY" || r.ShortID != "0123abcd" || r.SpiderX != "/spider" || r.MLDSA65Verify != "VERIFY" {
			t.Fatalf("reality block = %+v", r)
		}
		if r.PrivateKey != "" {
			t.Error("a client link must never yield a REALITY private key")
		}
	})
	t.Run("unknown security is none", func(t *testing.T) {
		q, _ := url.ParseQuery("security=banana")
		n := &model.Node{Protocol: model.ProtoVLESS}
		applyTransportSecurity(n, q)
		if n.Security.Type != model.SecNone {
			t.Fatalf("security = %q, want none", n.Security.Type)
		}
	})
}

// ---------------------------------------------------------------------------
// per-protocol parsing detail
// ---------------------------------------------------------------------------

func TestParseVLESSFields(t *testing.T) {
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&pbk=PK&sid=0123abcd&sni=www.apple.com&fp=chrome#Iran%20Node")
	if n.UUID != testUUID || n.Flow != "xtls-rprx-vision" || n.Encryption != "none" {
		t.Fatalf("vless identity = %+v", n)
	}
	if n.Remark != "Iran Node" {
		t.Errorf("remark = %q", n.Remark)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("parsed node does not validate: %v", err)
	}
}

func TestParseVMessTransportsAndSecurity(t *testing.T) {
	enc := func(m string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(m)) }
	t.Run("ws tls", func(t *testing.T) {
		n := mustURI(t, enc(`{"v":"2","ps":"vm-ws","add":"a.com","port":"443","id":"`+testUUID+`","net":"ws","host":"cdn.a.com","path":"/vm","tls":"tls","sni":"cdn.a.com","fp":"chrome","alpn":"h2,http/1.1","scy":"aes-128-gcm"}`))
		if n.Transport.Network != model.NetWS || n.Transport.Host != "cdn.a.com" || n.Transport.Path != "/vm" {
			t.Fatalf("transport = %+v", n.Transport)
		}
		if n.Security.Type != model.SecTLS || n.Security.ServerName != "cdn.a.com" || n.Security.Fingerprint != "chrome" {
			t.Fatalf("security = %+v", n.Security)
		}
		if !reflect.DeepEqual(n.Security.ALPN, []string{"h2", "http/1.1"}) {
			t.Errorf("alpn = %v", n.Security.ALPN)
		}
		if n.Encryption != "aes-128-gcm" || n.Remark != "vm-ws" || n.Port != 443 {
			t.Errorf("node = %+v", n)
		}
	})
	t.Run("grpc multi", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":443,"id":"`+testUUID+`","net":"grpc","path":"svc","type":"multi"}`))
		if n.Transport.Network != model.NetGRPC || n.Transport.ServiceName != "svc" || !n.Transport.MultiMode {
			t.Fatalf("transport = %+v", n.Transport)
		}
		// A numeric port field (not a string) must still be honoured.
		if n.Port != 443 {
			t.Errorf("port = %d, want 443 from a JSON number", n.Port)
		}
		// Missing "scy" defaults to auto.
		if n.Encryption != "auto" {
			t.Errorf("encryption = %q, want auto", n.Encryption)
		}
	})
	t.Run("h2", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"h2","host":"h.a.com","path":"/h2"}`))
		if n.Transport.Network != model.NetH2 || n.Transport.Host != "h.a.com" || n.Transport.Path != "/h2" {
			t.Fatalf("transport = %+v", n.Transport)
		}
	})
	t.Run("httpupgrade", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"httpupgrade","host":"h.a.com","path":"/hu"}`))
		if n.Transport.Network != model.NetHTTPUpgrade || n.Transport.Path != "/hu" {
			t.Fatalf("transport = %+v", n.Transport)
		}
	})
	t.Run("kcp with obfs", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"kcp","path":"s33d","type":"srtp"}`))
		if n.Transport.Network != model.NetMKCP || n.Transport.Seed != "s33d" {
			t.Fatalf("transport = %+v", n.Transport)
		}
		if n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "srtp" {
			t.Fatalf("header obfs = %+v", n.Transport.HeaderObfs)
		}
	})
	t.Run("tcp http obfs", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"tcp","type":"http","host":"fake.com","path":"/camo"}`))
		if n.Transport.Network != model.NetTCP || n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "http" {
			t.Fatalf("transport = %+v", n.Transport)
		}
		if n.Transport.Host != "fake.com" || n.Transport.Path != "/camo" {
			t.Errorf("obfs host/path = %q %q", n.Transport.Host, n.Transport.Path)
		}
	})
	t.Run("reality", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"tcp","tls":"reality","sni":"www.apple.com","fp":"chrome","pbk":"PK","sid":"0123abcd"}`))
		if n.Security.Type != model.SecReality || n.Security.Reality == nil ||
			n.Security.Reality.PublicKey != "PK" || n.Security.Reality.ShortID != "0123abcd" {
			t.Fatalf("security = %+v / %+v", n.Security, n.Security.Reality)
		}
	})
	t.Run("non-string non-number field is ignored", func(t *testing.T) {
		n := mustURI(t, enc(`{"add":"a.com","port":"443","id":"`+testUUID+`","net":"tcp","ps":["not","a","string"]}`))
		if n.Remark != "" {
			t.Errorf("remark = %q, want empty for a non-scalar JSON value", n.Remark)
		}
	})
}

func TestParseShadowsocksUserinfoForms(t *testing.T) {
	t.Run("sip002 base64 userinfo", func(t *testing.T) {
		n := mustURI(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+b64Key(16)))+"@1.2.3.4:8388#SS")
		if n.Method != model.SS2022AES128 {
			t.Fatalf("method = %q", n.Method)
		}
		if n.Remark != "SS" {
			t.Errorf("remark = %q", n.Remark)
		}
		if err := n.Validate(); err != nil {
			t.Fatalf("parsed SS2022 node does not validate: %v", err)
		}
	})
	t.Run("plain percent-encoded userinfo", func(t *testing.T) {
		n := mustURI(t, "ss://aes-256-gcm:p%40ss@1.2.3.4:8388")
		if n.Method != model.SSAES256GCM || n.Password != "p@ss" {
			t.Fatalf("method/password = %q / %q", n.Method, n.Password)
		}
	})
	t.Run("legacy fully-base64 link", func(t *testing.T) {
		n := mustURI(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw@1.2.3.4:8388"))+"#Legacy")
		if n.Method != model.SSAES256GCM || n.Password != "pw" || n.Address != "1.2.3.4" || n.Port != 8388 {
			t.Fatalf("legacy node = %+v", n)
		}
		if n.Remark != "Legacy" {
			t.Errorf("remark = %q", n.Remark)
		}
	})
	t.Run("sip003 plugin", func(t *testing.T) {
		n := mustURI(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))+"@1.2.3.4:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls")
		if n.SSPlugin == nil {
			t.Fatal("plugin block missing")
		}
		if n.SSPlugin.Name != "v2ray-plugin" || n.SSPlugin.Opts != "mode=websocket;tls" {
			t.Fatalf("plugin = %+v", n.SSPlugin)
		}
	})
	t.Run("userinfo without a colon", func(t *testing.T) {
		n := mustURI(t, "ss://onlymethod@1.2.3.4:8388")
		if n.Method != "onlymethod" || n.Password != "" {
			t.Fatalf("method/password = %q / %q", n.Method, n.Password)
		}
	})
}

func b64Key(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

func TestParseSOCKSCredentialForms(t *testing.T) {
	t.Run("base64 userinfo", func(t *testing.T) {
		n := mustURI(t, "socks://"+base64.RawURLEncoding.EncodeToString([]byte("user:pass"))+"@1.2.3.4:1080#S")
		if n.Username != "user" || n.Password != "pass" || n.Remark != "S" {
			t.Fatalf("socks node = %+v", n)
		}
	})
	t.Run("plain userinfo", func(t *testing.T) {
		n := mustURI(t, "socks://user:pass@1.2.3.4:1080")
		if n.Username != "user" || n.Password != "pass" {
			t.Fatalf("socks node = %+v", n)
		}
	})
	t.Run("no credentials", func(t *testing.T) {
		n := mustURI(t, "socks5://1.2.3.4:1080")
		if n.Username != "" || n.Password != "" {
			t.Fatalf("socks node = %+v", n)
		}
	})
}

func TestParseHTTPProxy(t *testing.T) {
	n := mustURI(t, "http://user:p%40ss@1.2.3.4:8080#Proxy")
	if n.Username != "user" || n.Password != "p@ss" || n.Remark != "Proxy" {
		t.Fatalf("http node = %+v", n)
	}
	if n.Security.Type != model.SecNone {
		t.Errorf("http:// must not imply TLS, got %q", n.Security.Type)
	}
	s := mustURI(t, "https://1.2.3.4:8443")
	if s.Security.Type != model.SecTLS {
		t.Errorf("https:// must imply TLS, got %q", s.Security.Type)
	}
	if s.Username != "" {
		t.Errorf("username = %q, want empty", s.Username)
	}
}

func TestParseHysteria2Parameters(t *testing.T) {
	n := mustURI(t, "hy2://p%40ss@1.2.3.4:443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=opw&mport=20000-50000&hop_interval=30&up=100&down=200&pinSHA256=PIN#HY")
	if n.Password != "p@ss" || n.Remark != "HY" {
		t.Fatalf("node = %+v", n)
	}
	if n.Security.Type != model.SecTLS || n.Security.ServerName != "hy.example.com" || !n.Security.AllowInsecure {
		t.Fatalf("security = %+v", n.Security)
	}
	if !reflect.DeepEqual(n.Security.PinSHA256, []string{"PIN"}) {
		t.Errorf("pinSHA256 = %v", n.Security.PinSHA256)
	}
	h := n.Hysteria2
	if h.ObfsType != "salamander" || h.ObfsPassword != "opw" || h.PortHopping != "20000-50000" ||
		h.PortHopInterval != 30 || h.UpMbps != 100 || h.DownMbps != 200 {
		t.Fatalf("hysteria2 options = %+v", h)
	}
	// insecure=true is the other spelling clients emit.
	if !mustURI(t, "hysteria2://pw@1.2.3.4:443?insecure=true").Security.AllowInsecure {
		t.Error("insecure=true was not honoured")
	}
	// Without obfs the options block stays empty rather than half-populated.
	plain := mustURI(t, "hysteria2://pw@1.2.3.4:443")
	if plain.Hysteria2.ObfsType != "" || plain.Hysteria2.ObfsPassword != "" {
		t.Errorf("bare link produced obfs settings: %+v", plain.Hysteria2)
	}
}

func TestParseTUICParameters(t *testing.T) {
	n := mustURI(t, "tuic://"+testUUID+":p%40ss@1.2.3.4:443?sni=t.example.com&alpn=h3&allow_insecure=1&congestion_control=bbr&udp_relay_mode=quic#T")
	if n.UUID != testUUID || n.Password != "p@ss" {
		t.Fatalf("identity = %q / %q", n.UUID, n.Password)
	}
	if n.Security.Type != model.SecTLS || n.Security.ServerName != "t.example.com" || !n.Security.AllowInsecure {
		t.Fatalf("security = %+v", n.Security)
	}
	if !reflect.DeepEqual(n.Security.ALPN, []string{"h3"}) {
		t.Errorf("alpn = %v", n.Security.ALPN)
	}
	if n.TUIC.CongestionControl != "bbr" || n.TUIC.UDPRelayMode != "quic" {
		t.Fatalf("tuic options = %+v", n.TUIC)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("parsed TUIC node does not validate: %v", err)
	}
}

func TestParseAnyTLSDefaultsToTLS(t *testing.T) {
	n := mustURI(t, "anytls://p%40ss@1.2.3.4:443?sni=any.example.com&padding_scheme=stop%3D8%0A0%3D30-30#A")
	if n.Security.Type != model.SecTLS || n.Security.ServerName != "any.example.com" {
		t.Fatalf("security = %+v", n.Security)
	}
	if n.AnyTLS == nil || !reflect.DeepEqual(n.AnyTLS.PaddingScheme, []string{"stop=8", "0=30-30"}) {
		t.Fatalf("padding scheme = %+v", n.AnyTLS)
	}
	// An explicit security=none must be honoured (CDN-plain deployments).
	plain := mustURI(t, "anytls://pw@1.2.3.4:443?security=none")
	if plain.Security.Type != model.SecTLS {
		t.Fatalf("security = %q; AnyTLS is TLS by construction and Normalize must force it back", plain.Security.Type)
	}
}

func TestParseTrojanDefaultsToTLS(t *testing.T) {
	n := mustURI(t, "trojan://p%40ss@1.2.3.4:443?sni=t.example.com#T")
	if n.Security.Type != model.SecTLS || n.Security.ServerName != "t.example.com" {
		t.Fatalf("trojan without an explicit security must default to TLS: %+v", n.Security)
	}
	if n.Password != "p@ss" {
		t.Errorf("password = %q", n.Password)
	}
	// An explicit security=none is a legal CDN-plain deployment and must stick.
	plain := mustURI(t, "trojan://pw@1.2.3.4:80?security=none&type=ws&path=/t")
	if plain.Security.Type != model.SecNone {
		t.Fatalf("security = %q, want none", plain.Security.Type)
	}
	if plain.Transport.Network != model.NetWS {
		t.Errorf("network = %q, want ws", plain.Transport.Network)
	}
}

func TestParseWireGuardParameters(t *testing.T) {
	n := mustURI(t, "wg://SK%3D@1.2.3.4:51820?publickey=PK%3D&presharedkey=PSK%3D&address=10.0.0.2/32,fd00::2/128&mtu=1380&reserved=1,%202,3#WG")
	w := n.WireGuard
	if w == nil {
		t.Fatal("wireguard block missing")
	}
	if w.PrivateKey != "SK=" || w.PublicKey != "PK=" || w.PreSharedKey != "PSK=" {
		t.Fatalf("keys = %+v", w)
	}
	if !reflect.DeepEqual(w.LocalAddress, []string{"10.0.0.2/32", "fd00::2/128"}) {
		t.Errorf("addresses = %v", w.LocalAddress)
	}
	if w.MTU != 1380 {
		t.Errorf("mtu = %d", w.MTU)
	}
	if !reflect.DeepEqual(w.Reserved, []int{1, 2, 3}) {
		t.Errorf("reserved = %v (whitespace around entries must be tolerated)", w.Reserved)
	}
	// Without an explicit MTU, Normalize supplies the 1420 default.
	bare := mustURI(t, "wireguard://SK@1.2.3.4:51820?publickey=PK")
	if bare.WireGuard.MTU != 1420 {
		t.Errorf("default mtu = %d, want 1420", bare.WireGuard.MTU)
	}
}

func TestParseBrookModes(t *testing.T) {
	for _, mode := range []string{"server", "wsserver", "wssserver", "quicserver"} {
		n := mustURI(t, "brook://"+mode+"?password=pw&server=1.2.3.4%3A9999#B")
		if n.Brook == nil || n.Brook.Mode != mode {
			t.Fatalf("brook mode = %+v, want %q", n.Brook, mode)
		}
		if n.Password != "pw" || n.Address != "1.2.3.4" || n.Port != 9999 || n.Remark != "B" {
			t.Fatalf("brook node = %+v", n)
		}
	}
}

func TestParseSSHDropsCredentials(t *testing.T) {
	n := mustURI(t, "ssh://root@1.2.3.4:22#SSH")
	if n.SSH == nil || n.SSH.User != "root" {
		t.Fatalf("ssh block = %+v", n.SSH)
	}
	if n.SSH.Password != "" || n.SSH.PrivateKey != "" {
		t.Error("the ssh:// link carries no credential; none may be invented")
	}
	if n.Remark != "SSH" {
		t.Errorf("remark = %q", n.Remark)
	}
}

func TestParseForgeDNS(t *testing.T) {
	n := mustURI(t, "forgedns://StormDNS@Tunnel.Example.COM?key=psk&rr=txt&ns=ns1.example.com#DNS")
	f := n.ForgeDNS
	if f == nil {
		t.Fatal("forgedns block missing")
	}
	if f.Adapter != "stormdns" || f.Zone != "tunnel.example.com" || f.Key != "psk" || f.RRType != "TXT" || f.NSHost != "ns1.example.com" {
		t.Fatalf("forgedns options = %+v", f)
	}
	if n.Port != 53 {
		t.Errorf("port = %d, want the standard DNS port", n.Port)
	}
	if n.Remark != "DNS" {
		t.Errorf("remark = %q", n.Remark)
	}
	// Without a query the RR type still defaults to TXT.
	bare := mustURI(t, "forgedns://cottendns@z.example.com")
	if bare.ForgeDNS.RRType != "TXT" || bare.ForgeDNS.EDNSBuffer != 1232 {
		t.Fatalf("defaults = %+v", bare.ForgeDNS)
	}
}

func TestParsedNodesAreNormalized(t *testing.T) {
	// URI() must return a canonical node: Normalize has run, so protocol-specific
	// defaults are present and irrelevant fields are gone.
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?type=ws&path=/ws&security=none&flow=xtls-rprx-vision")
	if n.Encryption != "none" {
		t.Errorf("encryption = %q, want the vless default", n.Encryption)
	}
	if n.Flow != "" {
		t.Errorf("flow = %q; Vision is meaningless over ws and must be dropped", n.Flow)
	}
}

// ---------------------------------------------------------------------------
// round trip: parse(export(x)) == x
// ---------------------------------------------------------------------------

// TestRoundTripExtendedMatrix complements the package-level property test with
// the transport and security combinations it does not reach.
func TestRoundTripExtendedMatrix(t *testing.T) {
	tls := func(sni string) model.Security {
		return model.Security{Type: model.SecTLS, ServerName: sni, Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}}
	}
	nodes := []*model.Node{
		{Remark: "vless-tcp-httpobfs-none", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 80, UUID: testUUID,
			Transport: model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"}},
		{Remark: "vless-httpupgrade-tls", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "a.example.com"}, Security: tls("a.example.com")},
		{Remark: "vless-h2-tls", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetH2, Path: "/h2", Host: "h.example.com"}, Security: tls("h.example.com")},
		{Remark: "vless-kcp-srtp", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 2443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetMKCP, Seed: "s33d", HeaderObfs: &model.Header{Type: "srtp"}}},
		{Remark: "vless-quic", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 2443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetQUIC, QUICSecurity: "aes-128-gcm", QUICKey: "qk", HeaderObfs: &model.Header{Type: "utp"}}},
		{Remark: "vless-ws-tls-insecure-ech", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetWS, Path: "/ws", Host: "a.example.com"},
			Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com", AllowInsecure: true,
				Fingerprint: "safari", ECH: &model.ECH{Enabled: true, ConfigList: "ECHCFG"}}},
		{Remark: "vless-xhttp-reality-pq", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetXHTTP, Path: "/xh", XHTTPMode: "stream-one"},
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com", Fingerprint: "chrome",
				Reality: &model.Reality{PublicKey: "PK", ShortID: "0123abcd", SpiderX: "/spider", MLDSA65Verify: "VERIFY"}}},
		{Remark: "vmess-grpc-multi", Protocol: model.ProtoVMess, Address: "a.example.com", Port: 443, UUID: testUUID,
			Encryption: "auto", Transport: model.Transport{Network: model.NetGRPC, ServiceName: "svc", MultiMode: true}},
		{Remark: "vmess-kcp", Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 2443, UUID: testUUID,
			Encryption: "auto", Transport: model.Transport{Network: model.NetMKCP, Seed: "s33d", HeaderObfs: &model.Header{Type: "wechat-video"}}},
		{Remark: "vmess-tcp-httpobfs", Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 80, UUID: testUUID,
			Encryption: "auto", Transport: model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"}},
		{Remark: "vmess-httpupgrade", Protocol: model.ProtoVMess, Address: "a.example.com", Port: 443, UUID: testUUID,
			Encryption: "auto", Transport: model.Transport{Network: model.NetHTTPUpgrade, Host: "a.example.com", Path: "/hu"}},
		{Remark: "trojan-plain-ws", Protocol: model.ProtoTrojan, Address: "1.2.3.4", Port: 80, Password: "pw",
			Transport: model.Transport{Network: model.NetWS, Path: "/tj", Host: "cdn.example.com"}},
		{Remark: "ss-plugin", Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
			Method: model.SSAES128GCM, Password: "pw", SSPlugin: &model.SSPluginOptions{Name: "v2ray-plugin", Opts: "mode=websocket;tls"}},
		{Remark: "socks-open", Protocol: model.ProtoSOCKS, Address: "2.2.2.2", Port: 1080},
		{Remark: "https-proxy", Protocol: model.ProtoHTTP, Address: "3.3.3.3", Port: 8443, Security: model.Security{Type: model.SecTLS}},
		{Remark: "hy2-hopping", Protocol: model.ProtoHysteria2, Address: "4.4.4.4", Port: 443, Password: "pw",
			Security:  model.Security{Type: model.SecTLS, ServerName: "hy.example.com", AllowInsecure: true, ALPN: []string{"h3"}, PinSHA256: []string{"PIN"}},
			Hysteria2: &model.Hysteria2Options{PortHopping: "20000-50000", PortHopInterval: 30, UpMbps: 100, DownMbps: 200}},
		{Remark: "tuic-quic-relay", Protocol: model.ProtoTUIC, Address: "6.6.6.6", Port: 443, UUID: testUUID, Password: "pw",
			Security: model.Security{Type: model.SecTLS, ServerName: "tuic.example.com", ALPN: []string{"h3"}, AllowInsecure: true},
			TUIC:     &model.TUICOptions{CongestionControl: "cubic", UDPRelayMode: "quic"}},
		{Remark: "anytls-padding", Protocol: model.ProtoAnyTLS, Address: "7.7.7.7", Port: 443, Password: "pw",
			Security: tls("any.example.com"), AnyTLS: &model.AnyTLSOptions{PaddingScheme: []string{"stop=8", "0=30-30"}}},
		{Remark: "wireguard-psk", Protocol: model.ProtoWireGuard, Address: "8.8.8.8", Port: 51820,
			WireGuard: &model.WireGuardOptions{PrivateKey: "SK=", PublicKey: "PK=", PreSharedKey: "PSK=",
				LocalAddress: []string{"10.0.0.2/32"}, MTU: 1380, Reserved: []int{1, 2, 3}}},
		{Remark: "brook-wsserver", Protocol: model.ProtoBrook, Address: "10.10.10.10", Port: 9999, Password: "pw",
			Brook: &model.BrookOptions{Mode: "wsserver"}},
		{Remark: "forgedns-cottendns", Protocol: model.ProtoForgeDNS, Address: "t.example.com", Port: 53,
			ForgeDNS: &model.ForgeDNSOptions{Adapter: "cottendns", Zone: "t.example.com", Key: "k", RRType: "NULL", NSHost: "ns1.example.com"}},
	}
	for _, n := range nodes {
		t.Run(n.Remark, func(t *testing.T) {
			want := n.Clone()
			want.Normalize()
			uri, err := export.URI(want)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			got, err := URI(uri)
			if err != nil {
				t.Fatalf("parse(%q): %v", uri, err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("round-trip mismatch\n  uri:  %s\n  want: %+v\n  got:  %+v", uri, want, got)
			}
		})
	}
}

func TestRoundTripPreservesUnicodeRemarks(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
		Remark: "🇮🇷 تهران — Node #1", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	uri, err := export.URI(n)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	got, err := URI(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Remark != n.Remark {
		t.Fatalf("remark = %q, want %q", got.Remark, n.Remark)
	}
}
