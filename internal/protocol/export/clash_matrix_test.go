package export

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func mustClash(t *testing.T, n *model.Node) map[string]any {
	t.Helper()
	p, err := ClashProxy(n)
	if err != nil {
		t.Fatalf("ClashProxy(%s): %v", n.Protocol, err)
	}
	return p
}

func wantKeys(t *testing.T, p map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		got, ok := p[k]
		if !ok {
			t.Errorf("key %q missing (proxy: %v)", k, p)
			continue
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("key %q = %#v, want %#v", k, got, v)
		}
	}
}

func wantNoKeys(t *testing.T, p map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := p[k]; ok {
			t.Errorf("key %q must not be emitted, got %#v", k, v)
		}
	}
}

// ---------------------------------------------------------------------------
// ClashProxy per protocol
// ---------------------------------------------------------------------------

func TestClashProxyPerProtocol(t *testing.T) {
	cases := []struct {
		name  string
		node  *model.Node
		check func(*testing.T, map[string]any)
	}{
		{
			name: "vless reality",
			node: &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
				Flow: "xtls-rprx-vision", Remark: "VL", Transport: model.Transport{Network: model.NetTCP},
				Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com",
					Reality: &model.Reality{PublicKey: "PK", ShortID: "0123abcd"}}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"name": "VL", "type": "vless", "server": "1.2.3.4", "port": 443,
					"uuid": testUUID, "udp": true, "flow": "xtls-rprx-vision", "servername": "www.apple.com",
					"client-fingerprint": "chrome"})
				wantKeys(t, p, map[string]any{"reality-opts": map[string]any{"public-key": "PK", "short-id": "0123abcd"}})
				// Plain TCP is Clash's default and carries no "network" key. The
				// VLESS family does spell the TLS layer with an explicit flag.
				wantNoKeys(t, p, "network")
				wantKeys(t, p, map[string]any{"tls": true})
			},
		},
		{
			name: "vmess ws tls",
			node: &model.Node{Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 443, UUID: testUUID,
				Encryption: "auto", Transport: model.Transport{Network: model.NetWS, Path: "/vm", Host: "cdn.example.com"},
				Security: model.Security{Type: model.SecTLS, ServerName: "cdn.example.com", Fingerprint: "chrome"}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "vmess", "alterId": 0, "cipher": "auto",
					"network": "ws", "tls": true, "servername": "cdn.example.com", "client-fingerprint": "chrome"})
				ws := p["ws-opts"].(map[string]any)
				if ws["path"] != "/vm" {
					t.Errorf("ws-opts = %v", ws)
				}
				if h := ws["headers"].(map[string]any); h["Host"] != "cdn.example.com" {
					t.Errorf("ws headers = %v", h)
				}
				wantNoKeys(t, ws, "v2ray-http-upgrade")
			},
		},
		{
			name: "vmess without an explicit cipher",
			node: &model.Node{Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 443, UUID: testUUID},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"cipher": "auto"})
			},
		},
		{
			name: "trojan grpc",
			node: &model.Node{Protocol: model.ProtoTrojan, Address: "1.2.3.4", Port: 443, Password: "pw", Flow: "",
				Transport: model.Transport{Network: model.NetGRPC, ServiceName: "svc"},
				Security:  model.Security{Type: model.SecTLS, ServerName: "t.example.com"}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "trojan", "password": "pw", "network": "grpc",
					"sni": "t.example.com", "grpc-opts": map[string]any{"grpc-service-name": "svc"}})
				// Trojan is TLS by definition in Clash.Meta: there is no "tls" key.
				wantNoKeys(t, p, "tls", "servername")
			},
		},
		{
			name: "shadowsocks with a plugin",
			node: &model.Node{Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
				Method: model.SSAES128GCM, Password: "pw",
				SSPlugin:  &model.SSPluginOptions{Name: "obfs-local", Opts: "obfs=http;obfs-host=example.com"},
				Multiplex: &model.Multiplex{Enabled: true, MaxConns: 4, MinStreams: 2, MaxStreams: 8, Padding: true}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "ss", "cipher": model.SSAES128GCM, "password": "pw", "udp": true,
					"plugin": "obfs"}) // Clash spells simple-obfs "obfs"
				wantKeys(t, p, map[string]any{"plugin-opts": map[string]any{"obfs": "http", "obfs-host": "example.com"}})
				wantKeys(t, p, map[string]any{"smux": map[string]any{"enabled": true, "protocol": "smux",
					"max-connections": 4, "min-streams": 2, "max-streams": 8, "padding": true}})
			},
		},
		{
			name: "socks5 with credentials",
			node: &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080, Username: "u", Password: "p",
				Security: model.Security{Type: model.SecTLS, ServerName: "s.example.com"}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "socks5", "username": "u", "password": "p",
					"tls": true, "sni": "s.example.com"})
			},
		},
		{
			name: "socks5 open",
			node: &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080},
			check: func(t *testing.T, p map[string]any) {
				wantNoKeys(t, p, "username", "password", "tls", "sni")
			},
		},
		{
			name: "http",
			node: &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8080, Username: "u", Password: "p"},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "http", "username": "u", "password": "p"})
				wantNoKeys(t, p, "tls")
			},
		},
		{
			name:  "http open",
			node:  &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8080},
			check: func(t *testing.T, p map[string]any) { wantNoKeys(t, p, "username", "password") },
		},
		{
			name: "hysteria2",
			node: &model.Node{Protocol: model.ProtoHysteria2, Address: "1.2.3.4", Port: 443, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "hy.example.com", AllowInsecure: true, PinSHA256: []string{"PIN"}},
				Hysteria2: &model.Hysteria2Options{UpMbps: 100, DownMbps: 200, ObfsType: "salamander",
					ObfsPassword: "opw", PortHopping: "20000-50000", PortHopInterval: 30}},
			check: func(t *testing.T, p map[string]any) {
				// mihomo parses up/down as bandwidth strings, not bare integers.
				wantKeys(t, p, map[string]any{"type": "hysteria2", "up": "100 Mbps", "down": "200 Mbps",
					"obfs": "salamander", "obfs-password": "opw", "ports": "20000-50000", "hop-interval": 30,
					"sni": "hy.example.com", "skip-cert-verify": true, "fingerprint": "PIN"})
				wantKeys(t, p, map[string]any{"alpn": []any{"h3"}})
				wantNoKeys(t, p, "tls")
			},
		},
		{
			name: "hysteria2 minimal",
			node: &model.Node{Protocol: model.ProtoHysteria2, Address: "1.2.3.4", Port: 443, Password: "pw"},
			check: func(t *testing.T, p map[string]any) {
				wantNoKeys(t, p, "up", "down", "obfs", "obfs-password", "ports", "hop-interval")
			},
		},
		{
			name: "tuic",
			node: &model.Node{Protocol: model.ProtoTUIC, Address: "1.2.3.4", Port: 443, UUID: testUUID, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "t.example.com"},
				TUIC: &model.TUICOptions{CongestionControl: "bbr", UDPRelayMode: "quic", ZeroRTTHandshake: true,
					HeartbeatSeconds: 10, DisableSNI: true}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "tuic", "uuid": testUUID, "password": "pw",
					"congestion-controller": "bbr", "udp-relay-mode": "quic", "reduce-rtt": true,
					"heartbeat-interval": 10000, "disable-sni": true, "sni": "t.example.com"})
			},
		},
		{
			name: "tuic minimal",
			node: &model.Node{Protocol: model.ProtoTUIC, Address: "1.2.3.4", Port: 443, UUID: testUUID, Password: "pw"},
			check: func(t *testing.T, p map[string]any) {
				// Normalize supplies bbr/native, so only the optional knobs are absent.
				wantNoKeys(t, p, "reduce-rtt", "heartbeat-interval", "disable-sni")
			},
		},
		{
			name: "anytls",
			node: &model.Node{Protocol: model.ProtoAnyTLS, Address: "1.2.3.4", Port: 443, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "any.example.com"},
				AnyTLS:   &model.AnyTLSOptions{IdleSessionCheckInterval: 30, IdleSessionTimeout: 60, MinIdleSessions: 2}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "anytls", "idle-session-check-interval": 30,
					"idle-session-timeout": 60, "min-idle-session": 2, "sni": "any.example.com"})
			},
		},
		{
			name: "anytls minimal",
			node: &model.Node{Protocol: model.ProtoAnyTLS, Address: "1.2.3.4", Port: 443, Password: "pw"},
			check: func(t *testing.T, p map[string]any) {
				wantNoKeys(t, p, "idle-session-check-interval", "idle-session-timeout", "min-idle-session")
			},
		},
		{
			name: "wireguard splits ip and ipv6",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK", PreSharedKey: "PSK",
					LocalAddress: []string{"10.0.0.2/32", "fd00::2/128"}, AllowedIPs: []string{"0.0.0.0/0"},
					MTU: 1380, Keepalive: 25, Reserved: []int{1, 2, 3}}},
			check: func(t *testing.T, p map[string]any) {
				wantKeys(t, p, map[string]any{"type": "wireguard", "private-key": "SK", "public-key": "PK",
					"pre-shared-key": "PSK", "ip": "10.0.0.2/32", "ipv6": "fd00::2/128",
					"mtu": 1380, "persistent-keepalive": 25})
				wantKeys(t, p, map[string]any{"allowed-ips": []any{"0.0.0.0/0"}, "reserved": []any{1, 2, 3}})
			},
		},
		{
			name: "wireguard minimal",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK"}},
			check: func(t *testing.T, p map[string]any) {
				wantNoKeys(t, p, "pre-shared-key", "ip", "ipv6", "allowed-ips", "persistent-keepalive", "reserved")
				// Normalize supplies the 1420 MTU default.
				wantKeys(t, p, map[string]any{"mtu": 1420})
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.check(t, mustClash(t, c.node))
		})
	}
}

func TestClashProxyUnsupported(t *testing.T) {
	cases := map[string]*model.Node{
		"shadowtls":              {Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &model.ShadowTLSOptions{Password: "hs"}},
		"ssh":                    {Protocol: model.ProtoSSH, Address: "a", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
		"brook":                  {Protocol: model.ProtoBrook, Address: "a", Port: 9999, Password: "pw"},
		"forgedns":               {Protocol: model.ProtoForgeDNS, Address: "a", Port: 53, ForgeDNS: &model.ForgeDNSOptions{Zone: "z", Adapter: "stormdns"}},
		"wireguard without keys": {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820},
		"xhttp transport": {Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetXHTTP}},
		"vmess over xhttp": {Protocol: model.ProtoVMess, Address: "a", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetXHTTP}},
		"trojan over xhttp": {Protocol: model.ProtoTrojan, Address: "a", Port: 443, Password: "pw",
			Transport: model.Transport{Network: model.NetXHTTP}},
		"mkcp transport": {Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetMKCP}},
		"quic transport": {Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: testUUID,
			Transport: model.Transport{Network: model.NetQUIC}},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ClashProxy(n)
			if err == nil {
				t.Fatal("ClashProxy accepted a node Clash.Meta cannot express")
			}
			if !errors.Is(err, ErrUnsupportedByClash) {
				t.Fatalf("error = %v, want it to wrap ErrUnsupportedByClash so subscriptions can skip the node", err)
			}
		})
	}
	// An unknown protocol is a hard error, NOT a skippable one: it means the
	// caller handed us something the model itself does not know.
	_, err := ClashProxy(&model.Node{Protocol: model.Protocol("carrier-pigeon"), Address: "a", Port: 1})
	if err == nil {
		t.Fatal("ClashProxy accepted an unknown protocol")
	}
	if errors.Is(err, ErrUnsupportedByClash) {
		t.Fatal("an unknown protocol must not be silently skippable")
	}
}

func TestClashTransports(t *testing.T) {
	vless := func(tr model.Transport) *model.Node {
		return &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID, Transport: tr}
	}
	t.Run("tcp http obfuscation", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetTCP,
			HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"}))
		wantKeys(t, p, map[string]any{"network": "http"})
		opts := p["http-opts"].(map[string]any)
		wantKeys(t, opts, map[string]any{"method": "GET", "path": []any{"/camo"},
			"headers": map[string]any{"Host": []any{"fake.example.com"}}})
	})
	t.Run("tcp http obfuscation without a host", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}}))
		opts := p["http-opts"].(map[string]any)
		wantKeys(t, opts, map[string]any{"path": []any{"/"}})
		wantNoKeys(t, opts, "headers")
	})
	t.Run("httpupgrade is ws plus a flag", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "hu.example.com"}))
		wantKeys(t, p, map[string]any{"network": "ws"})
		ws := p["ws-opts"].(map[string]any)
		wantKeys(t, ws, map[string]any{"path": "/hu", "v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true})
	})
	t.Run("ws early data and extra headers", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetWS, Path: "/ws", Host: "cdn.example.com",
			Headers: map[string]string{"User-Agent": "UA"}, EarlyData: 2048}))
		ws := p["ws-opts"].(map[string]any)
		wantKeys(t, ws, map[string]any{"max-early-data": 2048, "early-data-header-name": "Sec-WebSocket-Protocol"})
		wantKeys(t, ws, map[string]any{"headers": map[string]any{"Host": "cdn.example.com", "User-Agent": "UA"}})
	})
	t.Run("ws with a custom early-data header", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetWS, EarlyData: 1, EDHeader: "X-ED"}))
		ws := p["ws-opts"].(map[string]any)
		wantKeys(t, ws, map[string]any{"path": "/", "early-data-header-name": "X-ED"})
		wantNoKeys(t, ws, "headers")
	})
	t.Run("h2", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetH2, Path: "/h2", Host: "h.example.com"}))
		wantKeys(t, p, map[string]any{"network": "h2"})
		wantKeys(t, p, map[string]any{"h2-opts": map[string]any{"path": "/h2", "host": []any{"h.example.com"}}})
	})
	t.Run("h2 without a host", func(t *testing.T) {
		p := mustClash(t, vless(model.Transport{Network: model.NetH2}))
		wantKeys(t, p, map[string]any{"h2-opts": map[string]any{"path": "/"}})
	})
}

func TestClashTLSDetails(t *testing.T) {
	t.Run("security none writes nothing", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 80, UUID: testUUID})
		wantNoKeys(t, p, "tls", "servername", "sni", "alpn", "skip-cert-verify", "client-fingerprint", "reality-opts", "ech-opts")
	})
	t.Run("a literal IP SNI is not emitted", func(t *testing.T) {
		// SNI() falls back to the address; sending an IP as the server name is
		// noise at best and a handshake failure at worst.
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecTLS}})
		wantKeys(t, p, map[string]any{"tls": true})
		wantNoKeys(t, p, "servername")
	})
	t.Run("ech", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com", ECH: &model.ECH{Enabled: true, ConfigList: "ECHCFG"}}})
		wantKeys(t, p, map[string]any{"ech-opts": map[string]any{"enable": true, "config": "ECHCFG"}})
	})
	t.Run("ech enabled without a config list", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com", ECH: &model.ECH{Enabled: true}}})
		wantKeys(t, p, map[string]any{"ech-opts": map[string]any{"enable": true}})
	})
	t.Run("reality without a block still gets a fingerprint", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com"}})
		wantKeys(t, p, map[string]any{"client-fingerprint": "chrome", "reality-opts": map[string]any{}})
	})
	t.Run("reality falls back to the first shortId", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com",
				Reality: &model.Reality{PublicKey: "PK", ShortIDs: []string{"00ff", "0123abcd"}}}})
		wantKeys(t, p, map[string]any{"reality-opts": map[string]any{"public-key": "PK", "short-id": "00ff"}})
	})
	t.Run("reality with no shortId at all", func(t *testing.T) {
		p := mustClash(t, &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443, UUID: testUUID,
			Security: model.Security{Type: model.SecReality, ServerName: "www.apple.com",
				Reality: &model.Reality{PublicKey: "PK"}}})
		wantKeys(t, p, map[string]any{"reality-opts": map[string]any{"public-key": "PK"}})
	})
}

func TestClashSSPluginAndOpts(t *testing.T) {
	base := func(pl *model.SSPluginOptions) *model.Node {
		return &model.Node{Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388,
			Method: model.SSAES128GCM, Password: "pw", SSPlugin: pl}
	}
	if p := mustClash(t, base(nil)); p["plugin"] != nil {
		t.Errorf("no plugin block must emit no plugin key, got %v", p["plugin"])
	}
	if p := mustClash(t, base(&model.SSPluginOptions{})); p["plugin"] != nil {
		t.Errorf("an empty plugin name must emit no plugin key, got %v", p["plugin"])
	}
	if p := mustClash(t, base(&model.SSPluginOptions{Name: "simple-obfs", Opts: "obfs=tls"})); p["plugin"] != "obfs" {
		t.Errorf("simple-obfs must be renamed to Clash's %q, got %v", "obfs", p["plugin"])
	}
	// A plugin with no options emits no plugin-opts map.
	p := mustClash(t, base(&model.SSPluginOptions{Name: "v2ray-plugin"}))
	wantKeys(t, p, map[string]any{"plugin": "v2ray-plugin"})
	wantNoKeys(t, p, "plugin-opts")
}

func TestParsePluginOpts(t *testing.T) {
	got := parsePluginOpts("mode=websocket;tls;host=example.com; ;path=/ws")
	want := map[string]any{"mode": "websocket", "tls": true, "host": "example.com", "path": "/ws"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePluginOpts = %#v, want %#v", got, want)
	}
	if got := parsePluginOpts(""); len(got) != 0 {
		t.Errorf("parsePluginOpts(\"\") = %v, want empty", got)
	}
}

func TestClashMuxOnlyWhenEnabled(t *testing.T) {
	base := func(m *model.Multiplex) *model.Node {
		return &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID, Multiplex: m}
	}
	wantNoKeys(t, mustClash(t, base(nil)), "smux")
	// Normalize drops a disabled multiplex block entirely.
	wantNoKeys(t, mustClash(t, base(&model.Multiplex{Enabled: false, MaxConns: 4})), "smux")
	p := mustClash(t, base(&model.Multiplex{Enabled: true, Protocol: "yamux"}))
	wantKeys(t, p, map[string]any{"smux": map[string]any{"enabled": true, "protocol": "yamux"}})
}

func TestFirstNonEmptyStr(t *testing.T) {
	if got := firstNonEmptyStr("", "", "c"); got != "c" {
		t.Errorf("firstNonEmptyStr = %q", got)
	}
	if got := firstNonEmptyStr("", ""); got != "" {
		t.Errorf("firstNonEmptyStr of all-empty = %q", got)
	}
}

func TestAnySlice(t *testing.T) {
	if got := anySlice([]string{"a", "b"}); !reflect.DeepEqual(got, []any{"a", "b"}) {
		t.Errorf("anySlice = %#v", got)
	}
	if got := anySlice(nil); !reflect.DeepEqual(got, []any{}) {
		t.Errorf("anySlice(nil) = %#v, want an empty slice", got)
	}
}

// ---------------------------------------------------------------------------
// naming
// ---------------------------------------------------------------------------

func TestClashName(t *testing.T) {
	cases := []struct {
		node *model.Node
		want string
	}{
		{&model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, Remark: "  My Node  ", Tag: "tag"}, "My Node"},
		{&model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, Tag: " tag "}, "tag"},
		{&model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443}, "vless-1.2.3.4:443"},
		{&model.Node{Protocol: model.ProtoVLESS, Address: "2001:db8::1", Port: 443}, "vless-[2001:db8::1]:443"},
	}
	for _, c := range cases {
		if got := clashName(c.node); got != c.want {
			t.Errorf("clashName(%+v) = %q, want %q", c.node, got, c.want)
		}
	}
}

func TestUniqueClashName(t *testing.T) {
	seen := map[string]int{}
	if got := uniqueClashName("Node", seen); got != "Node" {
		t.Fatalf("first = %q", got)
	}
	if got := uniqueClashName("Node", seen); got != "Node #2" {
		t.Fatalf("second = %q", got)
	}
	if got := uniqueClashName("Node", seen); got != "Node #3" {
		t.Fatalf("third = %q", got)
	}
	// A pre-existing collision with the generated suffix is skipped over.
	seen2 := map[string]int{"N": 1, "N #2": 1}
	if got := uniqueClashName("N", seen2); got != "N #3" {
		t.Fatalf("collision handling = %q, want %q", got, "N #3")
	}
}

// ---------------------------------------------------------------------------
// ClashYAML
// ---------------------------------------------------------------------------

func TestClashYAMLSkipsUnsupportedAndDeduplicates(t *testing.T) {
	nodes := []*model.Node{
		nil, // nil entries are tolerated
		{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID, Remark: "Node"},
		{Protocol: model.ProtoTrojan, Address: "1.2.3.5", Port: 443, Password: "pw", Remark: "Node"},
		{Protocol: model.ProtoSSH, Address: "1.2.3.6", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
		{Protocol: model.ProtoBrook, Address: "1.2.3.7", Port: 9999, Password: "pw"},
	}
	out, err := ClashYAML(nodes)
	if err != nil {
		t.Fatalf("ClashYAML: %v", err)
	}
	if !strings.Contains(out, "name: Node\n") {
		t.Errorf("first proxy name missing:\n%s", out)
	}
	if !strings.Contains(out, `name: "Node #2"`) {
		t.Errorf("the duplicate name was not disambiguated:\n%s", out)
	}
	// SSH and Brook have no Clash.Meta representation and must be skipped
	// silently rather than costing the user the whole subscription.
	if strings.Contains(out, "1.2.3.6") || strings.Contains(out, "1.2.3.7") {
		t.Errorf("an unsupported node leaked into the document:\n%s", out)
	}
	for _, want := range []string{"proxies:", "proxy-groups:", "name: PROXY", "type: select", "rules:", `- "MATCH,PROXY"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// The select group must list exactly the emitted proxies.
	if strings.Count(out, "- Node\n") == 0 {
		t.Errorf("select group does not list the proxies:\n%s", out)
	}
}

func TestClashYAMLEmptySubscriptionFallsBackToDIRECT(t *testing.T) {
	// An empty select group is a load error in Clash; DIRECT always exists.
	out, err := ClashYAML([]*model.Node{
		{Protocol: model.ProtoSSH, Address: "a", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
	})
	if err != nil {
		t.Fatalf("ClashYAML: %v", err)
	}
	if !strings.Contains(out, "- DIRECT") {
		t.Fatalf("empty subscription must fall back to DIRECT:\n%s", out)
	}
	if !strings.Contains(out, "proxies: []") {
		t.Errorf("an empty proxies list must be emitted as a flow sequence:\n%s", out)
	}
}

func TestClashYAMLPropagatesHardErrors(t *testing.T) {
	_, err := ClashYAML([]*model.Node{{Protocol: model.Protocol("carrier-pigeon"), Address: "a", Port: 1}})
	if err == nil {
		t.Fatal("ClashYAML swallowed an unknown-protocol error")
	}
}

func TestClashYAMLIsByteStable(t *testing.T) {
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID, Remark: "A",
			Transport: model.Transport{Network: model.NetWS, Path: "/ws", Host: "a.example.com",
				Headers: map[string]string{"X-1": "1", "X-2": "2", "X-3": "3"}},
			Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com", ALPN: []string{"h2", "http/1.1"}}},
		{Protocol: model.ProtoHysteria2, Address: "1.2.3.5", Port: 443, Password: "pw", Remark: "B"},
	}
	first, err := ClashYAML(nodes)
	if err != nil {
		t.Fatalf("ClashYAML: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := ClashYAML(nodes)
		if err != nil {
			t.Fatalf("ClashYAML: %v", err)
		}
		if again != first {
			t.Fatalf("output is not byte-stable across runs:\n--- run 1 ---\n%s\n--- run %d ---\n%s", first, i+2, again)
		}
	}
	// The pinned key order puts name/type/server/port first in every proxy.
	if !strings.Contains(first, "  - name: A\n    type: vless\n    server: 1.2.3.4\n    port: 443\n") {
		t.Fatalf("proxy mappings should lead with name/type/server/port:\n%s", first)
	}
}

// ---------------------------------------------------------------------------
// the miniature YAML emitter
// ---------------------------------------------------------------------------

func TestYamlScalarTypes(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{true, "true"},
		{false, "false"},
		{42, "42"},
		{int64(-7), "-7"},
		{1.5, "1.5"},
		{"plain", "plain"},
		{"", `""`},
		{"  padded ", `"  padded "`},
		{"true", `"true"`},
		{"No", `"No"`},
		{"~", `"~"`},
		{"123", `"123"`},
		{"1e5", `"1e5"`},
		{"has: colon", `"has: colon"`},
		{"-leading", `"-leading"`},
		{"?leading", `"?leading"`},
		{"tab\there", `"tab\there"`},
		{"quote\"and\\slash", `"quote\"and\\slash"`},
		{"line\nbreak", `"line\nbreak"`},
		{"carriage\rreturn", `"carriage\rreturn"`},
		{"🇮🇷 ok", "🇮🇷 ok"},
		{uint(9), `"9"`}, // an unhandled type falls back to a quoted fmt.Sprint
	}
	for _, c := range cases {
		if got := yamlScalar(c.in); got != c.want {
			t.Errorf("yamlScalar(%#v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestYamlQuoteEscapesControlCharacters(t *testing.T) {
	// Go's \xNN escapes are not valid YAML, so control bytes must come out as
	// \uNNNN. A bare control byte does not by itself trigger quoting, so this is
	// asserted on yamlQuote directly.
	cases := map[string]string{
		"bell\x07":   `"bell\u0007"`,
		"del\x7f":    `"del\u007f"`,
		"tab\there":  `"tab\there"`,
		"nl\nhere":   `"nl\nhere"`,
		"cr\rhere":   `"cr\rhere"`,
		`quote"here`: `"quote\"here"`,
		`back\slash`: `"back\\slash"`,
		"plain":      `"plain"`,
	}
	for in, want := range cases {
		if got := yamlQuote(in); got != want {
			t.Errorf("yamlQuote(%q) = %s, want %s", in, got, want)
		}
	}
	// The escaping is reached through the emitter when the value also contains a
	// character that forces quoting in the first place.
	var b strings.Builder
	yamlMap(&b, map[string]any{"k": "a:b\x07"}, 0, false)
	if got := b.String(); got != "k: \"a:b\\u0007\"\n" {
		t.Errorf("emitter output = %q", got)
	}
}

func TestYamlNeedsQuote(t *testing.T) {
	for _, s := range []string{"", " x", "x ", "true", "FALSE", "yes", "no", "on", "off", "null", "~", "y", "N",
		"0", "3.14", "a:b", "a#b", "a,b", "[x]", "{x}", "a&b", "a*b", "a!b", "a|b", "a>b", "a'b", `a"b`,
		"100%", "a@b", "a`b", "a\\b", "a\nb", "-x", "?x"} {
		if !yamlNeedsQuote(s) {
			t.Errorf("yamlNeedsQuote(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"plain", "with space", "a/b", "a.b", "a_b", "a-b", "vless-1.2.3.4"} {
		if yamlNeedsQuote(s) {
			t.Errorf("yamlNeedsQuote(%q) = true, want false", s)
		}
	}
}

func TestYamlEmitterStructures(t *testing.T) {
	var b strings.Builder
	yamlMap(&b, map[string]any{
		"name":      "top",
		"emptyMap":  map[string]any{},
		"emptySeq":  []any{},
		"strSlice":  []string{"a", "b"},
		"nested":    map[string]any{"k": "v"},
		"seqOfMaps": []any{map[string]any{"x": 1, "y": 2}, "scalar", map[string]any{}},
		"scalarNum": 7,
	}, 0, false)
	got := b.String()
	for _, want := range []string{
		"name: top\n",
		"emptyMap: {}\n",
		"emptySeq: []\n",
		"strSlice:\n  - a\n  - b\n",
		"nested:\n  k: v\n",
		"scalarNum: 7\n",
		// "y" is a YAML boolean word, so even as a key it must be quoted.
		"seqOfMaps:\n  - x: 1\n    \"y\": 2\n  - scalar\n  - {}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("emitter output missing %q:\n%s", want, got)
		}
	}
}

func TestYamlSeqIndentation(t *testing.T) {
	var b strings.Builder
	yamlMap(&b, map[string]any{"proxies": []any{
		map[string]any{"name": "A", "port": 443},
		map[string]any{"name": "B", "port": 8443},
	}}, 0, false)
	want := "proxies:\n  - name: A\n    port: 443\n  - name: B\n    port: 8443\n"
	if got := b.String(); got != want {
		t.Fatalf("emitter output =\n%s\nwant\n%s", got, want)
	}
}
