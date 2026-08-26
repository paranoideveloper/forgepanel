package render

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// ---------------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------------

func sub(t *testing.T, o jobj, key string) jobj {
	t.Helper()
	v, ok := o[key]
	if !ok {
		t.Fatalf("key %q missing from %v", key, o)
	}
	m, ok := v.(jobj)
	if !ok {
		t.Fatalf("key %q = %T, want an object", key, v)
	}
	return m
}

func str(t *testing.T, o jobj, key string) string {
	t.Helper()
	v, ok := o[key]
	if !ok {
		t.Fatalf("key %q missing from %v", key, o)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("key %q = %T(%v), want a string", key, v, v)
	}
	return s
}

func num(t *testing.T, o jobj, key string) int {
	t.Helper()
	v, ok := o[key]
	if !ok {
		t.Fatalf("key %q missing from %v", key, o)
	}
	i, ok := v.(int)
	if !ok {
		t.Fatalf("key %q = %T(%v), want an int", key, v, v)
	}
	return i
}

func firstOf(t *testing.T, o jobj, key string) jobj {
	t.Helper()
	v, ok := o[key]
	if !ok {
		t.Fatalf("key %q missing from %v", key, o)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("key %q = %T(%v), want a non-empty array", key, v, v)
	}
	m, ok := arr[0].(jobj)
	if !ok {
		t.Fatalf("%q[0] = %T, want an object", key, arr[0])
	}
	return m
}

func mustAbsent(t *testing.T, o jobj, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := o[k]; ok {
			t.Errorf("key %q must not be emitted, got %v", k, o[k])
		}
	}
}

// ---------------------------------------------------------------------------
// engine routing + tiny helpers
// ---------------------------------------------------------------------------

func TestEngineFor(t *testing.T) {
	want := map[model.Protocol]string{
		model.ProtoVLESS: "xray", model.ProtoVMess: "xray", model.ProtoTrojan: "xray",
		model.ProtoShadowsocks: "xray", model.ProtoSOCKS: "xray", model.ProtoHTTP: "xray",
		model.ProtoHysteria2: "sing-box", model.ProtoTUIC: "sing-box", model.ProtoAnyTLS: "sing-box",
		model.ProtoShadowTLS: "sing-box", model.ProtoSSH: "sing-box", model.ProtoWireGuard: "sing-box",
		model.ProtoAmneziaWG: "amneziawg", model.ProtoBrook: "brook", model.ProtoForgeDNS: "forgedns",
	}
	for p, engine := range want {
		if got := EngineFor(p); got != engine {
			t.Errorf("EngineFor(%q) = %q, want %q", p, got, engine)
		}
	}
	if got := EngineFor(model.Protocol("carrier-pigeon")); got != "unknown" {
		t.Errorf("EngineFor(unknown) = %q, want %q", got, "unknown")
	}
	// Every protocol in the matrix must route somewhere.
	for _, p := range append(model.AllProtocols(), model.ProtoAmneziaWG) {
		if EngineFor(p) == "unknown" {
			t.Errorf("protocol %q has no engine", p)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := tagOr("", "fallback"); got != "fallback" {
		t.Errorf("tagOr(\"\") = %q", got)
	}
	if got := tagOr("mine", "fallback"); got != "mine" {
		t.Errorf("tagOr(\"mine\") = %q", got)
	}
	if got := firstNonEmpty("", "", "third"); got != "third" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty of all-empty = %q", got)
	}
	if got := splitOr("", "/"); !reflect.DeepEqual(got, []string{"/"}) {
		t.Errorf("splitOr(\"\") = %v", got)
	}
	if got := splitOr("/p", "/"); !reflect.DeepEqual(got, []string{"/p"}) {
		t.Errorf("splitOr(\"/p\") = %v", got)
	}
	if got := defaultStrs(nil, []string{"0.0.0.0/0"}); !reflect.DeepEqual(got, []string{"0.0.0.0/0"}) {
		t.Errorf("defaultStrs(nil) = %v", got)
	}
	if got := defaultStrs([]string{"10.0.0.0/8"}, []string{"0.0.0.0/0"}); !reflect.DeepEqual(got, []string{"10.0.0.0/8"}) {
		t.Errorf("defaultStrs(set) = %v", got)
	}
	if got := firstInt(0, 443); got != 443 {
		t.Errorf("firstInt(0,443) = %d", got)
	}
	if got := firstInt(8443, 443); got != 8443 {
		t.Errorf("firstInt(8443,443) = %d", got)
	}
	if got := sbSeconds(30); got != "30s" {
		t.Errorf("sbSeconds(30) = %q, want a sing-box duration string", got)
	}
}

func TestNetworkName(t *testing.T) {
	cases := map[model.Network]string{
		model.NetTCP: "tcp", model.NetWS: "ws", model.NetGRPC: "grpc",
		model.NetHTTPUpgrade: "httpupgrade", model.NetXHTTP: "xhttp",
		model.NetMKCP: "kcp", model.NetH2: "http", model.NetQUIC: "quic",
	}
	for net, want := range cases {
		if got := networkName(net); got != want {
			t.Errorf("networkName(%q) = %q, want %q", net, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Xray: settings per protocol
// ---------------------------------------------------------------------------

func vlessNode() *model.Node {
	return &model.Node{Tag: "vl", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443,
		UUID: testUUID, Transport: model.Transport{Network: model.NetTCP}}
}

func TestXrayOutboundVLESS(t *testing.T) {
	n := vlessNode()
	n.Flow = "xtls-rprx-vision"
	n.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com",
		Reality: &model.Reality{PublicKey: "PK", PrivateKey: "SK", ShortID: "0123abcd", Dest: "www.apple.com:443", ServerNames: []string{"www.apple.com"}}}
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	if str(t, out, "tag") != "vl" || str(t, out, "protocol") != "vless" {
		t.Fatalf("outbound envelope = %v", out)
	}
	vnext := firstOf(t, sub(t, out, "settings"), "vnext")
	if str(t, vnext, "address") != "1.2.3.4" || num(t, vnext, "port") != 443 {
		t.Fatalf("vnext = %v", vnext)
	}
	user := firstOf(t, vnext, "users")
	if str(t, user, "id") != testUUID || str(t, user, "encryption") != "none" || str(t, user, "flow") != "xtls-rprx-vision" {
		t.Fatalf("user = %v", user)
	}
	rs := sub(t, sub(t, out, "streamSettings"), "realitySettings")
	if str(t, rs, "publicKey") != "PK" {
		t.Errorf("client outbound must carry the REALITY publicKey, got %v", rs)
	}
	// Server-only REALITY fields must never reach a client outbound: Xray 26
	// would otherwise treat the node as a server and demand a privateKey.
	mustAbsent(t, rs, "privateKey", "dest", "target", "serverNames", "shortIds", "xver")
}

func TestXrayOutboundWithoutFlow(t *testing.T) {
	out, err := XrayOutbound(vlessNode())
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	user := firstOf(t, firstOf(t, sub(t, out, "settings"), "vnext"), "users")
	mustAbsent(t, user, "flow")
	// tag falls back to "proxy" when unset.
	n := vlessNode()
	n.Tag = ""
	out2, _ := XrayOutbound(n)
	if str(t, out2, "tag") != "proxy" {
		t.Errorf("default outbound tag = %q, want proxy", str(t, out2, "tag"))
	}
}

func TestXraySettingsPerProtocol(t *testing.T) {
	cases := []struct {
		name     string
		node     *model.Node
		checkIn  func(*testing.T, jobj)
		checkOut func(*testing.T, jobj)
	}{
		{
			name: "vmess",
			node: &model.Node{Protocol: model.ProtoVMess, Address: "1.2.3.4", Port: 443, UUID: testUUID, Encryption: "aes-128-gcm"},
			checkIn: func(t *testing.T, s jobj) {
				c := firstOf(t, s, "clients")
				if str(t, c, "id") != testUUID || num(t, c, "alterId") != 0 {
					t.Errorf("clients = %v", c)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				u := firstOf(t, firstOf(t, s, "vnext"), "users")
				if str(t, u, "security") != "aes-128-gcm" || num(t, u, "alterId") != 0 {
					t.Errorf("users = %v", u)
				}
			},
		},
		{
			name: "trojan",
			node: &model.Node{Protocol: model.ProtoTrojan, Address: "1.2.3.4", Port: 443, Password: "pw"},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, firstOf(t, s, "clients"), "password") != "pw" {
					t.Errorf("clients = %v", s)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				srv := firstOf(t, s, "servers")
				if str(t, srv, "password") != "pw" || str(t, srv, "address") != "1.2.3.4" {
					t.Errorf("servers = %v", srv)
				}
			},
		},
		{
			name: "shadowsocks",
			node: &model.Node{Protocol: model.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388, Method: model.SSAES256GCM, Password: "pw"},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, s, "method") != model.SSAES256GCM || str(t, s, "password") != "pw" || str(t, s, "network") != "tcp,udp" {
					t.Errorf("settings = %v", s)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				srv := firstOf(t, s, "servers")
				if str(t, srv, "method") != model.SSAES256GCM || num(t, srv, "port") != 8388 {
					t.Errorf("servers = %v", srv)
				}
			},
		},
		{
			name: "socks with auth",
			node: &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080, Username: "u", Password: "p"},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, s, "auth") != "password" {
					t.Errorf("auth = %v", s["auth"])
				}
				a := firstOf(t, s, "accounts")
				if str(t, a, "user") != "u" || str(t, a, "pass") != "p" {
					t.Errorf("accounts = %v", a)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				u := firstOf(t, firstOf(t, s, "servers"), "users")
				if str(t, u, "user") != "u" {
					t.Errorf("users = %v", u)
				}
			},
		},
		{
			name: "socks open",
			node: &model.Node{Protocol: model.ProtoSOCKS, Address: "1.2.3.4", Port: 1080},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, s, "auth") != "noauth" {
					t.Errorf("auth = %v, want noauth", s["auth"])
				}
				mustAbsent(t, s, "accounts")
			},
			checkOut: func(t *testing.T, s jobj) {
				mustAbsent(t, firstOf(t, s, "servers"), "users")
			},
		},
		{
			name: "http with auth",
			node: &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8080, Username: "u", Password: "p"},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, firstOf(t, s, "accounts"), "user") != "u" {
					t.Errorf("accounts = %v", s)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				if str(t, firstOf(t, firstOf(t, s, "servers"), "users"), "pass") != "p" {
					t.Errorf("servers = %v", s)
				}
			},
		},
		{
			name: "http open",
			node: &model.Node{Protocol: model.ProtoHTTP, Address: "1.2.3.4", Port: 8080},
			checkIn: func(t *testing.T, s jobj) {
				if len(s) != 0 {
					t.Errorf("settings = %v, want empty for an open http proxy", s)
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				mustAbsent(t, firstOf(t, s, "servers"), "users")
			},
		},
		{
			name: "wireguard",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK", LocalAddress: []string{"10.0.0.2/32"},
					AllowedIPs: []string{"10.0.0.0/24"}, MTU: 1380, Reserved: []int{1, 2, 3}}},
			checkIn: func(t *testing.T, s jobj) {
				if str(t, s, "secretKey") != "SK" {
					t.Errorf("secretKey = %v", s["secretKey"])
				}
				peer := firstOf(t, s, "peers")
				if str(t, peer, "publicKey") != "PK" || str(t, peer, "endpoint") != "1.2.3.4:51820" {
					t.Errorf("peer = %v", peer)
				}
				if !reflect.DeepEqual(peer["allowedIPs"], []string{"10.0.0.0/24"}) {
					t.Errorf("allowedIPs = %v", peer["allowedIPs"])
				}
				if num(t, s, "mtu") != 1380 || !reflect.DeepEqual(s["reserved"], []int{1, 2, 3}) {
					t.Errorf("settings = %v", s)
				}
				if !reflect.DeepEqual(s["address"], []string{"10.0.0.2/32"}) {
					t.Errorf("address = %v", s["address"])
				}
			},
			checkOut: func(t *testing.T, s jobj) {
				if str(t, s, "secretKey") != "SK" {
					t.Errorf("secretKey = %v", s["secretKey"])
				}
			},
		},
		{
			name: "wireguard defaults allowedIPs",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "1.2.3.4", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK"}},
			checkIn: func(t *testing.T, s jobj) {
				peer := firstOf(t, s, "peers")
				if !reflect.DeepEqual(peer["allowedIPs"], []string{"0.0.0.0/0", "::/0"}) {
					t.Errorf("allowedIPs = %v, want the full-tunnel default", peer["allowedIPs"])
				}
				mustAbsent(t, s, "address", "reserved")
			},
			checkOut: func(t *testing.T, s jobj) {},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, err := XrayInbound(c.node)
			if err != nil {
				t.Fatalf("XrayInbound: %v", err)
			}
			c.checkIn(t, sub(t, in, "settings"))
			out, err := XrayOutbound(c.node)
			if err != nil {
				t.Fatalf("XrayOutbound: %v", err)
			}
			c.checkOut(t, sub(t, out, "settings"))
		})
	}
}

func TestXrayRejectsNonXrayProtocols(t *testing.T) {
	nodes := map[string]*model.Node{
		"hysteria2": {Protocol: model.ProtoHysteria2, Address: "a", Port: 443, Password: "pw"},
		"tuic":      {Protocol: model.ProtoTUIC, Address: "a", Port: 443, UUID: testUUID, Password: "pw"},
		"anytls":    {Protocol: model.ProtoAnyTLS, Address: "a", Port: 443, Password: "pw"},
		"shadowtls": {Protocol: model.ProtoShadowTLS, Address: "a", Port: 443, ShadowTLS: &model.ShadowTLSOptions{Password: "hs", Version: 3}},
		"ssh":       {Protocol: model.ProtoSSH, Address: "a", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
		"brook":     {Protocol: model.ProtoBrook, Address: "a", Port: 9999, Password: "pw"},
		"forgedns":  {Protocol: model.ProtoForgeDNS, Address: "a", Port: 53, ForgeDNS: &model.ForgeDNSOptions{Zone: "z", Adapter: "stormdns"}},
	}
	for name, n := range nodes {
		t.Run(name, func(t *testing.T) {
			if _, err := XrayInbound(n); err == nil {
				t.Error("XrayInbound accepted a non-Xray protocol")
			} else if !strings.Contains(err.Error(), "not an Xray protocol") {
				t.Errorf("XrayInbound error = %v, want it to say the protocol is not an Xray one", err)
			}
			if _, err := XrayOutbound(n); err == nil {
				t.Error("XrayOutbound accepted a non-Xray protocol")
			}
		})
	}
}

func TestXrayInboundEnvelopeAndValidation(t *testing.T) {
	n := vlessNode()
	n.Tag = ""
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	if str(t, in, "tag") != "inbound" || str(t, in, "listen") != "1.2.3.4" || num(t, in, "port") != 443 {
		t.Fatalf("inbound envelope = %v", in)
	}
	sniff := sub(t, in, "sniffing")
	if sniff["enabled"] != true || !reflect.DeepEqual(sniff["destOverride"], []string{"http", "tls", "quic"}) {
		t.Fatalf("sniffing = %v", sniff)
	}
	if str(t, sub(t, in, "settings"), "decryption") != "none" {
		t.Error("a VLESS inbound must declare decryption=none")
	}

	// XrayInbound validates; XrayOutbound deliberately does not.
	bad := &model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443} // no uuid
	if _, err := XrayInbound(bad); err == nil {
		t.Fatal("XrayInbound accepted an invalid node")
	}
	if _, err := XrayOutbound(bad); err != nil {
		t.Fatalf("XrayOutbound must not validate, got %v", err)
	}
}

func TestXrayInboundWiresServerCertificate(t *testing.T) {
	n := vlessNode()
	n.Security = model.Security{Type: model.SecTLS, ServerName: "a.example.com",
		CertificateFile: "/etc/ssl/fullchain.pem", KeyFile: "/etc/ssl/key.pem"}
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	tls := sub(t, sub(t, in, "streamSettings"), "tlsSettings")
	cert := firstOf(t, tls, "certificates")
	if str(t, cert, "certificateFile") != "/etc/ssl/fullchain.pem" || str(t, cert, "keyFile") != "/etc/ssl/key.pem" {
		t.Fatalf("certificates = %v", cert)
	}
	// Without a certificate path there is no certificates array to emit.
	n2 := vlessNode()
	n2.Security = model.Security{Type: model.SecTLS, ServerName: "a.example.com"}
	in2, _ := XrayInbound(n2)
	mustAbsent(t, sub(t, sub(t, in2, "streamSettings"), "tlsSettings"), "certificates")
}

// ---------------------------------------------------------------------------
// Xray: streamSettings
// ---------------------------------------------------------------------------

func TestXrayStreamSettingsNilForOwnWireProtocols(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
		WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK"}}
	n.Normalize()
	if ss := xrayStreamSettings(n, false); ss != nil {
		t.Fatalf("streamSettings = %v, want nil for a protocol with its own wire format", ss)
	}
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	mustAbsent(t, out, "streamSettings")
}

func TestXrayStreamSettingsTransports(t *testing.T) {
	cases := []struct {
		name  string
		tr    model.Transport
		check func(*testing.T, jobj)
	}{
		{"tcp plain", model.Transport{Network: model.NetTCP}, func(t *testing.T, ss jobj) {
			if str(t, ss, "network") != "tcp" {
				t.Errorf("network = %v", ss["network"])
			}
			mustAbsent(t, ss, "tcpSettings")
		}},
		{"tcp http obfs", model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}, Host: "fake.example.com", Path: "/camo"},
			func(t *testing.T, ss jobj) {
				h := sub(t, sub(t, ss, "tcpSettings"), "header")
				if str(t, h, "type") != "http" {
					t.Fatalf("header = %v", h)
				}
				req := sub(t, h, "request")
				if !reflect.DeepEqual(req["path"], []string{"/camo"}) {
					t.Errorf("path = %v", req["path"])
				}
				if !reflect.DeepEqual(sub(t, req, "headers")["Host"], []string{"fake.example.com"}) {
					t.Errorf("host header = %v", sub(t, req, "headers")["Host"])
				}
			}},
		{"tcp obfs defaults path", model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}},
			func(t *testing.T, ss jobj) {
				req := sub(t, sub(t, sub(t, ss, "tcpSettings"), "header"), "request")
				if !reflect.DeepEqual(req["path"], []string{"/"}) {
					t.Errorf("default path = %v, want [/]", req["path"])
				}
				// No Host set means no Host header. This used to emit
				// `"Host": [""]`, which is a request no real browser sends —
				// camouflage that is easier to fingerprint than plain TCP.
				if _, ok := req["headers"]; ok {
					t.Errorf("headers = %v, want none when no Host is configured", req["headers"])
				}
			}},
		{"ws", model.Transport{Network: model.NetWS, Path: "/ws", Host: "cdn.example.com", EarlyData: 2048, EDHeader: "Sec-WebSocket-Protocol"},
			func(t *testing.T, ss jobj) {
				ws := sub(t, ss, "wsSettings")
				if str(t, ws, "path") != "/ws" || num(t, ws, "maxEarlyData") != 2048 || str(t, ws, "earlyDataHeaderName") != "Sec-WebSocket-Protocol" {
					t.Fatalf("wsSettings = %v", ws)
				}
				if str(t, sub(t, ws, "headers"), "Host") != "cdn.example.com" {
					t.Errorf("ws headers = %v", ws["headers"])
				}
			}},
		{"ws minimal", model.Transport{Network: model.NetWS}, func(t *testing.T, ss jobj) {
			ws := sub(t, ss, "wsSettings")
			if str(t, ws, "path") != "/" {
				t.Errorf("default path = %q", str(t, ws, "path"))
			}
			mustAbsent(t, ws, "headers", "maxEarlyData", "earlyDataHeaderName")
		}},
		{"httpupgrade", model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "hu.example.com"},
			func(t *testing.T, ss jobj) {
				hu := sub(t, ss, "httpupgradeSettings")
				if str(t, hu, "path") != "/hu" || str(t, hu, "host") != "hu.example.com" {
					t.Fatalf("httpupgradeSettings = %v", hu)
				}
			}},
		{"httpupgrade without host", model.Transport{Network: model.NetHTTPUpgrade},
			func(t *testing.T, ss jobj) {
				hu := sub(t, ss, "httpupgradeSettings")
				if str(t, hu, "path") != "/" {
					t.Errorf("path = %q", str(t, hu, "path"))
				}
				mustAbsent(t, hu, "host")
			}},
		{"grpc", model.Transport{Network: model.NetGRPC, ServiceName: "svc", MultiMode: true, IdleTimeout: 60, InitialWindows: 65536, PermitWithout: true},
			func(t *testing.T, ss jobj) {
				g := sub(t, ss, "grpcSettings")
				if str(t, g, "serviceName") != "svc" || g["multiMode"] != true ||
					num(t, g, "idle_timeout") != 60 || num(t, g, "initial_windows_size") != 65536 || g["permit_without_stream"] != true {
					t.Fatalf("grpcSettings = %v", g)
				}
			}},
		{"grpc minimal", model.Transport{Network: model.NetGRPC, ServiceName: "svc"},
			func(t *testing.T, ss jobj) {
				g := sub(t, ss, "grpcSettings")
				mustAbsent(t, g, "idle_timeout", "initial_windows_size", "permit_without_stream")
				if g["multiMode"] != false {
					t.Errorf("multiMode = %v, want false", g["multiMode"])
				}
			}},
		// maxConcurrency and maxConnections are alternative strategies the core
		// refuses to see together, so the two are exercised separately.
		{"xhttp full", model.Transport{Network: model.NetXHTTP, Path: "/xh", Host: "x.example.com", XHTTPMode: "stream-up", XPaddingB: "100-1000",
			XMux: &model.XMux{MaxConcurrency: "16", CMaxReuseTimes: "64", HMaxRequestTime: "600", HMaxReusableSecs: "1800-3000", HKeepAlivePeriod: 45}},
			func(t *testing.T, ss jobj) {
				xh := sub(t, ss, "xhttpSettings")
				if str(t, xh, "path") != "/xh" || str(t, xh, "mode") != "stream-up" ||
					str(t, xh, "host") != "x.example.com" || str(t, xh, "xPaddingBytes") != "100-1000" {
					t.Fatalf("xhttpSettings = %v", xh)
				}
				xm := sub(t, xh, "xmux")
				for k, want := range map[string]string{"maxConcurrency": "16",
					"cMaxReuseTimes": "64", "hMaxRequestTimes": "600", "hMaxReusableSecs": "1800-3000"} {
					if str(t, xm, k) != want {
						t.Errorf("xmux.%s = %v, want %q", k, xm[k], want)
					}
				}
				if num(t, xm, "hKeepAlivePeriod") != 45 {
					t.Errorf("xmux.hKeepAlivePeriod = %v", xm["hKeepAlivePeriod"])
				}
				// cMaxLifetimeMs is not part of the pinned core's xmux schema.
				mustAbsent(t, xm, "cMaxLifetimeMs", "maxConnections")
			}},
		{"xhttp xmux connection pool", model.Transport{Network: model.NetXHTTP, XMux: &model.XMux{MaxConnections: "8"}},
			func(t *testing.T, ss jobj) {
				xm := sub(t, sub(t, ss, "xhttpSettings"), "xmux")
				if str(t, xm, "maxConnections") != "8" {
					t.Errorf("xmux.maxConnections = %v", xm["maxConnections"])
				}
				mustAbsent(t, xm, "maxConcurrency")
			}},
		{"xhttp empty xmux is omitted", model.Transport{Network: model.NetXHTTP, XMux: &model.XMux{}},
			func(t *testing.T, ss jobj) {
				xh := sub(t, ss, "xhttpSettings")
				if str(t, xh, "mode") != "auto" {
					t.Errorf("mode = %q, want the auto default", str(t, xh, "mode"))
				}
				mustAbsent(t, xh, "xmux", "host", "xPaddingBytes")
			}},
		{"h2", model.Transport{Network: model.NetH2, Path: "/h2", Host: "h.example.com"},
			func(t *testing.T, ss jobj) {
				if str(t, ss, "network") != "http" {
					t.Errorf("network = %v, want Xray's http spelling", ss["network"])
				}
				h2 := sub(t, ss, "httpSettings")
				if str(t, h2, "path") != "/h2" || !reflect.DeepEqual(h2["host"], []string{"h.example.com"}) {
					t.Fatalf("httpSettings = %v", h2)
				}
			}},
		{"h2 without host", model.Transport{Network: model.NetH2},
			func(t *testing.T, ss jobj) { mustAbsent(t, sub(t, ss, "httpSettings"), "host") }},
		{"mkcp with seed and obfs", model.Transport{Network: model.NetMKCP, Seed: "s33d", HeaderObfs: &model.Header{Type: "srtp"}},
			func(t *testing.T, ss jobj) {
				if str(t, ss, "network") != "kcp" {
					t.Errorf("network = %v", ss["network"])
				}
				k := sub(t, ss, "kcpSettings")
				if str(t, k, "seed") != "s33d" || str(t, sub(t, k, "header"), "type") != "srtp" {
					t.Fatalf("kcpSettings = %v", k)
				}
			}},
		{"mkcp bare", model.Transport{Network: model.NetMKCP},
			func(t *testing.T, ss jobj) {
				k := sub(t, ss, "kcpSettings")
				if str(t, sub(t, k, "header"), "type") != "none" {
					t.Errorf("header = %v, want type none", k["header"])
				}
				mustAbsent(t, k, "seed")
			}},
		{"quic", model.Transport{Network: model.NetQUIC, QUICSecurity: "aes-128-gcm", QUICKey: "qk"},
			func(t *testing.T, ss jobj) {
				q := sub(t, ss, "quicSettings")
				if str(t, q, "security") != "aes-128-gcm" || str(t, q, "key") != "qk" {
					t.Fatalf("quicSettings = %v", q)
				}
			}},
		{"quic bare", model.Transport{Network: model.NetQUIC},
			func(t *testing.T, ss jobj) {
				if str(t, sub(t, ss, "quicSettings"), "security") != "none" {
					t.Errorf("security = %v, want none", sub(t, ss, "quicSettings")["security"])
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := vlessNode()
			n.Transport = c.tr
			// XrayOutbound does not validate, so it also reaches the transports
			// Validate rejects for Xray 26 (h2/quic/mKCP).
			out, err := XrayOutbound(n)
			if err != nil {
				t.Fatalf("XrayOutbound: %v", err)
			}
			c.check(t, sub(t, out, "streamSettings"))
		})
	}
}

func TestXrayStreamSettingsTLS(t *testing.T) {
	n := vlessNode()
	n.Security = model.Security{Type: model.SecTLS, ServerName: "a.example.com", ALPN: []string{"h2", "http/1.1"},
		Fingerprint: "chrome", MinVersion: "1.2", MaxVersion: "1.3", CipherSuites: "TLS_AES_128_GCM_SHA256",
		PinSHA256: []string{"PIN1", "PIN2"}}
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	ss := sub(t, out, "streamSettings")
	if str(t, ss, "security") != "tls" {
		t.Fatalf("security = %v", ss["security"])
	}
	tls := sub(t, ss, "tlsSettings")
	if str(t, tls, "serverName") != "a.example.com" || str(t, tls, "fingerprint") != "chrome" ||
		str(t, tls, "minVersion") != "1.2" || str(t, tls, "maxVersion") != "1.3" ||
		str(t, tls, "cipherSuites") != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("tlsSettings = %v", tls)
	}
	if !reflect.DeepEqual(tls["alpn"], []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %v", tls["alpn"])
	}
	// Xray 26 dropped allowInsecure; skip-verify is expressed as a pinned hash.
	if str(t, tls, "pinnedPeerCertSha256") != "PIN1" {
		t.Errorf("pinnedPeerCertSha256 = %v", tls["pinnedPeerCertSha256"])
	}
	mustAbsent(t, tls, "allowInsecure")

	// A minimal TLS layer emits only the server name.
	bare := vlessNode()
	bare.Security = model.Security{Type: model.SecTLS}
	outBare, _ := XrayOutbound(bare)
	tlsBare := sub(t, sub(t, outBare, "streamSettings"), "tlsSettings")
	if str(t, tlsBare, "serverName") != "1.2.3.4" {
		t.Errorf("serverName = %v, want the SNI() fallback to the address", tlsBare["serverName"])
	}
	mustAbsent(t, tlsBare, "alpn", "fingerprint", "minVersion", "maxVersion", "cipherSuites", "pinnedPeerCertSha256")
}

func TestXrayStreamSettingsRealityInbound(t *testing.T) {
	n := vlessNode()
	n.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com",
		Reality: &model.Reality{PrivateKey: "SK", PublicKey: "PK", Dest: "www.apple.com:443",
			ServerNames: []string{"www.apple.com"}, ShortIDs: []string{"0123abcd"}, SpiderX: "/spider", Xver: 1}}
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	ss := sub(t, in, "streamSettings")
	if str(t, ss, "security") != "reality" {
		t.Fatalf("security = %v", ss["security"])
	}
	rs := sub(t, ss, "realitySettings")
	if str(t, rs, "privateKey") != "SK" || str(t, rs, "dest") != "www.apple.com:443" ||
		str(t, rs, "target") != "www.apple.com:443" || str(t, rs, "serverName") != "www.apple.com" ||
		str(t, rs, "shortId") != "0123abcd" || str(t, rs, "spiderX") != "/spider" || num(t, rs, "xver") != 1 {
		t.Fatalf("realitySettings = %v", rs)
	}
	if !reflect.DeepEqual(rs["serverNames"], []string{"www.apple.com"}) {
		t.Errorf("serverNames = %v", rs["serverNames"])
	}
	if !reflect.DeepEqual(rs["shortIds"], []string{"0123abcd"}) {
		t.Errorf("shortIds = %v", rs["shortIds"])
	}
	// A client's publicKey must never appear on a server inbound.
	mustAbsent(t, rs, "publicKey")
	if str(t, rs, "fingerprint") != "chrome" {
		t.Errorf("fingerprint = %v, want the chrome default", rs["fingerprint"])
	}
}

func TestXrayRealityInboundShortIDFallbacks(t *testing.T) {
	// Only a single selected shortId: it must be promoted into the shortIds array
	// Xray's REALITY inbound requires.
	n := vlessNode()
	n.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com",
		Reality: &model.Reality{PrivateKey: "SK", ShortID: "0123abcd"}}
	in, err := XrayInbound(n)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	rs := sub(t, sub(t, in, "streamSettings"), "realitySettings")
	if !reflect.DeepEqual(rs["shortIds"], []string{"0123abcd"}) {
		t.Errorf("shortIds = %v", rs["shortIds"])
	}

	// No shortId at all: a single empty string matches any client shortId.
	n2 := vlessNode()
	n2.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com",
		Reality: &model.Reality{PrivateKey: "SK"}}
	in2, err := XrayInbound(n2)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	rs2 := sub(t, sub(t, in2, "streamSettings"), "realitySettings")
	if !reflect.DeepEqual(rs2["shortIds"], []string{""}) {
		t.Errorf("shortIds = %v, want a single empty match-any entry", rs2["shortIds"])
	}
	mustAbsent(t, rs2, "shortId", "dest", "target", "serverNames", "xver")

	// A REALITY security with no block at all still renders the envelope.
	n3 := vlessNode()
	n3.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com"}
	out3, err := XrayOutbound(n3)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	rs3 := sub(t, sub(t, out3, "streamSettings"), "realitySettings")
	if rs3["show"] != false || str(t, rs3, "fingerprint") != "chrome" {
		t.Fatalf("realitySettings = %v", rs3)
	}
	mustAbsent(t, rs3, "publicKey", "serverName", "shortId")
}

func TestXrayRealityOutboundPicksFirstShortID(t *testing.T) {
	n := vlessNode()
	n.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com", Fingerprint: "firefox",
		Reality: &model.Reality{PublicKey: "PK", ShortIDs: []string{"00ff", "0123abcd"}}}
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	rs := sub(t, sub(t, out, "streamSettings"), "realitySettings")
	if str(t, rs, "shortId") != "00ff" {
		t.Errorf("shortId = %v, want the first (sorted) entry", rs["shortId"])
	}
	if str(t, rs, "fingerprint") != "firefox" {
		t.Errorf("fingerprint = %v, want the explicit one", rs["fingerprint"])
	}
}

func TestRenderXrayJSON(t *testing.T) {
	raw, err := RenderXrayJSON(vlessNode())
	if err != nil {
		t.Fatalf("RenderXrayJSON: %v", err)
	}
	var cfg struct {
		Log       map[string]any   `json:"log"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	if cfg.Log["loglevel"] != "warning" {
		t.Errorf("log = %v", cfg.Log)
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0]["protocol"] != "socks" || cfg.Inbounds[0]["port"] != float64(10808) {
		t.Fatalf("inbounds = %v", cfg.Inbounds)
	}
	if len(cfg.Outbounds) != 1 || cfg.Outbounds[0]["protocol"] != "vless" {
		t.Fatalf("outbounds = %v", cfg.Outbounds)
	}
	if !strings.Contains(string(raw), "\n  ") {
		t.Error("output should be indented")
	}
	if _, err := RenderXrayJSON(&model.Node{Protocol: model.ProtoBrook, Address: "a", Port: 1, Password: "pw"}); err == nil {
		t.Error("RenderXrayJSON must propagate the render error for a non-Xray protocol")
	}
}

// ---------------------------------------------------------------------------
// sing-box: outbounds
// ---------------------------------------------------------------------------

func TestSingboxOutboundVLESS(t *testing.T) {
	n := vlessNode()
	n.Flow = "xtls-rprx-vision"
	n.Security = model.Security{Type: model.SecReality, ServerName: "www.apple.com",
		Reality: &model.Reality{PublicKey: "PK", ShortID: "0123abcd"}}
	n.Multiplex = &model.Multiplex{Enabled: true, Protocol: "h2mux", MaxConns: 4, MinStreams: 2, MaxStreams: 8,
		Padding: true, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}
	out, err := SingboxOutbound(n)
	if err != nil {
		t.Fatalf("SingboxOutbound: %v", err)
	}
	o := jobj(out)
	if str(t, o, "type") != "vless" || str(t, o, "server") != "1.2.3.4" || num(t, o, "server_port") != 443 ||
		str(t, o, "uuid") != testUUID || str(t, o, "flow") != "xtls-rprx-vision" || str(t, o, "tag") != "vl" {
		t.Fatalf("outbound = %v", o)
	}
	if str(t, o, "packet_encoding") != "xudp" {
		t.Errorf("packet_encoding = %v, want an explicit xudp", o["packet_encoding"])
	}
	mux := sub(t, o, "multiplex")
	if mux["enabled"] != true || str(t, mux, "protocol") != "h2mux" || num(t, mux, "max_connections") != 4 ||
		num(t, mux, "min_streams") != 2 || num(t, mux, "max_streams") != 8 || mux["padding"] != true {
		t.Fatalf("multiplex = %v", mux)
	}
	br := sub(t, mux, "brutal")
	if br["enabled"] != true || num(t, br, "up_mbps") != 50 || num(t, br, "down_mbps") != 100 {
		t.Fatalf("brutal = %v", br)
	}
	tls := sub(t, o, "tls")
	if tls["enabled"] != true || str(t, tls, "server_name") != "www.apple.com" {
		t.Fatalf("tls = %v", tls)
	}
	if str(t, sub(t, tls, "reality"), "public_key") != "PK" {
		t.Errorf("reality = %v", tls["reality"])
	}
	if str(t, sub(t, tls, "utls"), "fingerprint") != "chrome" {
		t.Errorf("utls = %v, want the chrome default REALITY needs", tls["utls"])
	}
}

func TestSingboxOutboundPerProtocol(t *testing.T) {
	cases := []struct {
		name  string
		node  *model.Node
		check func(*testing.T, jobj)
	}{
		{
			name: "vmess",
			node: &model.Node{Protocol: model.ProtoVMess, Address: "a", Port: 443, UUID: testUUID, Encryption: "zero"},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "vmess" || str(t, o, "security") != "zero" || num(t, o, "alter_id") != 0 {
					t.Fatalf("vmess outbound = %v", o)
				}
			},
		},
		{
			name: "trojan",
			node: &model.Node{Protocol: model.ProtoTrojan, Address: "a", Port: 443, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "t.example.com"}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "trojan" || str(t, o, "password") != "pw" {
					t.Fatalf("trojan outbound = %v", o)
				}
				if str(t, sub(t, o, "tls"), "server_name") != "t.example.com" {
					t.Errorf("tls = %v", o["tls"])
				}
			},
		},
		{
			name: "shadowsocks with plugin",
			node: &model.Node{Protocol: model.ProtoShadowsocks, Address: "a", Port: 8388, Method: model.SSAES128GCM, Password: "pw",
				SSPlugin: &model.SSPluginOptions{Name: "v2ray-plugin", Opts: "mode=websocket;tls"}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "shadowsocks" || str(t, o, "method") != model.SSAES128GCM {
					t.Fatalf("ss outbound = %v", o)
				}
				if str(t, o, "plugin") != "v2ray-plugin" || str(t, o, "plugin_opts") != "mode=websocket;tls" {
					t.Fatalf("ss plugin = %v / %v", o["plugin"], o["plugin_opts"])
				}
			},
		},
		{
			name: "shadowsocks without plugin opts",
			node: &model.Node{Protocol: model.ProtoShadowsocks, Address: "a", Port: 8388, Method: model.SSAES128GCM, Password: "pw",
				SSPlugin: &model.SSPluginOptions{Name: "obfs-local"}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "plugin") != "obfs-local" {
					t.Errorf("plugin = %v", o["plugin"])
				}
				mustAbsent(t, o, "plugin_opts")
			},
		},
		{
			name: "socks with auth",
			node: &model.Node{Protocol: model.ProtoSOCKS, Address: "a", Port: 1080, Username: "u", Password: "p"},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "socks" || str(t, o, "version") != "5" ||
					str(t, o, "username") != "u" || str(t, o, "password") != "p" {
					t.Fatalf("socks outbound = %v", o)
				}
			},
		},
		{
			name:  "socks open",
			node:  &model.Node{Protocol: model.ProtoSOCKS, Address: "a", Port: 1080},
			check: func(t *testing.T, o jobj) { mustAbsent(t, o, "username", "password") },
		},
		{
			name: "http over tls",
			node: &model.Node{Protocol: model.ProtoHTTP, Address: "a", Port: 8443, Username: "u", Password: "p",
				Security: model.Security{Type: model.SecTLS, ServerName: "p.example.com"}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "http" || str(t, o, "username") != "u" {
					t.Fatalf("http outbound = %v", o)
				}
				if str(t, sub(t, o, "tls"), "server_name") != "p.example.com" {
					t.Errorf("tls = %v", o["tls"])
				}
			},
		},
		{
			name:  "http plain",
			node:  &model.Node{Protocol: model.ProtoHTTP, Address: "a", Port: 8080},
			check: func(t *testing.T, o jobj) { mustAbsent(t, o, "tls", "username", "password") },
		},
		{
			name: "hysteria2",
			node: &model.Node{Protocol: model.ProtoHysteria2, Address: "a", Port: 443, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "hy.example.com"},
				Hysteria2: &model.Hysteria2Options{UpMbps: 100, DownMbps: 200, ObfsType: "salamander", ObfsPassword: "opw",
					PortHopping: "20000-50000", PortHopInterval: 30}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "hysteria2" || num(t, o, "up_mbps") != 100 || num(t, o, "down_mbps") != 200 {
					t.Fatalf("hysteria2 outbound = %v", o)
				}
				obfs := sub(t, o, "obfs")
				if str(t, obfs, "type") != "salamander" || str(t, obfs, "password") != "opw" {
					t.Fatalf("obfs = %v", obfs)
				}
				if !reflect.DeepEqual(o["server_ports"], []string{"20000:50000"}) {
					t.Errorf("server_ports = %v, want sing-box's colon form", o["server_ports"])
				}
				if str(t, o, "hop_interval") != "30s" {
					t.Errorf("hop_interval = %v", o["hop_interval"])
				}
				if !reflect.DeepEqual(sub(t, o, "tls")["alpn"], []string{"h3"}) {
					t.Errorf("alpn = %v", sub(t, o, "tls")["alpn"])
				}
			},
		},
		{
			name: "hysteria2 minimal",
			node: &model.Node{Protocol: model.ProtoHysteria2, Address: "a", Port: 443, Password: "pw"},
			check: func(t *testing.T, o jobj) {
				mustAbsent(t, o, "up_mbps", "down_mbps", "obfs", "server_ports", "hop_interval")
				if sub(t, o, "tls")["enabled"] != true {
					t.Error("hysteria2 is TLS by construction; the tls block is mandatory")
				}
			},
		},
		{
			name: "tuic",
			node: &model.Node{Protocol: model.ProtoTUIC, Address: "a", Port: 443, UUID: testUUID, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "t.example.com"},
				TUIC:     &model.TUICOptions{CongestionControl: "cubic", UDPRelayMode: "quic", ZeroRTTHandshake: true, HeartbeatSeconds: 10, DisableSNI: true}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "tuic" || str(t, o, "uuid") != testUUID ||
					str(t, o, "congestion_control") != "cubic" || str(t, o, "udp_relay_mode") != "quic" ||
					o["zero_rtt_handshake"] != true || str(t, o, "heartbeat") != "10s" {
					t.Fatalf("tuic outbound = %v", o)
				}
				if sub(t, o, "tls")["disable_sni"] != true {
					t.Errorf("disable_sni belongs in the tls block, got %v", o["tls"])
				}
			},
		},
		{
			name: "anytls",
			node: &model.Node{Protocol: model.ProtoAnyTLS, Address: "a", Port: 443, Password: "pw",
				Security: model.Security{Type: model.SecTLS, ServerName: "any.example.com"},
				AnyTLS:   &model.AnyTLSOptions{PaddingScheme: []string{"stop=8"}, IdleSessionCheckInterval: 30, IdleSessionTimeout: 60, MinIdleSessions: 2}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "anytls" || str(t, o, "idle_session_check_interval") != "30s" ||
					str(t, o, "idle_session_timeout") != "60s" || num(t, o, "min_idle_session") != 2 {
					t.Fatalf("anytls outbound = %v", o)
				}
				if !reflect.DeepEqual(o["padding_scheme"], []string{"stop=8"}) {
					t.Errorf("padding_scheme = %v", o["padding_scheme"])
				}
			},
		},
		// ShadowTLS is covered by TestShadowTLSClientRendersAPairThatCarriesTraffic:
		// it is the one protocol whose client side is TWO outbounds, so the single
		// -outbound shape this table asserts cannot express it.
		{
			name: "wireguard",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK", PublicKey: "SRV-PK", PeerPrivateKey: "CLI-SK",
					PreSharedKey: "PSK", LocalAddress: []string{"10.0.0.2/32"}, MTU: 1380, Reserved: []int{1, 2, 3}, Workers: 4,
					AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: 25}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "wireguard" || str(t, o, "private_key") != "CLI-SK" || str(t, o, "peer_public_key") != "SRV-PK" {
					t.Fatalf("wireguard outbound = %v", o)
				}
				if str(t, o, "pre_shared_key") != "PSK" || num(t, o, "mtu") != 1380 || num(t, o, "workers") != 4 {
					t.Fatalf("wireguard outbound = %v", o)
				}
				if !reflect.DeepEqual(o["local_address"], []string{"10.0.0.2/32"}) || !reflect.DeepEqual(o["reserved"], []int{1, 2, 3}) {
					t.Fatalf("wireguard outbound = %v", o)
				}
				// The server's own private key must never be shipped to a client,
				// and the 1.11 outbound has no allowed_ips / keepalive keys.
				if o["private_key"] == "SRV-SK" {
					t.Error("the server private key leaked into a client outbound")
				}
				mustAbsent(t, o, "allowed_ips", "persistent_keepalive_interval")
			},
		},
		{
			name: "wireguard minimal",
			node: &model.Node{Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
				WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK", PublicKey: "SRV-PK"}},
			check: func(t *testing.T, o jobj) {
				mustAbsent(t, o, "pre_shared_key", "local_address", "workers", "reserved")
				// MTU comes from the 1420 Normalize default.
				if num(t, o, "mtu") != 1420 {
					t.Errorf("mtu = %v", o["mtu"])
				}
			},
		},
		{
			name: "ssh full",
			node: &model.Node{Protocol: model.ProtoSSH, Address: "a", Port: 22,
				SSH: &model.SSHOptions{User: "root", Password: "pw", PrivateKey: "KEY", PrivateKeyPassword: "kpw",
					HostKeyAlgorithms: []string{"ssh-ed25519"}, ClientVersion: "SSH-2.0-OpenSSH_9.6"}},
			check: func(t *testing.T, o jobj) {
				if str(t, o, "type") != "ssh" || str(t, o, "user") != "root" || str(t, o, "password") != "pw" ||
					str(t, o, "private_key") != "KEY" || str(t, o, "private_key_passphrase") != "kpw" ||
					str(t, o, "client_version") != "SSH-2.0-OpenSSH_9.6" {
					t.Fatalf("ssh outbound = %v", o)
				}
				if !reflect.DeepEqual(o["host_key_algorithms"], []string{"ssh-ed25519"}) {
					t.Errorf("host_key_algorithms = %v", o["host_key_algorithms"])
				}
			},
		},
		{
			name: "ssh minimal",
			node: &model.Node{Protocol: model.ProtoSSH, Address: "a", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
			check: func(t *testing.T, o jobj) {
				mustAbsent(t, o, "private_key", "private_key_passphrase", "host_key_algorithms", "client_version")
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := SingboxOutbound(c.node)
			if err != nil {
				t.Fatalf("SingboxOutbound: %v", err)
			}
			c.check(t, jobj(out))
			// Only the mux-capable protocols may carry a multiplex block.
			if _, has := out["multiplex"]; has && !sbSupportsMultiplex(c.node.Protocol) {
				t.Errorf("a multiplex block leaked onto %q", c.node.Protocol)
			}
		})
	}
}

func TestSingboxOutboundErrors(t *testing.T) {
	t.Run("validates first", func(t *testing.T) {
		if _, err := SingboxOutbound(&model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443}); err == nil {
			t.Fatal("SingboxOutbound accepted a node without a UUID")
		}
	})
	t.Run("non sing-box protocol", func(t *testing.T) {
		_, err := SingboxOutbound(&model.Node{Protocol: model.ProtoBrook, Address: "a", Port: 9999, Password: "pw"})
		if err == nil {
			t.Fatal("SingboxOutbound accepted brook")
		}
		if !strings.Contains(err.Error(), "brook") {
			t.Errorf("error = %v, want it to name the right engine", err)
		}
	})
	t.Run("forgedns", func(t *testing.T) {
		_, err := SingboxOutbound(&model.Node{Protocol: model.ProtoForgeDNS, Address: "a", Port: 53,
			ForgeDNS: &model.ForgeDNSOptions{Zone: "z", Adapter: "stormdns"}})
		if err == nil {
			t.Fatal("SingboxOutbound accepted forgedns")
		}
	})
	t.Run("shadowsocks over a transport", func(t *testing.T) {
		_, err := SingboxOutbound(&model.Node{Protocol: model.ProtoShadowsocks, Address: "a", Port: 8388,
			Method: model.SSAES128GCM, Password: "pw", Transport: model.Transport{Network: model.NetWS, Path: "/ws"}})
		if err == nil {
			t.Fatal("SingboxOutbound rendered a ws-fronted shadowsocks node; it would connect in the clear")
		}
		if !strings.Contains(err.Error(), "SIP003") {
			t.Errorf("error = %v, want it to point at SIP003 plugins", err)
		}
	})
	t.Run("transport sing-box cannot express", func(t *testing.T) {
		n := vlessNode()
		n.Transport = model.Transport{Network: model.NetXHTTP, Path: "/xh"}
		if _, err := SingboxOutbound(n); err == nil {
			t.Fatal("SingboxOutbound accepted an xhttp transport")
		}
	})
	t.Run("tcp header obfuscation", func(t *testing.T) {
		n := vlessNode()
		n.Transport = model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}}
		if _, err := SingboxOutbound(n); err == nil {
			t.Fatal("SingboxOutbound accepted tcp http obfuscation, which sing-box cannot do")
		}
	})
}

// ---------------------------------------------------------------------------
// sing-box: transport / tls / multiplex helpers
// ---------------------------------------------------------------------------

func TestSBTransport(t *testing.T) {
	t.Run("tcp is expressed by omitting the key", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetTCP})
		if err != nil || tr != nil {
			t.Fatalf("sbTransport(tcp) = (%v,%v), want (nil,nil)", tr, err)
		}
		// "none" is not obfuscation and must not be rejected.
		if _, err := sbTransport(model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "none"}}); err != nil {
			t.Fatalf("headerType=none rejected: %v", err)
		}
		if _, err := sbTransport(model.Transport{Network: model.NetTCP, HeaderObfs: &model.Header{Type: "http"}}); err == nil {
			t.Fatal("tcp http obfuscation must be reported, not silently dropped")
		}
	})
	t.Run("ws", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetWS, Path: "/ws", Host: "cdn.example.com",
			Headers: map[string]string{"User-Agent": "UA"}, EarlyData: 2048})
		if err != nil {
			t.Fatalf("sbTransport: %v", err)
		}
		if str(t, tr, "type") != "ws" || str(t, tr, "path") != "/ws" {
			t.Fatalf("ws transport = %v", tr)
		}
		h := sub(t, tr, "headers")
		if str(t, h, "Host") != "cdn.example.com" || str(t, h, "User-Agent") != "UA" {
			t.Fatalf("headers = %v", h)
		}
		if num(t, tr, "max_early_data") != 2048 || str(t, tr, "early_data_header_name") != "Sec-WebSocket-Protocol" {
			t.Fatalf("early data = %v / %v", tr["max_early_data"], tr["early_data_header_name"])
		}
	})
	t.Run("ws honours an explicit Host header and ED name", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetWS, Host: "cdn.example.com",
			Headers: map[string]string{"Host": "explicit.example.com"}, EarlyData: 1, EDHeader: "X-ED"})
		if str(t, sub(t, tr, "headers"), "Host") != "explicit.example.com" {
			t.Errorf("an explicit Host header must not be overwritten: %v", tr["headers"])
		}
		if str(t, tr, "early_data_header_name") != "X-ED" {
			t.Errorf("early_data_header_name = %v", tr["early_data_header_name"])
		}
		if str(t, tr, "path") != "/" {
			t.Errorf("path = %v, want the / default", tr["path"])
		}
	})
	t.Run("ws without host emits no headers", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetWS, Path: "/ws"})
		mustAbsent(t, tr, "headers", "max_early_data", "early_data_header_name")
	})
	t.Run("httpupgrade keeps host out of the headers map", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "hu.example.com",
			Headers: map[string]string{"X-Tag": "1"}})
		if err != nil {
			t.Fatalf("sbTransport: %v", err)
		}
		if str(t, tr, "type") != "httpupgrade" || str(t, tr, "host") != "hu.example.com" || str(t, tr, "path") != "/hu" {
			t.Fatalf("httpupgrade transport = %v", tr)
		}
		if _, dup := sub(t, tr, "headers")["Host"]; dup {
			t.Error("Host must not be duplicated into the headers map; sing-box would send it twice")
		}
	})
	t.Run("httpupgrade minimal", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetHTTPUpgrade})
		if str(t, tr, "path") != "/" {
			t.Errorf("path = %v", tr["path"])
		}
		mustAbsent(t, tr, "host", "headers")
	})
	t.Run("grpc", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetGRPC, ServiceName: "svc", IdleTimeout: 60, PermitWithout: true, MultiMode: true})
		if err != nil {
			t.Fatalf("sbTransport: %v", err)
		}
		if str(t, tr, "type") != "grpc" || str(t, tr, "service_name") != "svc" ||
			str(t, tr, "idle_timeout") != "60s" || tr["permit_without_stream"] != true {
			t.Fatalf("grpc transport = %v", tr)
		}
		// multiMode is an Xray-only extension; sing-box's gRPC is always "gun".
		mustAbsent(t, tr, "multi_mode", "multiMode")
	})
	t.Run("grpc minimal", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetGRPC, ServiceName: "svc"})
		mustAbsent(t, tr, "idle_timeout", "permit_without_stream")
	})
	t.Run("h2 host list", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetH2, Path: "/h2", H2Hosts: []string{"a.com", "b.com"},
			Headers: map[string]string{"X-Tag": "1"}})
		if err != nil {
			t.Fatalf("sbTransport: %v", err)
		}
		if str(t, tr, "type") != "http" || str(t, tr, "path") != "/h2" {
			t.Fatalf("h2 transport = %v", tr)
		}
		if !reflect.DeepEqual(tr["host"], []string{"a.com", "b.com"}) {
			t.Errorf("host = %v", tr["host"])
		}
		if str(t, sub(t, tr, "headers"), "X-Tag") != "1" {
			t.Errorf("headers = %v", tr["headers"])
		}
	})
	t.Run("h2 falls back to the single Host", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetH2, Host: "only.example.com"})
		if !reflect.DeepEqual(tr["host"], []string{"only.example.com"}) {
			t.Errorf("host = %v", tr["host"])
		}
	})
	t.Run("h2 without any host", func(t *testing.T) {
		tr, _ := sbTransport(model.Transport{Network: model.NetH2})
		mustAbsent(t, tr, "host", "headers")
	})
	t.Run("quic takes no options", func(t *testing.T) {
		tr, err := sbTransport(model.Transport{Network: model.NetQUIC, QUICSecurity: "aes-128-gcm", QUICKey: "qk"})
		if err != nil {
			t.Fatalf("sbTransport: %v", err)
		}
		if !reflect.DeepEqual(tr, jobj{"type": "quic"}) {
			t.Fatalf("quic transport = %v, want just the type", tr)
		}
	})
	t.Run("xhttp is not a sing-box transport", func(t *testing.T) {
		_, err := sbTransport(model.Transport{Network: model.NetXHTTP})
		if err == nil {
			t.Fatal("sbTransport accepted xhttp")
		}
		if !strings.Contains(err.Error(), "use xray") {
			t.Errorf("error = %v, want it to route the caller to xray", err)
		}
	})
	t.Run("mkcp is not a sing-box transport", func(t *testing.T) {
		if _, err := sbTransport(model.Transport{Network: model.NetMKCP}); err == nil {
			t.Fatal("sbTransport accepted mKCP")
		}
	})
}

func TestSBTLS(t *testing.T) {
	t.Run("none without force is nil", func(t *testing.T) {
		n := &model.Node{Address: "1.2.3.4", Security: model.Security{Type: model.SecNone}}
		if got := sbTLS(n, false); got != nil {
			t.Fatalf("sbTLS = %v, want nil", got)
		}
	})
	t.Run("none with force still emits a block", func(t *testing.T) {
		n := &model.Node{Address: "1.2.3.4", Security: model.Security{Type: model.SecNone}}
		got := sbTLS(n, true)
		if got["enabled"] != true || str(t, got, "server_name") != "1.2.3.4" {
			t.Fatalf("sbTLS = %v", got)
		}
	})
	t.Run("tls with every knob", func(t *testing.T) {
		n := &model.Node{Address: "1.2.3.4", Security: model.Security{Type: model.SecTLS, ServerName: "a.example.com",
			ALPN: []string{"h2"}, AllowInsecure: true, MinVersion: "1.2", MaxVersion: "1.3", Fingerprint: "firefox",
			ECH: &model.ECH{Enabled: true, ConfigList: "ECHCFG"}}}
		got := sbTLS(n, false)
		if str(t, got, "server_name") != "a.example.com" || got["insecure"] != true ||
			str(t, got, "min_version") != "1.2" || str(t, got, "max_version") != "1.3" {
			t.Fatalf("sbTLS = %v", got)
		}
		if !reflect.DeepEqual(got["alpn"], []string{"h2"}) {
			t.Errorf("alpn = %v", got["alpn"])
		}
		if str(t, sub(t, got, "utls"), "fingerprint") != "firefox" {
			t.Errorf("utls = %v", got["utls"])
		}
		if !reflect.DeepEqual(sub(t, got, "ech")["config"], []string{"ECHCFG"}) {
			t.Errorf("ech = %v", got["ech"])
		}
	})
	t.Run("ech auto-fetch omits the config list", func(t *testing.T) {
		n := &model.Node{Address: "a", Security: model.Security{Type: model.SecTLS, ECH: &model.ECH{AutoFetch: true}}}
		ech := sub(t, sbTLS(n, false), "ech")
		if ech["enabled"] != true {
			t.Fatalf("ech = %v", ech)
		}
		mustAbsent(t, ech, "config")
	})
	t.Run("tls without a fingerprint emits no utls", func(t *testing.T) {
		n := &model.Node{Address: "a", Security: model.Security{Type: model.SecTLS}}
		mustAbsent(t, sbTLS(n, false), "utls", "alpn", "insecure", "min_version", "max_version", "ech", "reality")
	})
	t.Run("reality picks the first shortId and forces a fingerprint", func(t *testing.T) {
		n := &model.Node{Address: "a", Security: model.Security{Type: model.SecReality,
			Reality: &model.Reality{PublicKey: "PK", ShortIDs: []string{"00ff", "0123abcd"}}}}
		got := sbTLS(n, false)
		r := sub(t, got, "reality")
		if r["enabled"] != true || str(t, r, "public_key") != "PK" || str(t, r, "short_id") != "00ff" {
			t.Fatalf("reality = %v", r)
		}
		if str(t, sub(t, got, "utls"), "fingerprint") != "chrome" {
			t.Errorf("utls = %v; REALITY is a uTLS-only handshake in sing-box", got["utls"])
		}
	})
	t.Run("reality without a block", func(t *testing.T) {
		n := &model.Node{Address: "a", Security: model.Security{Type: model.SecReality}}
		r := sub(t, sbTLS(n, false), "reality")
		if r["enabled"] != true {
			t.Fatalf("reality = %v", r)
		}
		mustAbsent(t, r, "public_key", "short_id")
	})
	t.Run("reality with an empty public key", func(t *testing.T) {
		n := &model.Node{Address: "a", Security: model.Security{Type: model.SecReality, Reality: &model.Reality{ShortID: "00"}}}
		r := sub(t, sbTLS(n, false), "reality")
		mustAbsent(t, r, "public_key")
		if str(t, r, "short_id") != "00" {
			t.Errorf("short_id = %v", r["short_id"])
		}
	})
}

func TestSBMultiplex(t *testing.T) {
	if got := sbMultiplex(nil); got != nil {
		t.Errorf("sbMultiplex(nil) = %v, want nil", got)
	}
	if got := sbMultiplex(&model.Multiplex{Enabled: false, MaxStreams: 4}); got != nil {
		t.Errorf("sbMultiplex(disabled) = %v, want nil", got)
	}
	bare := sbMultiplex(&model.Multiplex{Enabled: true})
	if bare["enabled"] != true {
		t.Fatalf("sbMultiplex = %v", bare)
	}
	mustAbsent(t, bare, "protocol", "max_connections", "min_streams", "max_streams", "padding", "brutal")
	// A brutal block that is present but disabled is not emitted.
	off := sbMultiplex(&model.Multiplex{Enabled: true, Brutal: &model.Brutal{Enabled: false, UpMbps: 50}})
	mustAbsent(t, off, "brutal")
}

func TestSBSupportsMultiplex(t *testing.T) {
	yes := map[model.Protocol]bool{model.ProtoVLESS: true, model.ProtoVMess: true, model.ProtoTrojan: true, model.ProtoShadowsocks: true}
	for _, p := range append(model.AllProtocols(), model.ProtoAmneziaWG) {
		if got := sbSupportsMultiplex(p); got != yes[p] {
			t.Errorf("sbSupportsMultiplex(%q) = %v, want %v", p, got, yes[p])
		}
	}
}

func TestSBPortRanges(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"20000-50000", []string{"20000:50000"}},
		{"20000:50000", []string{"20000:50000"}},
		{"443", []string{"443:443"}},
		{"443,20000-30000", []string{"443:443", "20000:30000"}},
		{"443, , 8443", []string{"443:443", "8443:8443"}},
		{"abc", nil},                     // a bare non-numeric port is skipped
		{"lo-50000", nil},                // a non-numeric low bound is skipped
		{"20000-hi", nil},                // a non-numeric high bound is skipped
		{"abc,443", []string{"443:443"}}, // one bad entry must not kill the rest
	}
	for _, c := range cases {
		if got := sbPortRanges(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("sbPortRanges(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// sing-box: inbounds and endpoints
// ---------------------------------------------------------------------------

func TestSingboxInboundPerProtocol(t *testing.T) {
	cases := []struct {
		name  string
		node  *model.Node
		check func(*testing.T, jobj)
	}{
		{
			name: "vless with flow and ws",
			node: &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443, UUID: testUUID, Remark: "alice",
				Transport: model.Transport{Network: model.NetWS, Path: "/ws"},
				Security:  model.Security{Type: model.SecTLS, ServerName: "a.example.com", CertificateFile: "/c.pem", KeyFile: "/k.pem", AllowInsecure: true, Fingerprint: "chrome"}},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "type") != "vless" || str(t, in, "tag") != "in-vless" ||
					str(t, in, "listen") != "::" || num(t, in, "listen_port") != 443 {
					t.Fatalf("inbound envelope = %v", in)
				}
				u := firstOf(t, in, "users")
				if str(t, u, "uuid") != testUUID || str(t, u, "name") != "alice" {
					t.Fatalf("users = %v", u)
				}
				tls := sub(t, in, "tls")
				if str(t, tls, "certificate_path") != "/c.pem" || str(t, tls, "key_path") != "/k.pem" ||
					str(t, tls, "server_name") != "a.example.com" {
					t.Fatalf("tls = %v", tls)
				}
				// Client-only knobs must not appear on a server inbound.
				mustAbsent(t, tls, "insecure", "utls")
				if str(t, sub(t, in, "transport"), "type") != "ws" {
					t.Errorf("transport = %v", in["transport"])
				}
			},
		},
		{
			name: "vless with vision and no remark",
			node: &model.Node{Tag: "custom", Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443, UUID: testUUID,
				Flow: "xtls-rprx-vision", Transport: model.Transport{Network: model.NetTCP}},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "tag") != "custom" {
					t.Errorf("tag = %v", in["tag"])
				}
				u := firstOf(t, in, "users")
				if str(t, u, "flow") != "xtls-rprx-vision" || str(t, u, "name") != "user" {
					t.Fatalf("users = %v", u)
				}
				mustAbsent(t, in, "tls", "transport")
			},
		},
		{
			name: "vmess",
			node: &model.Node{Protocol: model.ProtoVMess, Address: "0.0.0.0", Port: 443, UUID: testUUID},
			check: func(t *testing.T, in jobj) {
				u := firstOf(t, in, "users")
				if str(t, in, "type") != "vmess" || str(t, u, "uuid") != testUUID || num(t, u, "alterId") != 0 {
					t.Fatalf("vmess inbound = %v", in)
				}
			},
		},
		{
			name: "trojan",
			node: &model.Node{Protocol: model.ProtoTrojan, Address: "0.0.0.0", Port: 443, Password: "pw", Remark: "bob"},
			check: func(t *testing.T, in jobj) {
				u := firstOf(t, in, "users")
				if str(t, in, "type") != "trojan" || str(t, u, "password") != "pw" || str(t, u, "name") != "bob" {
					t.Fatalf("trojan inbound = %v", in)
				}
			},
		},
		{
			name: "shadowsocks",
			node: &model.Node{Protocol: model.ProtoShadowsocks, Address: "0.0.0.0", Port: 8388, Method: model.SSAES128GCM, Password: "pw"},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "type") != "shadowsocks" || str(t, in, "method") != model.SSAES128GCM || str(t, in, "password") != "pw" {
					t.Fatalf("ss inbound = %v", in)
				}
			},
		},
		{
			name: "hysteria2 with masquerade",
			node: &model.Node{Protocol: model.ProtoHysteria2, Address: "0.0.0.0", Port: 443, Password: "pw",
				Hysteria2: &model.Hysteria2Options{UpMbps: 100, DownMbps: 200, ObfsType: "salamander", ObfsPassword: "opw",
					IgnoreClientBandwidth: true,
					Masquerade: &model.Hy2Masquerade{Type: "proxy", URL: "https://example.com", RewriteHost: true}}},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "type") != "hysteria2" || num(t, in, "up_mbps") != 100 || in["ignore_client_bandwidth"] != true {
					t.Fatalf("hysteria2 inbound = %v", in)
				}
				if str(t, firstOf(t, in, "users"), "password") != "pw" {
					t.Errorf("users = %v", in["users"])
				}
				m := sub(t, in, "masquerade")
				if str(t, m, "type") != "proxy" || str(t, m, "url") != "https://example.com" || m["rewrite_host"] != true {
					t.Fatalf("masquerade = %v", m)
				}
				// There is no brutal_cc key. The model carried one, documented as a
				// panel preset that "applyCreateDefaults selects a bandwidth profile
				// for" — a behaviour that existed in the comment and nowhere else.
				mustAbsent(t, in, "brutal_cc")
				if sub(t, in, "tls")["enabled"] != true {
					t.Error("hysteria2 inbound needs a tls block")
				}
			},
		},
		{
			name: "tuic",
			node: &model.Node{Protocol: model.ProtoTUIC, Address: "0.0.0.0", Port: 443, UUID: testUUID, Password: "pw",
				TUIC: &model.TUICOptions{CongestionControl: "bbr"}},
			check: func(t *testing.T, in jobj) {
				u := firstOf(t, in, "users")
				if str(t, in, "type") != "tuic" || str(t, u, "uuid") != testUUID || str(t, u, "password") != "pw" ||
					str(t, in, "congestion_control") != "bbr" {
					t.Fatalf("tuic inbound = %v", in)
				}
			},
		},
		{
			name: "anytls",
			node: &model.Node{Protocol: model.ProtoAnyTLS, Address: "0.0.0.0", Port: 443, Password: "pw",
				AnyTLS: &model.AnyTLSOptions{PaddingScheme: []string{"stop=8"}}},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "type") != "anytls" || str(t, firstOf(t, in, "users"), "password") != "pw" {
					t.Fatalf("anytls inbound = %v", in)
				}
				if !reflect.DeepEqual(in["padding_scheme"], []string{"stop=8"}) {
					t.Errorf("padding_scheme = %v", in["padding_scheme"])
				}
			},
		},
		{
			name: "shadowtls",
			node: &model.Node{Protocol: model.ProtoShadowTLS, Address: "0.0.0.0", Port: 8443,
				ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs", HandshakeHost: "www.apple.com"}},
			check: func(t *testing.T, in jobj) {
				if str(t, in, "type") != "shadowtls" || num(t, in, "version") != 3 {
					t.Fatalf("shadowtls inbound = %v", in)
				}
				u := firstOf(t, in, "users")
				if str(t, u, "password") != "hs" || str(t, u, "name") != "user" {
					t.Fatalf("users = %v", u)
				}
				hs := sub(t, in, "handshake")
				if str(t, hs, "server") != "www.apple.com" || num(t, hs, "server_port") != 443 {
					t.Fatalf("handshake = %v", hs)
				}
				if str(t, in, "detour") != "stls-inner-8443" {
					t.Errorf("detour = %v", in["detour"])
				}
				// A top-level tls block makes sing-box reject a shadowtls inbound.
				mustAbsent(t, in, "tls")
			},
		},
		{
			name: "shadowtls without a handshake host",
			node: &model.Node{Protocol: model.ProtoShadowTLS, Address: "0.0.0.0", Port: 8443,
				ShadowTLS: &model.ShadowTLSOptions{Version: 2, Password: "hs", HandshakePort: 8443}},
			check: func(t *testing.T, in jobj) {
				if num(t, in, "version") != 2 {
					t.Errorf("version = %v", in["version"])
				}
				mustAbsent(t, in, "handshake")
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, err := SingboxInbound(c.node)
			if err != nil {
				t.Fatalf("SingboxInbound: %v", err)
			}
			c.check(t, in)
		})
	}
}

func TestSingboxInboundErrors(t *testing.T) {
	for name, n := range map[string]*model.Node{
		"socks":     {Protocol: model.ProtoSOCKS, Address: "0.0.0.0", Port: 1080},
		"http":      {Protocol: model.ProtoHTTP, Address: "0.0.0.0", Port: 8080},
		"ssh":       {Protocol: model.ProtoSSH, Address: "0.0.0.0", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "pw"}},
		"wireguard": {Protocol: model.ProtoWireGuard, Address: "0.0.0.0", Port: 51820, WireGuard: &model.WireGuardOptions{PrivateKey: "SK", PublicKey: "PK"}},
		"brook":     {Protocol: model.ProtoBrook, Address: "0.0.0.0", Port: 9999, Password: "pw"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SingboxInbound(n); err == nil {
				t.Fatalf("SingboxInbound accepted %s", name)
			}
		})
	}
	// Invalid nodes are rejected before any rendering happens.
	if _, err := SingboxInbound(&model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443}); err == nil {
		t.Fatal("SingboxInbound accepted a node without a UUID")
	}
	if _, err := SingboxInbounds(&model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443}); err == nil {
		t.Fatal("SingboxInbounds must propagate the validation error")
	}
}

func TestSingboxInboundTLSWithoutServerName(t *testing.T) {
	// AnyTLS is TLS by construction: the block must exist even with no SNI and
	// no certificate configured.
	n := &model.Node{Protocol: model.ProtoAnyTLS, Address: "0.0.0.0", Port: 443, Password: "pw"}
	in, err := SingboxInbound(n)
	if err != nil {
		t.Fatalf("SingboxInbound: %v", err)
	}
	tls := sub(t, in, "tls")
	if tls["enabled"] != true {
		t.Fatalf("tls = %v", tls)
	}
	mustAbsent(t, tls, "certificate_path", "key_path")
}

func TestSingboxInboundsMaterializesShadowTLSInnerShadowsocks(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowTLS, Address: "0.0.0.0", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs"}}
	n.Normalize() // backfills the inner method/PSK
	ins, err := SingboxInbounds(n)
	if err != nil {
		t.Fatalf("SingboxInbounds: %v", err)
	}
	if len(ins) != 2 {
		t.Fatalf("got %d inbounds, want the camouflage inbound plus its inner shadowsocks", len(ins))
	}
	inner := ins[1]
	if str(t, inner, "type") != "shadowsocks" || str(t, inner, "listen") != "127.0.0.1" {
		t.Fatalf("inner inbound = %v", inner)
	}
	if str(t, inner, "tag") != str(t, ins[0], "detour") {
		t.Fatalf("the outer inbound detours to %q but the inner one is tagged %q", ins[0]["detour"], inner["tag"])
	}
	if num(t, inner, "listen_port") != 28443 {
		t.Errorf("inner listen_port = %v, want the outer port plus the fixed offset", inner["listen_port"])
	}
	if str(t, inner, "method") != model.SS2022AES128 || str(t, inner, "password") != n.ShadowTLS.InnerPassword {
		t.Fatalf("inner credentials = %v / %v", inner["method"], inner["password"])
	}

	// An un-normalized ShadowTLS node without an inner method still gets one.
	raw := &model.Node{Protocol: model.ProtoShadowTLS, Address: "0.0.0.0", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs"}}
	rawIns, err := SingboxInbounds(raw)
	if err != nil {
		t.Fatalf("SingboxInbounds: %v", err)
	}
	if str(t, rawIns[1], "method") != model.SS2022AES128 {
		t.Errorf("inner method = %v, want the SS2022 default", rawIns[1]["method"])
	}

	// Every other protocol yields exactly one inbound.
	one, err := SingboxInbounds(&model.Node{Protocol: model.ProtoTrojan, Address: "0.0.0.0", Port: 443, Password: "pw"})
	if err != nil {
		t.Fatalf("SingboxInbounds: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("got %d inbounds for trojan, want 1", len(one))
	}
}

func TestStlsInnerPortWrapsBelowTheCeiling(t *testing.T) {
	if got := stlsInnerPort(&model.Node{Port: 8443}); got != 28443 {
		t.Errorf("stlsInnerPort(8443) = %d, want 28443", got)
	}
	if got := stlsInnerPort(&model.Node{Port: 50000}); got != 30000 {
		t.Errorf("stlsInnerPort(50000) = %d, want it to wrap downwards", got)
	}
	if got := stlsInnerTag(&model.Node{Port: 8443}); got != "stls-inner-8443" {
		t.Errorf("stlsInnerTag = %q", got)
	}
}

func TestHy2Masquerade(t *testing.T) {
	if got := hy2Masquerade(&model.Hysteria2Options{}); got != nil {
		t.Errorf("hy2Masquerade(no masquerade) = %v, want nil", got)
	}
	if got := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{}}); got != nil {
		t.Errorf("hy2Masquerade(empty type) = %v, want nil", got)
	}
	t.Run("proxy", func(t *testing.T) {
		m := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{Type: "proxy", URL: "https://e.com"}})
		if str(t, m, "type") != "proxy" || str(t, m, "url") != "https://e.com" {
			t.Fatalf("masquerade = %v", m)
		}
		mustAbsent(t, m, "rewrite_host")
	})
	t.Run("file", func(t *testing.T) {
		m := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{Type: "file", Directory: "/srv/www"}})
		if str(t, m, "directory") != "/srv/www" {
			t.Fatalf("masquerade = %v", m)
		}
	})
	t.Run("string", func(t *testing.T) {
		m := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{Type: "string",
			StatusCode: 404, Headers: map[string]string{"Server": "nginx"}, Content: "not found"}})
		if num(t, m, "status_code") != 404 || str(t, m, "content") != "not found" {
			t.Fatalf("masquerade = %v", m)
		}
		if !reflect.DeepEqual(m["headers"], map[string]string{"Server": "nginx"}) {
			t.Errorf("headers = %v", m["headers"])
		}
	})
	t.Run("string minimal", func(t *testing.T) {
		m := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{Type: "string"}})
		mustAbsent(t, m, "status_code", "headers")
		if str(t, m, "content") != "" {
			t.Errorf("content = %v", m["content"])
		}
	})
	t.Run("unknown type carries only the type", func(t *testing.T) {
		m := hy2Masquerade(&model.Hysteria2Options{Masquerade: &model.Hy2Masquerade{Type: "banana", URL: "x"}})
		if !reflect.DeepEqual(m, jobj{"type": "banana"}) {
			t.Fatalf("masquerade = %v", m)
		}
	})
}

func TestSingboxEndpoint(t *testing.T) {
	t.Run("only wireguard is an endpoint", func(t *testing.T) {
		for _, p := range append(model.AllProtocols(), model.ProtoAmneziaWG) {
			want := p == model.ProtoWireGuard
			if got := IsSingboxEndpoint(&model.Node{Protocol: p}); got != want {
				t.Errorf("IsSingboxEndpoint(%q) = %v, want %v", p, got, want)
			}
		}
		if _, err := SingboxEndpoint(&model.Node{Protocol: model.ProtoVLESS}); err == nil {
			t.Fatal("SingboxEndpoint accepted a non-wireguard node")
		}
	})
	t.Run("needs a server private key", func(t *testing.T) {
		if _, err := SingboxEndpoint(&model.Node{Protocol: model.ProtoWireGuard}); err == nil {
			t.Fatal("SingboxEndpoint accepted a node with no wireguard block")
		}
		if _, err := SingboxEndpoint(&model.Node{Protocol: model.ProtoWireGuard, WireGuard: &model.WireGuardOptions{}}); err == nil {
			t.Fatal("SingboxEndpoint accepted a node with no private key")
		}
	})
	t.Run("full", func(t *testing.T) {
		n := &model.Node{Tag: "wg0", Protocol: model.ProtoWireGuard, Address: "0.0.0.0", Port: 51820,
			WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK", PeerPublicKey: "CLI-PK", PreSharedKey: "PSK",
				ServerAddress: []string{"10.66.66.1/24"}, PeerAddress: []string{"10.66.66.2/32"}, MTU: 1420, Keepalive: 25}}
		ep, err := SingboxEndpoint(n)
		if err != nil {
			t.Fatalf("SingboxEndpoint: %v", err)
		}
		if str(t, ep, "type") != "wireguard" || str(t, ep, "tag") != "wg0" ||
			str(t, ep, "private_key") != "SRV-SK" || num(t, ep, "listen_port") != 51820 || num(t, ep, "mtu") != 1420 {
			t.Fatalf("endpoint = %v", ep)
		}
		if !reflect.DeepEqual(ep["address"], []string{"10.66.66.1/24"}) {
			t.Errorf("address = %v", ep["address"])
		}
		peer := firstOf(t, ep, "peers")
		if str(t, peer, "public_key") != "CLI-PK" || str(t, peer, "pre_shared_key") != "PSK" ||
			num(t, peer, "persistent_keepalive_interval") != 25 {
			t.Fatalf("peer = %v", peer)
		}
		if !reflect.DeepEqual(peer["allowed_ips"], []string{"10.66.66.2/32"}) {
			t.Errorf("allowed_ips = %v", peer["allowed_ips"])
		}
	})
	t.Run("legacy LocalAddress is used as the server address", func(t *testing.T) {
		ep, err := SingboxEndpoint(&model.Node{Protocol: model.ProtoWireGuard, Port: 51820,
			WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK", LocalAddress: []string{"10.1.0.1/24"}}})
		if err != nil {
			t.Fatalf("SingboxEndpoint: %v", err)
		}
		if !reflect.DeepEqual(ep["address"], []string{"10.1.0.1/24"}) {
			t.Errorf("address = %v", ep["address"])
		}
	})
	t.Run("defaults", func(t *testing.T) {
		ep, err := SingboxEndpoint(&model.Node{Protocol: model.ProtoWireGuard, Port: 51820,
			WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK"}})
		if err != nil {
			t.Fatalf("SingboxEndpoint: %v", err)
		}
		if !reflect.DeepEqual(ep["address"], []string{"10.66.66.1/24"}) {
			t.Errorf("default address = %v", ep["address"])
		}
		if !reflect.DeepEqual(firstOf(t, ep, "peers")["allowed_ips"], []string{"10.66.66.2/32"}) {
			t.Errorf("default peer ips = %v", firstOf(t, ep, "peers")["allowed_ips"])
		}
		if str(t, ep, "tag") != "wg-51820" {
			t.Errorf("default tag = %v", ep["tag"])
		}
		mustAbsent(t, ep, "mtu")
		mustAbsent(t, firstOf(t, ep, "peers"), "pre_shared_key", "persistent_keepalive_interval")
	})
}

func TestRenderSingboxJSON(t *testing.T) {
	raw, err := RenderSingboxJSON(vlessNode())
	if err != nil {
		t.Fatalf("RenderSingboxJSON: %v", err)
	}
	var cfg struct {
		Log       map[string]any   `json:"log"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	if cfg.Log["level"] != "warn" || cfg.Log["timestamp"] != true {
		t.Errorf("log = %v", cfg.Log)
	}
	if len(cfg.Outbounds) != 2 {
		t.Fatalf("outbounds = %v, want the proxy plus a direct outbound", cfg.Outbounds)
	}
	if cfg.Outbounds[0]["type"] != "vless" || cfg.Outbounds[0]["tag"] != "vl" {
		t.Errorf("proxy outbound = %v", cfg.Outbounds[0])
	}
	if cfg.Outbounds[1]["type"] != "direct" || cfg.Outbounds[1]["tag"] != "direct" {
		t.Errorf("direct outbound = %v", cfg.Outbounds[1])
	}
	if _, err := RenderSingboxJSON(&model.Node{Protocol: model.ProtoBrook, Address: "a", Port: 1, Password: "pw"}); err == nil {
		t.Error("RenderSingboxJSON must propagate the render error")
	}
}

// TestRenderersDoNotMutateTheirInput guards the purity invariant every renderer
// documents: the caller's node is cloned before normalization.
func TestRenderersDoNotMutateTheirInput(t *testing.T) {
	orig := &model.Node{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: testUUID,
		Transport: model.Transport{Network: ""}, Security: model.Security{Type: ""}}
	before := orig.Clone()
	if _, err := XrayInbound(orig); err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	if _, err := XrayOutbound(orig); err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	if _, err := SingboxOutbound(orig); err != nil {
		t.Fatalf("SingboxOutbound: %v", err)
	}
	if _, err := SingboxInbound(orig); err != nil {
		t.Fatalf("SingboxInbound: %v", err)
	}
	if !reflect.DeepEqual(before, orig) {
		t.Fatalf("a renderer mutated its input\nbefore: %+v\nafter:  %+v", before, orig)
	}
}

// ShadowTLS is camouflage, not a proxy.
//
// sing-box models the client side as a real proxy outbound that DETOURS through
// a shadowtls outbound. The renderer emitted the shadowtls object alone: valid
// JSON, sing-box starts, the TLS handshake to the decoy host succeeds, and then
// there is no proxy protocol to speak — so every ShadowTLS client config this
// panel produced connected and carried nothing.
//
// The server side always got this right (SingboxInbound sets detour to an inner
// Shadowsocks inbound), which is what makes the client half worth a test of its
// own: the two sides disagreed and only one of them was checked.
func TestShadowTLSClientRendersAPairThatCarriesTraffic(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{
			Version: 3, Password: "hs", HandshakeHost: "www.apple.com", StrictMode: true,
			InnerMethod: model.SS2022AES128, InnerPassword: "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
	}
	outs, err := SingboxOutbounds(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 2 {
		t.Fatalf("got %d outbound(s), want the shadowsocks + shadowtls pair: %v", len(outs), outs)
	}

	// The PRIMARY is the proxy, because that is the tag a route rule, a selector
	// or a chain points at. If the camouflage were primary, everything that
	// referenced this node would reference the half that carries nothing.
	inner, support := jobj(outs[0]), jobj(outs[1])
	if str(t, inner, "type") != "shadowsocks" {
		t.Fatalf("primary outbound is %q, want the shadowsocks that carries traffic", inner["type"])
	}
	if str(t, support, "type") != "shadowtls" {
		t.Fatalf("support outbound is %q, want shadowtls", support["type"])
	}
	if str(t, inner, "tag") != "proxy" {
		t.Errorf("primary tag = %q, want the node's own tag", inner["tag"])
	}
	if str(t, inner, "detour") != str(t, support, "tag") {
		t.Fatalf("the proxy detours to %q but the camouflage is tagged %q — sing-box refuses an unknown detour",
			inner["detour"], support["tag"])
	}
	// The inner credentials, not the handshake password. The shadowtls password
	// authenticates the mimicry layer; using it as the Shadowsocks key produces
	// a config that connects and then fails to authenticate.
	if str(t, inner, "method") != model.SS2022AES128 || str(t, inner, "password") != "MDEyMzQ1Njc4OWFiY2RlZg==" {
		t.Errorf("inner credentials = %v/%v, want the inner Shadowsocks pair", inner["method"], inner["password"])
	}
	// And the primary must NOT dial the server itself: the detour supplies the
	// connection, and a server address here bypasses the camouflage entirely.
	mustAbsent(t, inner, "server", "server_port")

	// The camouflage keeps everything that describes the mimicry.
	if num(t, support, "version") != 3 || str(t, support, "password") != "hs" || support["strict_mode"] != true {
		t.Errorf("camouflage outbound = %v", support)
	}
	if str(t, sub(t, support, "tls"), "server_name") != "www.apple.com" {
		t.Errorf("the handshake host must win over the node SNI, got %v", support["tls"])
	}
}

func TestShadowTLSV2HasNoStrictMode(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{Version: 2, Password: "hs", StrictMode: true}}
	outs, err := SingboxOutbounds(n)
	if err != nil {
		t.Fatal(err)
	}
	support := jobj(outs[len(outs)-1])
	mustAbsent(t, support, "strict_mode")
	if str(t, sub(t, support, "tls"), "server_name") != "a" {
		t.Errorf("server_name = %v, want the SNI() fallback", sub(t, support, "tls")["server_name"])
	}
}

// Renaming the primary must carry the detour with it. A subscription
// deduplicates tags across many nodes, and a rename that left the detour behind
// would point at an outbound that no longer exists — which sing-box refuses, at
// the operator's client, after the subscription was handed out.
func TestRetaggingAPairKeepsTheDetourIntact(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs",
			InnerMethod: model.SS2022AES128, InnerPassword: "MDEyMzQ1Njc4OWFiY2RlZg=="}}
	outs, err := SingboxOutbounds(n)
	if err != nil {
		t.Fatal(err)
	}
	RetagOutbounds(outs, "node-7")
	if got := outs[0]["tag"]; got != "node-7" {
		t.Fatalf("primary tag = %v", got)
	}
	if outs[0]["detour"] != outs[1]["tag"] {
		t.Fatalf("after renaming, the detour %v does not match the camouflage tag %v",
			outs[0]["detour"], outs[1]["tag"])
	}
	if outs[1]["tag"] == "proxy-stls" {
		t.Error("the camouflage kept the old tag prefix")
	}
}

// A chain's detour belongs on the OUTERMOST outbound. A pair's primary already
// detours through its own camouflage, and a second detour there would replace
// the first — sending traffic out without the camouflage, or without the chain.
func TestAChainDetourGoesOnTheOutermostOutbound(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowTLS, Address: "a", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs",
			InnerMethod: model.SS2022AES128, InnerPassword: "MDEyMzQ1Njc4OWFiY2RlZg=="}}
	outs, _ := SingboxOutbounds(n)
	SetChainDetour(outs, "previous-hop")

	if outs[len(outs)-1]["detour"] != "previous-hop" {
		t.Errorf("the chain detour landed on %v, not the outbound that opens the connection", outs)
	}
	if outs[0]["detour"] == "previous-hop" {
		t.Error("the chain detour replaced the camouflage detour on the primary")
	}
	if outs[0]["detour"] != outs[1]["tag"] {
		t.Error("the primary no longer detours through its camouflage")
	}

	// And a single-outbound node still detours from itself.
	plain := &model.Node{Protocol: model.ProtoTrojan, Address: "a", Port: 443, Password: "p",
		Security: model.Security{Type: model.SecTLS}}
	one, _ := SingboxOutbounds(plain)
	SetChainDetour(one, "previous-hop")
	if one[0]["detour"] != "previous-hop" {
		t.Errorf("a one-outbound node did not take the chain detour: %v", one[0])
	}
}

// And the real core has to accept the pair.
//
// A two-outbound shape is exactly the kind of thing that reads correctly and is
// refused: sing-box validates detour targets and has opinions about where the
// tls block may sit. Only sing-box says. (Writing this test, the core rejected
// the fixture — "bad key length, required 16, got 15" — because the inner PSK in
// it was 15 bytes. That is the sort of thing no amount of reading finds.)
//
// Note what this test can NOT prove. Checked against sing-box 1.13: the OLD bare
// {"type":"shadowtls"} outbound VALIDATES AND STARTS. It completes the handshake
// to the decoy host and then carries nothing, because there is no proxy protocol
// inside it. So "the core accepts it" was never evidence of anything here, which
// is why the assertions above are about the SHAPE of the pair and this one only
// guards against the pair being malformed.
func TestShadowTLSPairIsAcceptedByTheRealCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/bin/sing-box"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no sing-box binary")
	}
	n := &model.Node{
		Protocol: model.ProtoShadowTLS, Address: "example.com", Port: 8443,
		ShadowTLS: &model.ShadowTLSOptions{
			Version: 3, Password: "handshake-pw", HandshakeHost: "www.apple.com",
			InnerMethod: model.SS2022AES128, InnerPassword: "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
	}
	raw, err := RenderSingboxJSON(n)
	if err != nil {
		t.Fatal(err)
	}
	// Not vacuous: a config with no shadowtls outbound would also validate.
	if !strings.Contains(string(raw), `"shadowtls"`) || !strings.Contains(string(raw), `"detour"`) {
		t.Fatalf("nothing to validate — the config has no detoured pair:\n%s", raw)
	}
	path := filepath.Join(t.TempDir(), "stls.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box refuses the ShadowTLS client config:\n%s\n%s", out, raw)
	}
}
