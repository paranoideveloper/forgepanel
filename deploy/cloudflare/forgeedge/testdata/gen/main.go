// Golden-file generator for the ForgeEdge TypeScript mirrors.
//
// It builds a representative node for every protocol/transport/security
// combination the edge can be asked to render, runs the REAL Go exporters over
// them, and writes the results to ../golden.json. The TypeScript test suite then
// asserts byte equality against that file, which is what proves the mirror in
// deploy/cloudflare/forgeedge/src/{model,export} has not drifted from
// internal/protocol/{model,export,render}.
//
// It lives under testdata/, which the go tool excludes from `./...` package
// matching, so `go build ./...` and `go vet ./...` never see it. Run it with an
// explicit file path:
//
//	go run deploy/cloudflare/forgeedge/testdata/gen/main.go
//
// Nothing outside deploy/cloudflare/forgeedge/ is read or written.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

type Case struct {
	Name       string          `json:"name"`
	Input      *model.Node     `json:"input"`
	Normalized *model.Node     `json:"normalized"`
	URI        string          `json:"uri,omitempty"`
	URIError   string          `json:"uri_error,omitempty"`
	Clash      json.RawMessage `json:"clash,omitempty"`
	ClashError string          `json:"clash_error,omitempty"`
	Singbox    json.RawMessage `json:"singbox,omitempty"`
	SbError    string          `json:"singbox_error,omitempty"`
	Xray       json.RawMessage `json:"xray,omitempty"`
	XrayError  string          `json:"xray_error,omitempty"`
}

type Golden struct {
	Cases     []Case `json:"cases"`
	ClashYAML string `json:"clash_yaml"`
	Links     string `json:"links"`
}

func node(protocol model.Protocol, mutate func(n *model.Node)) *model.Node {
	n := &model.Node{
		Protocol:  protocol,
		Address:   "edge.example.com",
		Port:      443,
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecNone},
	}
	mutate(n)
	return n
}

func main() {
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

	cases := []struct {
		name string
		n    *model.Node
	}{
		{"vless-ws-tls", node(model.ProtoVLESS, func(n *model.Node) {
			n.Remark = "Edge 1. VLESS - Domain : 443"
			n.Tag = "Edge 1. VLESS - Domain : 443"
			n.UUID = uuid
			n.Encryption = "none"
			n.Transport = model.Transport{
				Network: model.NetWS, Path: "/vl/9f2c1a", Host: "edge.example.com",
				EarlyData: 2560, EDHeader: "Sec-WebSocket-Protocol",
			}
			n.Security = model.Security{
				Type: model.SecTLS, ServerName: "eDgE.exAmple.com",
				ALPN: []string{"http/1.1"}, Fingerprint: "chrome",
			}
		})},
		{"vless-ws-plain", node(model.ProtoVLESS, func(n *model.Node) {
			n.Remark = "Edge 2. VLESS - IPv4 : 8080"
			n.UUID = uuid
			n.Port = 8080
			n.Address = "104.16.0.1"
			n.Transport = model.Transport{Network: model.NetWS, Path: "/vl/9f2c1a", Host: "edge.example.com", EarlyData: 2560, EDHeader: "Sec-WebSocket-Protocol"}
		})},
		{"vless-tcp-reality-vision", node(model.ProtoVLESS, func(n *model.Node) {
			n.Remark = "VPS REALITY"
			n.UUID = uuid
			n.Flow = "xtls-rprx-vision"
			n.Address = "203.0.113.10"
			n.Security = model.Security{
				Type: model.SecReality, Fingerprint: "chrome",
				Reality: &model.Reality{
					PublicKey:   "xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU",
					ShortID:     "0123abcd",
					ServerNames: []string{"www.datadoghq.com"},
					SpiderX:     "/",
					Dest:        "www.datadoghq.com:443",
				},
			}
		})},
		{"vless-grpc-tls", node(model.ProtoVLESS, func(n *model.Node) {
			n.Remark = "gRPC node"
			n.UUID = uuid
			n.Transport = model.Transport{Network: model.NetGRPC, ServiceName: "forge/grpc", MultiMode: true}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "grpc.example.com", Fingerprint: "firefox"}
		})},
		{"vless-xhttp-reality", node(model.ProtoVLESS, func(n *model.Node) {
			n.Remark = "XHTTP + REALITY"
			n.UUID = uuid
			n.Transport = model.Transport{
				Network: model.NetXHTTP, Path: "/xh", Host: "cdn.example.com", XHTTPMode: "packet-up",
				XPaddingB: "100-1000",
				XMux:      &model.XMux{MaxConcurrency: "16-32", HMaxRequestTime: "600-900"},
			}
			n.Security = model.Security{
				Type: model.SecReality, Fingerprint: "chrome",
				Reality: &model.Reality{PublicKey: "pubkeyhere", ShortIDs: []string{"aabb", "ccdd"}, ServerNames: []string{"www.speedtest.net"}},
			}
		})},
		{"trojan-ws-tls", node(model.ProtoTrojan, func(n *model.Node) {
			n.Remark = "Edge 1. Trojan - Domain : 443"
			n.Tag = "Edge 1. Trojan - Domain : 443"
			n.Password = "p@ss w/ord+special&chars"
			n.Transport = model.Transport{Network: model.NetWS, Path: "/tr/aa11", Host: "edge.example.com", EarlyData: 2560, EDHeader: "Sec-WebSocket-Protocol"}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "edge.example.com", ALPN: []string{"http/1.1"}, Fingerprint: "chrome"}
		})},
		{"vmess-ws-tls", node(model.ProtoVMess, func(n *model.Node) {
			n.Remark = "VMess <ws> & tls"
			n.UUID = uuid
			n.Transport = model.Transport{Network: model.NetWS, Path: "/vm", Host: "vm.example.com"}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "vm.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}}
		})},
		{"vmess-tcp-http-obfs", node(model.ProtoVMess, func(n *model.Node) {
			n.Remark = "VMess tcp http"
			n.UUID = uuid
			n.Transport = model.Transport{Network: model.NetTCP, Host: "obfs.example.com", Path: "/index", HeaderObfs: &model.Header{Type: "http"}}
		})},
		{"shadowsocks-2022", node(model.ProtoShadowsocks, func(n *model.Node) {
			n.Remark = "SS 2022"
			n.Method = model.SS2022AES128
			n.Password = "SGVsbG8gV29ybGQhIQ==" // 16 bytes decoded
		})},
		{"shadowsocks-classic-plugin", node(model.ProtoShadowsocks, func(n *model.Node) {
			n.Remark = "SS + v2ray-plugin"
			n.Method = model.SSChaCha20Poly
			n.Password = "hunter2"
			n.SSPlugin = &model.SSPluginOptions{Name: "v2ray-plugin", Opts: "tls;host=ss.example.com"}
		})},
		{"socks-auth", node(model.ProtoSOCKS, func(n *model.Node) {
			n.Remark = "SOCKS chain"
			n.Username = "user"
			n.Password = "pass"
			n.Port = 1080
		})},
		{"http-tls", node(model.ProtoHTTP, func(n *model.Node) {
			n.Remark = "HTTPS proxy"
			n.Username = "user"
			n.Password = "p@ss"
			n.Port = 8443
			n.Security = model.Security{Type: model.SecTLS, ServerName: "proxy.example.com"}
		})},
		{"hysteria2", node(model.ProtoHysteria2, func(n *model.Node) {
			n.Remark = "Hy2"
			n.Password = "hy2pass"
			n.Port = 8443
			n.Hysteria2 = &model.Hysteria2Options{
				UpMbps: 50, DownMbps: 200, ObfsType: "salamander", ObfsPassword: "obfspw",
				PortHopping: "20000-50000", PortHopInterval: 30,
			}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "hy2.example.com"}
		})},
		{"tuic", node(model.ProtoTUIC, func(n *model.Node) {
			n.Remark = "TUIC v5"
			n.UUID = uuid
			n.Password = "tuicpass"
			n.Port = 8444
			n.TUIC = &model.TUICOptions{CongestionControl: "bbr", UDPRelayMode: "native", ZeroRTTHandshake: true, HeartbeatSeconds: 10}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "tuic.example.com"}
		})},
		{"anytls", node(model.ProtoAnyTLS, func(n *model.Node) {
			n.Remark = "AnyTLS"
			n.Password = "anytlspass"
			n.Port = 8445
			n.AnyTLS = &model.AnyTLSOptions{IdleSessionCheckInterval: 30, IdleSessionTimeout: 30, MinIdleSessions: 2}
			n.Security = model.Security{Type: model.SecTLS, ServerName: "anytls.example.com"}
		})},
		{"wireguard-warp", node(model.ProtoWireGuard, func(n *model.Node) {
			n.Remark = "WARP 1"
			n.Address = "162.159.192.1"
			n.Port = 2408
			n.WireGuard = &model.WireGuardOptions{
				PrivateKey:     "4NyxMUme2zGv5r3QWI0hJBlNglm1J/thoCE55PK29G8=",
				PeerPrivateKey: "4NyxMUme2zGv5r3QWI0hJBlNglm1J/thoCE55PK29G8=",
				PublicKey:      "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				LocalAddress:   []string{"172.16.0.2/32", "2606:4700:110:8fd2::1/128"},
				AllowedIPs:     []string{"0.0.0.0/0", "::/0"},
				MTU:            1280, Keepalive: 25, Reserved: []int{55, 218, 131},
			}
		})},
		{"shadowtls", node(model.ProtoShadowTLS, func(n *model.Node) {
			n.Remark = "ShadowTLS v3"
			n.Port = 8446
			n.ShadowTLS = &model.ShadowTLSOptions{Version: 3, Password: "stlspass", HandshakeHost: "www.apple.com", HandshakePort: 443, StrictMode: true}
		})},
		{"ssh", node(model.ProtoSSH, func(n *model.Node) {
			n.Remark = "SSH tunnel"
			n.Port = 22
			n.SSH = &model.SSHOptions{User: "forge", Password: "sshpass"}
		})},
		{"brook", node(model.ProtoBrook, func(n *model.Node) {
			n.Remark = "Brook wsserver"
			n.Port = 9700
			n.Password = "brookpw"
			n.Brook = &model.BrookOptions{Mode: "wsserver", Path: "/ws"}
		})},
		{"forgedns", node(model.ProtoForgeDNS, func(n *model.Node) {
			n.Remark = "ForgeDNS tunnel"
			n.Address = "ns1.tunnel.example.com"
			n.Port = 53
			n.ForgeDNS = &model.ForgeDNSOptions{Adapter: "stormdns", Zone: "t.example.com.", NSHost: "ns1.example.com", Key: "dnskey", RRType: "txt"}
		})},
	}

	g := Golden{}
	var all []*model.Node

	for _, c := range cases {
		out := Case{Name: c.name, Input: c.n}

		normalized := c.n.Clone()
		normalized.Normalize()
		out.Normalized = normalized

		if uri, err := export.URI(c.n); err != nil {
			out.URIError = err.Error()
		} else {
			out.URI = uri
		}

		if p, err := export.ClashProxy(c.n); err != nil {
			out.ClashError = err.Error()
		} else {
			b, _ := json.Marshal(p)
			out.Clash = b
		}

		if o, err := render.SingboxOutbound(c.n); err != nil {
			out.SbError = err.Error()
		} else {
			b, _ := json.Marshal(o)
			out.Singbox = b
		}

		if o, err := render.XrayOutbound(c.n); err != nil {
			out.XrayError = err.Error()
		} else {
			b, _ := json.Marshal(o)
			out.Xray = b
		}

		g.Cases = append(g.Cases, out)
		all = append(all, c.n)
	}

	yaml, err := export.ClashYAML(all)
	if err != nil {
		panic(err)
	}
	g.ClashYAML = yaml

	for _, n := range all {
		if uri, err := export.URI(n); err == nil {
			g.Links += uri + "\n"
		}
	}

	_, self, _, _ := runtime.Caller(0)
	dest := filepath.Join(filepath.Dir(self), "..", "golden.json")
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(dest, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s (%d cases, %d bytes)\n", dest, len(g.Cases), len(b))
}
