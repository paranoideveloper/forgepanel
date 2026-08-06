package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func TestURIExportAllProtocols(t *testing.T) {
	tests := []struct {
		name     string
		node     *model.Node
		wantPref string
	}{
		{
			name: "VLESS REALITY",
			node: &model.Node{
				Protocol: model.ProtoVLESS,
				Address:  "1.2.3.4",
				Port:     443,
				UUID:     "11111111-2222-3333-4444-555555555555",
				Flow:     "xtls-rprx-vision",
				Remark:   "VLESS Test",
				Transport: model.Transport{
					Network: model.NetTCP,
				},
				Security: model.Security{
					Type:        model.SecReality,
					ServerName:  "example.com",
					Fingerprint: "chrome",
					Reality: &model.Reality{
						PublicKey: "pbkey123",
						ShortID:   "sid1",
						SpiderX:   "/spider",
					},
				},
				Multiplex: &model.Multiplex{Enabled: true, Concurrency: 8},
			},
			wantPref: "vless://",
		},
		{
			name: "VMess WS TLS",
			node: &model.Node{
				Protocol: model.ProtoVMess,
				Address:  "1.2.3.4",
				Port:     443,
				UUID:     "11111111-2222-3333-4444-555555555555",
				Remark:   "VMess Test",
				Transport: model.Transport{
					Network: model.NetWS,
					Path:    "/ws",
					Host:    "vmess.example.com",
				},
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "vmess.example.com",
				},
			},
			wantPref: "vmess://",
		},
		{
			name: "Trojan gRPC TLS",
			node: &model.Node{
				Protocol: model.ProtoTrojan,
				Address:  "1.2.3.4",
				Port:     443,
				Password: "pass123",
				Remark:   "Trojan Test",
				Transport: model.Transport{
					Network:     model.NetGRPC,
					ServiceName: "grpc-svc",
				},
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "trojan.example.com",
				},
			},
			wantPref: "trojan://",
		},
		{
			name: "Shadowsocks 2022",
			node: &model.Node{
				Protocol: model.ProtoShadowsocks,
				Address:  "1.2.3.4",
				Port:     8388,
				Password: "2022-blake3-aes-128-gcm:secretkey",
				Method:   "2022-blake3-aes-128-gcm",
				Remark:   "SS Test",
			},
			wantPref: "ss://",
		},
		{
			name: "SOCKS",
			node: &model.Node{
				Protocol: model.ProtoSOCKS,
				Address:  "1.2.3.4",
				Port:     1080,
				Username: "user",
				Password: "pass",
				Remark:   "SOCKS Test",
			},
			wantPref: "socks://",
		},
		{
			name: "HTTP",
			node: &model.Node{
				Protocol: model.ProtoHTTP,
				Address:  "1.2.3.4",
				Port:     8080,
				Username: "user",
				Password: "pass",
				Remark:   "HTTP Test",
			},
			wantPref: "http://",
		},
		{
			name: "Hysteria2",
			node: &model.Node{
				Protocol: model.ProtoHysteria2,
				Address:  "1.2.3.4",
				Port:     8443,
				Password: "hysteria-secret",
				Remark:   "Hysteria2 Test",
				Security: model.Security{
					Type:          model.SecTLS,
					ServerName:    "hy2.example.com",
					AllowInsecure: true,
					ALPN:          []string{"h3"},
				},
				Hysteria2: &model.Hysteria2Options{
					ObfsType:     "salamander",
					ObfsPassword: "obfspass",
					UpMbps:       100,
					DownMbps:     500,
					PortHopping:  "443,8000-8005",
				},
			},
			wantPref: "hysteria2://",
		},
		{
			name: "TUIC",
			node: &model.Node{
				Protocol: model.ProtoTUIC,
				Address:  "1.2.3.4",
				Port:     8443,
				UUID:     "11111111-2222-3333-4444-555555555555",
				Password: "tuicpass",
				Remark:   "TUIC Test",
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "tuic.example.com",
				},
				TUIC: &model.TUICOptions{
					CongestionControl: "bbr",
					UDPRelayMode:      "native",
					ZeroRTTHandshake:  true,
					HeartbeatSeconds:  10,
					DisableSNI:        true,
				},
			},
			wantPref: "tuic://",
		},
		{
			name: "WireGuard",
			node: &model.Node{
				Protocol: model.ProtoWireGuard,
				Address:  "1.2.3.4",
				Port:     51820,
				Remark:   "WG Test",
				WireGuard: &model.WireGuardOptions{
					PublicKey:      "pubkey123=",
					PrivateKey:     "privkey123=",
					PeerPrivateKey: "peerprivkey=",
					PeerAddress:    []string{"10.0.0.2/32"},
					MTU:            1420,
					Reserved:       []int{1, 2, 3},
				},
			},
			wantPref: "wireguard://",
		},
		{
			name: "Brook",
			node: &model.Node{
				Protocol: model.ProtoBrook,
				Address:  "1.2.3.4",
				Port:     9999,
				Password: "brookpass",
				Remark:   "Brook Test",
			},
			wantPref: "brook://",
		},
		{
			name: "SSH",
			node: &model.Node{
				Protocol: model.ProtoSSH,
				Address:  "1.2.3.4",
				Port:     22,
				Username: "root",
				Password: "sshpassword",
				Remark:   "SSH Test",
			},
			wantPref: "ssh://",
		},
		{
			name: "ForgeDNS",
			node: &model.Node{
				Protocol: model.ProtoForgeDNS,
				Address:  "1.2.3.4",
				Port:     53,
				Remark:   "ForgeDNS Test",
				ForgeDNS: &model.ForgeDNSOptions{
					Zone:    "tunnel.example.com",
					Adapter: "cottendns",
					Key:     "psk123",
				},
			},
			wantPref: "forgedns://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := URI(tt.node)
			if err != nil {
				t.Fatalf("URI() failed: %v", err)
			}
			if !strings.HasPrefix(uri, tt.wantPref) {
				t.Fatalf("URI %q does not start with %q", uri, tt.wantPref)
			}
		})
	}
}

func TestClashProxyAndYAML(t *testing.T) {
	nodes := []*model.Node{
		{
			Protocol: model.ProtoVLESS,
			Address:  "1.2.3.4",
			Port:     443,
			UUID:     "11111111-2222-3333-4444-555555555555",
			Remark:   "VLESS Node",
			Transport: model.Transport{
				Network: model.NetTCP,
			},
			Security: model.Security{
				Type:       model.SecReality,
				ServerName: "example.com",
				Reality: &model.Reality{
					PublicKey: "pbkey123",
					ShortID:   "sid1",
				},
			},
		},
		{
			Protocol: model.ProtoHysteria2,
			Address:  "1.2.3.4",
			Port:     8443,
			Password: "hysteria-secret",
			Remark:   "Hy2 Node",
			Security: model.Security{
				Type:       model.SecTLS,
				ServerName: "hy2.example.com",
			},
			Hysteria2: &model.Hysteria2Options{
				ObfsType:     "salamander",
				ObfsPassword: "obfspass",
			},
		},
		{
			Protocol: model.ProtoShadowsocks,
			Address:  "1.2.3.4",
			Port:     8388,
			Password: "pass",
			Method:   "aes-128-gcm",
			Remark:   "SS Node",
		},
	}

	for _, n := range nodes {
		pMap, err := ClashProxy(n)
		if err != nil {
			t.Fatalf("ClashProxy failed for %s: %v", n.Protocol, err)
		}
		if pMap["name"] == "" || pMap["type"] == "" {
			t.Fatalf("ClashProxy returned invalid proxy map: %+v", pMap)
		}
	}

	yamlStr, err := ClashYAML(nodes)
	if err != nil {
		t.Fatalf("ClashYAML failed: %v", err)
	}
	if !strings.Contains(yamlStr, "proxies:") || !strings.Contains(yamlStr, "proxy-groups:") {
		t.Fatalf("ClashYAML output invalid: %s", yamlStr)
	}
}

func TestWireGuardConfExport(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoWireGuard,
		Address:  "1.2.3.4",
		Port:     51820,
		WireGuard: &model.WireGuardOptions{
			PublicKey:      "serverpubkey=",
			PrivateKey:     "clientprivkey=",
			PeerPrivateKey: "peerprivkey=",
			PeerAddress:    []string{"10.0.0.2/32"},
			MTU:            1420,
			Reserved:       []int{1, 2, 3},
		},
	}

	conf, err := WireGuardConf(n, "203.0.113.5")
	if err != nil {
		t.Fatalf("WireGuardConf failed: %v", err)
	}

	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Fatalf("WireGuardConf output missing headers: %s", conf)
	}
	if !strings.Contains(conf, "Endpoint = 203.0.113.5:51820") {
		t.Fatalf("WireGuardConf endpoint wrong: %s", conf)
	}
}

func TestClashProxyTransportsAndPlugins(t *testing.T) {
	transports := []struct {
		name string
		node *model.Node
	}{
		{
			name: "WS Transport",
			node: &model.Node{
				Protocol: model.ProtoVLESS,
				Address:  "1.1.1.1",
				Port:     443,
				UUID:     "11111111-2222-3333-4444-555555555555",
				Transport: model.Transport{
					Network: model.NetWS,
					Path:    "/wspath",
					Host:    "ws.example.com",
					Headers: map[string]string{"User-Agent": "CustomUA"},
				},
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "ws.example.com",
				},
			},
		},
		{
			name: "HTTPUpgrade Transport",
			node: &model.Node{
				Protocol: model.ProtoVLESS,
				Address:  "1.1.1.1",
				Port:     443,
				UUID:     "11111111-2222-3333-4444-555555555555",
				Transport: model.Transport{
					Network: model.NetHTTPUpgrade,
					Path:    "/httppath",
					Host:    "http.example.com",
				},
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "http.example.com",
				},
			},
		},
		{
			name: "gRPC Transport",
			node: &model.Node{
				Protocol: model.ProtoTrojan,
				Address:  "1.1.1.1",
				Port:     443,
				Password: "pass",
				Transport: model.Transport{
					Network:     model.NetGRPC,
					ServiceName: "grpc-svc",
				},
				Security: model.Security{
					Type:       model.SecTLS,
					ServerName: "grpc.example.com",
				},
			},
		},
		{
			name: "SS Plugin v2ray-plugin",
			node: &model.Node{
				Protocol: model.ProtoShadowsocks,
				Address:  "1.1.1.1",
				Port:     8388,
				Password: "pass",
				Method:   "aes-128-gcm",
				SSPlugin: &model.SSPluginOptions{
					Name: "v2ray-plugin",
					Opts: "mode=websocket;tls;host=plugin.com",
				},
			},
		},
	}

	for _, tt := range transports {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ClashProxy(tt.node)
			if err != nil {
				t.Fatalf("ClashProxy failed: %v", err)
			}
			if p == nil || p["type"] == "" {
				t.Fatalf("ClashProxy returned empty map")
			}
		})
	}
}
