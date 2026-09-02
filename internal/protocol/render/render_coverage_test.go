package render

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// coverageNodes returns a valid, normalized node per protocol×transport×security
// worth rendering, so the render functions are exercised across their branches.
func coverageNodes(t *testing.T) []*model.Node {
	t.Helper()
	uuid := keygen.UUID()
	rk, err := keygen.RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	ss2022, _ := keygen.SS2022PSK("2022-blake3-aes-128-gcm")
	tcp := model.Transport{Network: model.NetTCP}
	ws := model.Transport{Network: model.NetWS, Path: "/ws", Host: "h.example.com"}
	grpc := model.Transport{Network: model.NetGRPC, ServiceName: "svc"}
	tls := model.Security{Type: model.SecTLS, ServerName: "h.example.com"}
	reality := model.Security{Type: model.SecReality, Reality: &model.Reality{
		Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
		PrivateKey: rk.PrivateKey, PublicKey: rk.PublicKey, ShortIDs: []string{"01ab"}}}

	mk := func(n *model.Node) *model.Node { n.Address = "203.0.113.9"; n.Port = 443; n.Normalize(); return n }
	return []*model.Node{
		mk(&model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: tcp, Security: reality, Flow: "xtls-rprx-vision"}),
		mk(&model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: ws, Security: tls}),
		mk(&model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: grpc, Security: tls}),
		mk(&model.Node{Protocol: model.ProtoVMess, UUID: uuid, Transport: ws, Security: tls}),
		mk(&model.Node{Protocol: model.ProtoVMess, UUID: uuid, Transport: tcp}),
		mk(&model.Node{Protocol: model.ProtoTrojan, Password: "pw", Transport: ws, Security: tls}),
		mk(&model.Node{Protocol: model.ProtoTrojan, Password: "pw", Transport: grpc, Security: tls}),
		mk(&model.Node{Protocol: model.ProtoShadowsocks, Method: "2022-blake3-aes-128-gcm", Password: ss2022, Transport: tcp}),
		mk(&model.Node{Protocol: model.ProtoShadowsocks, Method: "aes-256-gcm", Password: "pw", Transport: tcp}),
		mk(&model.Node{Protocol: model.ProtoSOCKS, Username: "u", Password: "p", Transport: tcp}),
		mk(&model.Node{Protocol: model.ProtoHTTP, Username: "u", Password: "p", Transport: tcp}),
		mk(&model.Node{Protocol: model.ProtoHysteria2, Password: "pw", Security: tls}),
		mk(&model.Node{Protocol: model.ProtoTUIC, UUID: uuid, Password: "pw", Security: tls}),
		mk(&model.Node{Protocol: model.ProtoAnyTLS, Password: "pw", Security: tls}),
		mk(&model.Node{Protocol: model.ProtoShadowTLS, Security: tls, ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "stpw", HandshakeHost: "www.apple.com", HandshakePort: 443, InnerMethod: "2022-blake3-aes-128-gcm", InnerPassword: "MTIzNDU2Nzg5MDEyMzQ1Ng=="}}),
		mk(&model.Node{Protocol: model.ProtoWireGuard, WireGuard: &model.WireGuardOptions{PrivateKey: "cGVlcnByaXZhdGVrZXlwZWVycHJpdmF0ZWtleTA=", PeerPublicKey: "cGVlcnB1YmxpY2tleXBlZXJwdWJsaWNrZXkwMDA="}}),
		mk(&model.Node{Protocol: model.ProtoBrook, Password: "pw"}),
	}
}

func TestRenderAllProtocols(t *testing.T) {
	for _, n := range coverageNodes(t) {
		name := string(n.Protocol) + "-" + string(n.Transport.Network) + "-" + string(n.Security.Type)
		t.Run(name, func(t *testing.T) {
			eng := EngineFor(n.Protocol)
			switch eng {
			case "xray":
				if _, err := XrayInbound(n); err != nil {
					t.Errorf("XrayInbound: %v", err)
				}
				if _, err := XrayOutbound(n); err != nil {
					t.Errorf("XrayOutbound: %v", err)
				}
				if b, err := RenderXrayJSON(n); err != nil || len(b) == 0 {
					t.Errorf("RenderXrayJSON: %v", err)
				}
			case "singbox":
				if IsSingboxEndpoint(n) {
					if _, err := SingboxEndpoint(n); err != nil {
						t.Errorf("SingboxEndpoint: %v", err)
					}
				} else {
					if _, err := SingboxOutbound(n); err != nil {
						t.Errorf("SingboxOutbound: %v", err)
					}
					if _, err := SingboxInbound(n); err != nil {
						t.Errorf("SingboxInbound: %v", err)
					}
				}
				if _, err := SingboxInbounds(n); err != nil {
					t.Errorf("SingboxInbounds: %v", err)
				}
				if b, err := RenderSingboxJSON(n); err != nil || len(b) == 0 {
					t.Errorf("RenderSingboxJSON: %v", err)
				}
			}
		})
	}
}

func TestEngineForCoversAll(t *testing.T) {
	for _, p := range model.AllProtocols() {
		if e := EngineFor(p); e == "" {
			t.Errorf("EngineFor(%s) empty", p)
		}
	}
}

// TestRenderMatrixExercisesBranches drives the render functions across every
// protocol × transport × security combination the model allows, tolerating the
// invalid ones (they return an error, which is itself a covered path). This
// exercises the per-transport and per-security branches that a single valid node
// per protocol cannot reach.
func TestRenderMatrixExercisesBranches(t *testing.T) {
	uuid := keygen.UUID()
	rk, _ := keygen.RealityKeys()
	ss, _ := keygen.SS2022PSK("2022-blake3-aes-128-gcm")
	transports := []model.Transport{
		{Network: model.NetTCP},
		{Network: model.NetWS, Path: "/p", Host: "h.example.com"},
		{Network: model.NetGRPC, ServiceName: "svc"},
		{Network: model.NetHTTPUpgrade, Path: "/u", Host: "h.example.com"},
		{Network: model.NetH2, Host: "h.example.com"},
		{Network: model.NetXHTTP, Path: "/x", Host: "h.example.com"},
	}
	securities := []model.Security{
		{Type: model.SecNone},
		{Type: model.SecTLS, ServerName: "h.example.com"},
		{Type: model.SecReality, Reality: &model.Reality{Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}, PrivateKey: rk.PrivateKey, PublicKey: rk.PublicKey, ShortIDs: []string{"01ab"}}},
	}
	protos := []model.Protocol{model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks}
	for _, p := range protos {
		for _, tr := range transports {
			for _, sec := range securities {
				n := &model.Node{Protocol: p, Address: "203.0.113.9", Port: 443, UUID: uuid, Password: "pw", Method: "2022-blake3-aes-128-gcm", Transport: tr, Security: sec}
				if p == model.ProtoShadowsocks {
					n.Password = ss
				}
				n.Normalize()
				// Tolerate errors: an invalid combo returns one, which is a covered
				// path. We only require no panic.
				_, _ = XrayInbound(n)
				_, _ = XrayOutbound(n)
				_, _ = RenderXrayJSON(n)
				_, _ = SingboxInbound(n)
				_, _ = SingboxOutbound(n)
				_, _ = SingboxInbounds(n)
				_, _ = RenderSingboxJSON(n)
			}
		}
	}

	// Endpoint protocols (wireguard/amneziawg) + niche (ssh, brook, forgedns).
	niche := []*model.Node{
		{Protocol: model.ProtoWireGuard, Address: "203.0.113.9", Port: 51820, WireGuard: &model.WireGuardOptions{PrivateKey: "cGVlcnByaXZhdGVrZXlwZWVycHJpdmF0ZWtleTA=", PeerPublicKey: "cGVlcnB1YmxpY2tleXBlZXJwdWJsaWNrZXkwMDA="}},
		{Protocol: model.ProtoSSH, Address: "203.0.113.9", Port: 22, Username: "u", Password: "p"},
		{Protocol: model.ProtoBrook, Address: "203.0.113.9", Port: 9999, Password: "pw"},
		{Protocol: model.ProtoHysteria2, Address: "203.0.113.9", Port: 443, Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "h"}},
		{Protocol: model.ProtoTUIC, Address: "203.0.113.9", Port: 443, UUID: uuid, Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "h"}},
		{Protocol: model.ProtoAnyTLS, Address: "203.0.113.9", Port: 443, Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "h"}},
	}
	for _, n := range niche {
		n.Normalize()
		if IsSingboxEndpoint(n) {
			_, _ = SingboxEndpoint(n)
		}
		_, _ = SingboxInbound(n)
		_, _ = SingboxOutbound(n)
		_, _ = SingboxInbounds(n)
		_, _ = RenderSingboxJSON(n)
		_, _ = XrayInbound(n)
		_, _ = XrayOutbound(n)
	}
}

// TestRenderFeatureRichNodes hits the feature-specific helpers: multiplex,
// Hysteria2 port-hopping + salamander obfs, and ShadowTLS inner details.
func TestRenderFeatureRichNodes(t *testing.T) {
	uuid := keygen.UUID()
	mux := &model.Multiplex{Enabled: true, Protocol: "smux", MaxStreams: 8, Padding: true,
		Brutal: &model.Brutal{Enabled: true, UpMbps: 100, DownMbps: 100}}
	nodes := []*model.Node{
		// Multiplex on vmess-ws-tls.
		{Protocol: model.ProtoVMess, Address: "203.0.113.9", Port: 443, UUID: uuid,
			Transport: model.Transport{Network: model.NetWS, Path: "/w"}, Security: model.Security{Type: model.SecTLS, ServerName: "h"}, Multiplex: mux},
		// Hysteria2 with port hopping + salamander obfs.
		{Protocol: model.ProtoHysteria2, Address: "203.0.113.9", Port: 443, Password: "pw",
			Security:  model.Security{Type: model.SecTLS, ServerName: "h"},
			Hysteria2: &model.Hysteria2Options{UpMbps: 50, DownMbps: 100, ObfsType: "salamander", ObfsPassword: "obfspw", PortHopping: "20000-30000", PortHopInterval: 30}},
		// TUIC with congestion + mux fields.
		{Protocol: model.ProtoTUIC, Address: "203.0.113.9", Port: 443, UUID: uuid, Password: "pw",
			Security: model.Security{Type: model.SecTLS, ServerName: "h"}, TUIC: &model.TUICOptions{CongestionControl: "bbr", UDPRelayMode: "native"}},
	}
	for _, n := range nodes {
		n.Normalize()
		_, _ = SingboxInbound(n)
		_, _ = SingboxOutbound(n)
		_, _ = SingboxInbounds(n)
		_, _ = RenderSingboxJSON(n)
		_, _ = XrayInbound(n)
		_, _ = XrayOutbound(n)
	}
}

// TestRenderMasqueradeAndShadowTLSInner covers the hysteria2 masquerade variants
// and the ShadowTLS inner-Shadowsocks helpers.
func TestRenderMasqueradeAndShadowTLSInner(t *testing.T) {
	tls := model.Security{Type: model.SecTLS, ServerName: "h"}
	for _, mq := range []*model.Hy2Masquerade{
		{Type: "proxy", URL: "https://example.com", RewriteHost: true},
		{Type: "file", Directory: "/var/www"},
		{Type: "string", StatusCode: 200, Content: "hello", Headers: map[string]string{"X-A": "b"}},
	} {
		n := &model.Node{Protocol: model.ProtoHysteria2, Address: "203.0.113.9", Port: 443, Password: "pw",
			Security: tls, Hysteria2: &model.Hysteria2Options{Masquerade: mq}}
		n.Normalize()
		_, _ = SingboxInbound(n)
		_, _ = SingboxInbounds(n)
	}
	// ShadowTLS with inner SS (reaches stlsInnerTag/stlsInnerPort).
	st := &model.Node{Protocol: model.ProtoShadowTLS, Address: "203.0.113.9", Port: 443, Security: tls,
		ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "stpw", HandshakeHost: "www.apple.com", HandshakePort: 443,
			InnerMethod: "2022-blake3-aes-128-gcm", InnerPassword: "MTIzNDU2Nzg5MDEyMzQ1Ng=="}}
	st.Normalize()
	_, _ = SingboxInbound(st)
	_, _ = SingboxInbounds(st)
	_, _ = SingboxOutbound(st)
}
