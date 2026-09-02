package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// fullMatrix returns one node per distinct panel-creatable config variant.
func fullMatrix(t *testing.T) []*model.Node {
	t.Helper()
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	rk, _ := keygen.RealityKeys()
	sid, _ := keygen.ShortID(8)
	psk128, _ := keygen.SS2022PSK(model.SS2022AES128)
	psk256, _ := keygen.SS2022PSK(model.SS2022AES256)
	reality := func() model.Security {
		return model.Security{Type: model.SecReality, ServerName: "www.microsoft.com", Fingerprint: "chrome",
			Reality: &model.Reality{PrivateKey: rk.PrivateKey, PublicKey: rk.PublicKey, ShortID: sid,
				Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}}}
	}
	tls := func() model.Security { return model.Security{Type: model.SecTLS, ServerName: "forgepanel.local"} }
	port := 20000
	np := func() int { port++; return port }
	tcp := model.Transport{Network: model.NetTCP}
	ws := func() model.Transport {
		return model.Transport{Network: model.NetWS, Path: "/ws", Host: "forgepanel.local"}
	}
	grpc := func() model.Transport { return model.Transport{Network: model.NetGRPC, ServiceName: "grpcsvc"} }
	xhttp := func() model.Transport {
		return model.Transport{Network: model.NetXHTTP, Path: "/xh", XHTTPMode: "auto"}
	}
	hu := func() model.Transport {
		return model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "forgepanel.local"}
	}

	mk := func(remark string, n *model.Node) *model.Node {
		n.Remark = remark
		n.Address = "0.0.0.0"
		n.Port = np()
		n.Normalize()
		return n
	}

	return []*model.Node{
		// VLESS
		mk("vless-tcp-reality-vision", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Flow: "xtls-rprx-vision", Transport: tcp, Security: reality()}),
		mk("vless-tcp-reality", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: tcp, Security: reality()}),
		mk("vless-xhttp-reality", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: xhttp(), Security: reality()}),
		mk("vless-grpc-reality", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: grpc(), Security: reality()}),
		mk("vless-ws-tls", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: ws(), Security: tls()}),
		mk("vless-grpc-tls", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: grpc(), Security: tls()}),
		mk("vless-xhttp-tls", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: xhttp(), Security: tls()}),
		mk("vless-httpupgrade-tls", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Transport: hu(), Security: tls()}),
		mk("vless-tcp-tls-vision", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid, Flow: "xtls-rprx-vision", Transport: tcp, Security: tls()}),
		// VMess
		mk("vmess-tcp", &model.Node{Protocol: model.ProtoVMess, UUID: uuid, Transport: tcp}),
		mk("vmess-ws-tls", &model.Node{Protocol: model.ProtoVMess, UUID: uuid, Transport: ws(), Security: tls()}),
		mk("vmess-grpc-tls", &model.Node{Protocol: model.ProtoVMess, UUID: uuid, Transport: grpc(), Security: tls()}),
		// Trojan
		mk("trojan-tcp-tls", &model.Node{Protocol: model.ProtoTrojan, Password: "trojanpw", Transport: tcp, Security: tls()}),
		mk("trojan-ws-tls", &model.Node{Protocol: model.ProtoTrojan, Password: "trojanpw", Transport: ws(), Security: tls()}),
		mk("trojan-grpc-tls", &model.Node{Protocol: model.ProtoTrojan, Password: "trojanpw", Transport: grpc(), Security: tls()}),
		// Shadowsocks
		mk("ss-aes-256-gcm", &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SSAES256GCM, Password: "sspw"}),
		mk("ss-chacha20", &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SSChaCha20Poly, Password: "sspw"}),
		mk("ss-2022-128", &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SS2022AES128, Password: psk128}),
		mk("ss-2022-256", &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SS2022AES256, Password: psk256}),
		// SOCKS / HTTP
		mk("socks5", &model.Node{Protocol: model.ProtoSOCKS, Username: "u", Password: "p"}),
		mk("http", &model.Node{Protocol: model.ProtoHTTP, Username: "u", Password: "p"}),
		// sing-box family
		mk("hysteria2", &model.Node{Protocol: model.ProtoHysteria2, Password: "hy2pw",
			Hysteria2: &model.Hysteria2Options{ObfsType: "salamander", ObfsPassword: "obfspw", UpMbps: 100, DownMbps: 100},
			Security:  model.Security{Type: model.SecTLS, ServerName: "forgepanel.local", ALPN: []string{"h3"}}}),
		mk("tuic-v5", &model.Node{Protocol: model.ProtoTUIC, UUID: uuid, Password: "tuicpw",
			TUIC:     &model.TUICOptions{CongestionControl: "bbr", UDPRelayMode: "native"},
			Security: model.Security{Type: model.SecTLS, ServerName: "forgepanel.local", ALPN: []string{"h3"}}}),
		mk("anytls", &model.Node{Protocol: model.ProtoAnyTLS, Password: "anytlspw", Security: model.Security{Type: model.SecTLS, ServerName: "forgepanel.local"}}),
	}
}

// TestFullMatrixValidates is the exhaustive gate: build every
// distinct panel-creatable inbound variant, aggregate them, and run the REAL
// `xray -test` and `sing-box check` — so a config a core would reject can never
// reach the panel. Downloads the pinned cores; skipped in -short mode.
func TestFullMatrixValidates(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the engine binaries")
	}
	dir := t.TempDir()
	ctrl := NewController(dir, 10099)
	cp, kp, _ := cert.EnsureSelfSigned(filepath.Join(dir, "certs"))

	nodes := fullMatrix(t)
	// Per-variant validation so a failure names the exact broken combo.
	if _, err := ctrl.bins.Ensure(binmgr.EngineXray); err != nil {
		t.Fatalf("xray download: %v", err)
	}
	if _, err := ctrl.bins.Ensure(binmgr.EngineSingbox); err != nil {
		t.Fatalf("sing-box download: %v", err)
	}
	var failures []string
	for _, n := range nodes {
		b, err := engine.BuildMulti([]engine.InboundSpec{{Node: n}}, 10099, cp, kp)
		if err != nil {
			failures = append(failures, n.Remark+": build: "+err.Error())
			continue
		}
		if len(b.Skipped) > 0 {
			failures = append(failures, n.Remark+": SKIPPED: "+b.Skipped[0].Reason)
			continue
		}
		// Validate through the ADAPTER the panel would actually use, rather
		// than a supervisor the test builds itself. Validating via a
		// hand-built process meant this suite could pass while the product's
		// own validation path was broken or unwired — which is exactly what
		// happened: the adapter layer was never mounted at all.
		eng := render.EngineFor(n.Protocol)
		res, resErr := ctrl.Registry().ResolveNode(n)
		if resErr != nil {
			failures = append(failures, n.Remark+" ["+eng+"]: no adapter: "+resErr.Error())
			continue
		}
		cfg, genErr := res.Adapter.GenerateConfig([]*model.Node{n})
		if genErr != nil {
			failures = append(failures, n.Remark+" ["+res.Engine+"]: generate: "+genErr.Error())
			continue
		}
		if err := res.Adapter.ValidateConfig(cfg); err != nil {
			failures = append(failures, n.Remark+" ["+res.Engine+"]: "+err.Error())
		} else {
			t.Logf("✓ %-26s [%s] valid", n.Remark, res.Engine)
		}
	}
	if len(failures) > 0 {
		t.Fatalf("%d/%d variants failed engine validation:\n  - %s",
			len(failures), len(nodes), joinLines(failures))
	}
	t.Logf("ALL %d protocol variants passed xray -test / sing-box check", len(nodes))
	_ = os.Stdout
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}
