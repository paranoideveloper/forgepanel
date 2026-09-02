package protocol_test

import (
	"reflect"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/parse"
)

// sampleNodes returns one representative node per protocol × a spread of
// transports and security layers, covering the matrix in spec §3.1/§3.2. Every
// node here must survive parse(export(x)) == x after normalization.
func sampleNodes() []*model.Node {
	reality := func() *model.Security {
		return &model.Security{
			Type: model.SecReality, ServerName: "www.microsoft.com", Fingerprint: "chrome",
			Reality: &model.Reality{
				PublicKey: "AQ2Zr9m0Xr8s7t6u5v4w3x2y1z0aBcDeFgHiJkLmNo", ShortID: "0123abcd", SpiderX: "/",
			},
		}
	}
	tls := func(sni string) model.Security {
		return model.Security{Type: model.SecTLS, ServerName: sni, Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}}
	}
	return []*model.Node{
		// VLESS variants
		{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Flow: "xtls-rprx-vision", Transport: model.Transport{Network: model.NetTCP}, Security: *reality(), Remark: "vless-vision-reality"},
		{Protocol: model.ProtoVLESS, Address: "example.com", Port: 8443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetWS, Path: "/ws", Host: "cdn.example.com"}, Security: tls("cdn.example.com"), Remark: "vless-ws-tls"},
		{Protocol: model.ProtoVLESS, Address: "example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetGRPC, ServiceName: "grpcsvc", MultiMode: true}, Security: tls("example.com"), Remark: "vless-grpc"},
		{Protocol: model.ProtoVLESS, Address: "example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetXHTTP, Path: "/xh", Host: "h.example.com", XHTTPMode: "stream-up"}, Security: tls("example.com"), Remark: "vless-xhttp"},
		// VMess
		{Protocol: model.ProtoVMess, Address: "5.6.7.8", Port: 80, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Encryption: "auto", Transport: model.Transport{Network: model.NetWS, Path: "/vm", Host: "vm.example.com"}, Remark: "vmess-ws"},
		{Protocol: model.ProtoVMess, Address: "5.6.7.8", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Encryption: "aes-128-gcm", Transport: model.Transport{Network: model.NetTCP}, Security: tls("vm.example.com"), Remark: "vmess-tcp-tls"},
		// Trojan
		{Protocol: model.ProtoTrojan, Address: "9.9.9.9", Port: 443, Password: "p@ss word!",
			Transport: model.Transport{Network: model.NetTCP}, Security: tls("t.example.com"), Remark: "trojan-tls"},
		{Protocol: model.ProtoTrojan, Address: "9.9.9.9", Port: 443, Password: "trojanpw",
			Transport: model.Transport{Network: model.NetWS, Path: "/tj", Host: "t.example.com"}, Security: tls("t.example.com"), Remark: "trojan-ws"},
		// Shadowsocks
		{Protocol: model.ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: model.SSChaCha20Poly, Password: "sspass", Remark: "ss-chacha"},
		{Protocol: model.ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: model.SS2022AES128, Password: "XDsvRm+UPxAE3Xyj4ouGcA==", Remark: "ss-2022-128"},
		{Protocol: model.ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: model.SS2022AES256, Password: "HxgXRKLozqyTnMh0tW2c32mIjLspKKrhDhAADhrdXwg=", Remark: "ss-2022-256"},
		// SOCKS / HTTP
		{Protocol: model.ProtoSOCKS, Address: "2.2.2.2", Port: 1080, Username: "u", Password: "p", Remark: "socks"},
		{Protocol: model.ProtoHTTP, Address: "3.3.3.3", Port: 8080, Username: "u", Password: "p", Remark: "http"},
		// Hysteria2
		{Protocol: model.ProtoHysteria2, Address: "4.4.4.4", Port: 443, Password: "hy2pass",
			Security:  model.Security{Type: model.SecTLS, ServerName: "hy.example.com", ALPN: []string{"h3"}},
			Hysteria2: &model.Hysteria2Options{ObfsType: "salamander", ObfsPassword: "obfspw", UpMbps: 100, DownMbps: 200, PortHopping: "20000-50000"}, Remark: "hy2"},
		// TUIC
		{Protocol: model.ProtoTUIC, Address: "6.6.6.6", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Password: "tuicpw",
			Security: model.Security{Type: model.SecTLS, ServerName: "tuic.example.com", ALPN: []string{"h3"}},
			TUIC:     &model.TUICOptions{CongestionControl: "bbr", UDPRelayMode: "native"}, Remark: "tuic"},
		// AnyTLS
		{Protocol: model.ProtoAnyTLS, Address: "7.7.7.7", Port: 443, Password: "anytlspw", Security: tls("any.example.com"), Remark: "anytls"},
		// WireGuard
		{Protocol: model.ProtoWireGuard, Address: "8.8.8.8", Port: 51820, Remark: "wg",
			WireGuard: &model.WireGuardOptions{PrivateKey: "eBVrVY/gKsGJxfxjZqE88zIluFGgOU/LO4tiUrIRxDs=", PublicKey: "mo6UldV4T75yUQKdSmqyDfamIATMFeygq/dp9Sixd9g=", LocalAddress: []string{"10.0.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}}},
		// Brook
		{Protocol: model.ProtoBrook, Address: "10.10.10.10", Port: 9999, Password: "brookpw", Brook: &model.BrookOptions{Mode: "server"}, Remark: "brook"},
		// SSH — the ssh:// link intentionally carries no credential (see below).
		{Protocol: model.ProtoSSH, Address: "11.11.11.11", Port: 22, SSH: &model.SSHOptions{User: "root", Password: "sshpw"}, Remark: "ssh"},
		// ForgeDNS
		{Protocol: model.ProtoForgeDNS, Address: "t.example.com", Port: 53, Remark: "forgedns",
			ForgeDNS: &model.ForgeDNSOptions{Adapter: "stormdns", Zone: "t.example.com", Key: "k", RRType: "TXT"}},
	}
}

// TestRoundTrip is the mandatory property test from spec §15:
// parse(export(x)) == x across the protocol matrix.
func TestRoundTrip(t *testing.T) {
	for _, n := range sampleNodes() {
		want := n.Clone()
		want.Normalize()
		if err := want.Validate(); err != nil {
			t.Fatalf("%s: sample is itself invalid: %v", want.Remark, err)
		}
		uri, err := export.URI(want)
		if err != nil {
			t.Fatalf("%s: export: %v", want.Remark, err)
		}
		got, err := parse.URI(uri)
		if err != nil {
			t.Fatalf("%s: parse(%q): %v", want.Remark, uri, err)
		}
		// The ssh:// share link deliberately does NOT embed the password or
		// private key (those are provisioned out of band). So the round-trip
		// identity holds only over the link-representable projection: clear the
		// intentionally-omitted credential before comparing.
		if want.Protocol == model.ProtoSSH {
			want.SSH.Password = ""
			want.SSH.PrivateKey = ""
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: round-trip mismatch\n  uri:  %s\n  want: %+v\n  got:  %+v", want.Remark, uri, want, got)
		}
	}
}

// TestValidateRejectsBadSS2022 asserts the SIP022 PSK-length rule is enforced.
func TestValidateRejectsBadSS2022(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: model.SS2022AES256, Password: "dG9vc2hvcnQ="} // "tooshort"
	n.Normalize()
	if err := n.Validate(); err == nil {
		t.Fatal("expected SS2022 PSK length validation error, got nil")
	}
}
