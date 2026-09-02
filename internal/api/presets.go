package api

import (
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Preset is a ready-to-use, known-good protocol/transport/security combination.
// A preset fills valid defaults but every field stays editable afterwards — it is
// only a starting point. Each preset is verified to render + validate against the
// pinned engines (see the protocol matrix test), so the API never advertises a
// combination the engine would reject.
type Preset struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Engine      string      `json:"engine"`
	CDN         bool        `json:"cdn"`  // true = works behind a normal HTTP CDN (Cloudflare)
	Node        *model.Node `json:"node"` // template; run through create-defaults to complete
}

// presetList returns the curated compatibility presets. CDN is set only for
// HTTP-terminated transports (WS/XHTTP/HTTPUpgrade, and gRPC on capable accounts);
// raw TCP, REALITY and QUIC protocols are never marked CDN-compatible.
func presetList() []Preset {
	tls := model.Security{Type: model.SecTLS}
	reality := model.Security{Type: model.SecReality}
	ws := func(path string) model.Transport { return model.Transport{Network: model.NetWS, Path: path} }
	grpc := func(svc string) model.Transport { return model.Transport{Network: model.NetGRPC, ServiceName: svc} }
	xhttp := func(path string) model.Transport {
		return model.Transport{Network: model.NetXHTTP, Path: path, XHTTPMode: "auto"}
	}
	tcp := model.Transport{Network: model.NetTCP}

	return []Preset{
		{
			ID: "vless-reality-vision", Name: "VLESS · REALITY · Vision",
			Description: "Best all-round: raw TCP with REALITY and XTLS-Vision. No domain or certificate needed.",
			Engine:      "xray", CDN: false,
			Node: &model.Node{Protocol: model.ProtoVLESS, Transport: tcp, Security: reality, Flow: "xtls-rprx-vision"},
		},
		{
			ID: "vless-ws-tls-cdn", Name: "VLESS · WebSocket · TLS (CDN)",
			Description: "WebSocket over TLS — frontable through a Cloudflare-style HTTP CDN.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoVLESS, Transport: ws("/"), Security: tls},
		},
		{
			ID: "vless-xhttp-tls-cdn", Name: "VLESS · XHTTP · TLS (CDN)",
			Description: "XHTTP (the modern replacement for H2/QUIC transports) over TLS, CDN-frontable.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoVLESS, Transport: xhttp("/"), Security: tls},
		},
		{
			ID: "vless-grpc-tls", Name: "VLESS · gRPC · TLS",
			Description: "gRPC over TLS. CDN support depends on the account/service.",
			Engine:      "xray", CDN: false,
			Node: &model.Node{Protocol: model.ProtoVLESS, Transport: grpc("grpc"), Security: tls},
		},
		{
			ID: "vmess-ws-tls", Name: "VMess · WebSocket · TLS (CDN)",
			Description: "VMess (AEAD) over WebSocket+TLS, CDN-frontable.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoVMess, Transport: ws("/"), Security: tls},
		},
		{
			ID: "vmess-xhttp-tls", Name: "VMess · XHTTP · TLS (CDN)",
			Description: "VMess (AEAD) over XHTTP+TLS, CDN-frontable.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoVMess, Transport: xhttp("/"), Security: tls},
		},
		{
			ID: "trojan-tcp-tls", Name: "Trojan · TCP · TLS",
			Description: "Classic Trojan over raw TCP with TLS. Needs a domain + certificate.",
			Engine:      "xray", CDN: false,
			Node: &model.Node{Protocol: model.ProtoTrojan, Transport: tcp, Security: tls},
		},
		{
			ID: "trojan-ws-tls-cdn", Name: "Trojan · WebSocket · TLS (CDN)",
			Description: "Trojan over WebSocket+TLS, CDN-frontable.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoTrojan, Transport: ws("/"), Security: tls},
		},
		{
			ID: "trojan-xhttp-tls-cdn", Name: "Trojan · XHTTP · TLS (CDN)",
			Description: "Trojan over XHTTP+TLS, CDN-frontable.",
			Engine:      "xray", CDN: true,
			Node: &model.Node{Protocol: model.ProtoTrojan, Transport: xhttp("/"), Security: tls},
		},
		{
			ID: "shadowsocks-2022", Name: "Shadowsocks 2022",
			Description: "Shadowsocks with a SIP022 2022-blake3 AEAD cipher.",
			Engine:      "xray", CDN: false,
			Node: &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SS2022AES128},
		},
		{
			ID: "hysteria2", Name: "Hysteria2 (QUIC)",
			Description: "Hysteria2 over QUIC/UDP — fast on lossy links. Native QUIC, not a CDN transport.",
			Engine:      "sing-box", CDN: false,
			Node: &model.Node{Protocol: model.ProtoHysteria2, Security: tls},
		},
		{
			ID: "tuic", Name: "TUIC (QUIC)",
			Description: "TUIC v5 over QUIC/UDP. Native QUIC, not a CDN transport.",
			Engine:      "sing-box", CDN: false,
			Node: &model.Node{Protocol: model.ProtoTUIC, Security: tls},
		},
		{
			ID: "anytls", Name: "AnyTLS",
			Description: "AnyTLS over TLS: many streams multiplexed inside one real TLS connection.",
			Engine:      "sing-box", CDN: false,
			Node: &model.Node{Protocol: model.ProtoAnyTLS, Security: tls},
		},
		{
			ID: "shadowtls", Name: "ShadowTLS v3",
			Description: "A real TLS handshake to a decoy host, with Shadowsocks carrying the traffic behind it.",
			Engine:      "sing-box", CDN: false,
			Node: &model.Node{Protocol: model.ProtoShadowTLS,
				ShadowTLS: &model.ShadowTLSOptions{Version: 3, HandshakeHost: "www.apple.com", HandshakePort: 443}},
		},
		{
			ID: "amneziawg", Name: "AmneziaWG",
			Description: "WireGuard plus junk-packet obfuscation, in kernel mode. Ships a ready awg-quick client config.",
			Engine:      "amneziawg", CDN: false,
			Node: &model.Node{Protocol: model.ProtoAmneziaWG},
		},
		{
			ID: "wireguard", Name: "WireGuard",
			Description: "Standard WireGuard endpoint. Ships a ready wg-quick client config.",
			Engine:      "sing-box", CDN: false,
			Node: &model.Node{Protocol: model.ProtoWireGuard},
		},
		{
			ID: "brook-wss", Name: "Brook · WSS",
			Description: "Brook over WebSocket-Secure.",
			Engine:      "brook", CDN: false,
			Node: &model.Node{Protocol: model.ProtoBrook, Brook: &model.BrookOptions{Mode: "wssserver", Path: "/ws"}},
		},
	}
}

// handlePresets returns the compatibility presets with each template completed by
// the same create-defaults the create endpoint applies, so the UI can show a
// realistic preview and one-click a working inbound.
func (s *Server) handlePresets(c *gin.Context) {
	ps := presetList()
	for i := range ps {
		applyCreateDefaults(ps[i].Node) // fills keys/dest/creds so the preview is complete
	}
	c.JSON(200, gin.H{"presets": ps})
}
