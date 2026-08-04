package api

import (
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// TransportCap describes whether a stream transport is usable with the pinned
// engine, and why not when it isn't. The panel only advertises transports the
// engine actually accepts (verified against the running core).
type TransportCap struct {
	Name      string `json:"name"`
	Engine    string `json:"engine"`
	Supported bool   `json:"supported"`
	CDN       bool   `json:"cdn"`             // frontable through a normal HTTP CDN
	Reason    string `json:"reason,omitempty"` // set when Supported=false
}

// handleCapabilities returns an engine-version-based capability matrix so the UI
// and clients can tell, for the *pinned* engines, which transports/QUIC modes are
// real vs removed. In particular it distinguishes protocol-native QUIC
// (Hysteria2/TUIC/Brook quicserver) from the LEGACY Xray "quic" stream transport,
// which was removed and is never silently offered.
func (s *Server) handleCapabilities(c *gin.Context) {
	c.JSON(200, gin.H{
		"engines": gin.H{
			"xray":     binmgr.XrayVersion,
			"sing-box": binmgr.SingboxVersion,
			"brook":    binmgr.BrookVersion,
		},
		"transports": []TransportCap{
			{Name: "tcp", Engine: "xray", Supported: true, CDN: false},
			{Name: "ws", Engine: "xray", Supported: true, CDN: true},
			{Name: "grpc", Engine: "xray", Supported: true, CDN: false},
			{Name: "httpupgrade", Engine: "xray", Supported: true, CDN: true},
			{Name: "xhttp", Engine: "xray", Supported: true, CDN: true},
			{Name: "h2", Engine: "xray", Supported: false, Reason: "HTTP/2 stream transport was removed in Xray " + binmgr.XrayVersion + " — use XHTTP"},
			{Name: "quic", Engine: "xray", Supported: false, Reason: "the legacy Xray QUIC stream transport was removed — use a native-QUIC protocol (Hysteria2/TUIC) or XHTTP"},
			{Name: "mkcp", Engine: "xray", Supported: false, Reason: "mKCP was removed in Xray " + binmgr.XrayVersion},
		},
		// QUIC is a protocol capability, not an Xray stream transport, on the pinned engines.
		"quic": gin.H{
			"native": []gin.H{
				{"protocol": "hysteria2", "engine": "sing-box", "supported": true},
				{"protocol": "tuic", "engine": "sing-box", "supported": true},
				{"protocol": "brook-quicserver", "engine": "brook", "supported": true},
			},
			"legacy_xray_transport": gin.H{
				"supported": false,
				"reason":    "removed in Xray " + binmgr.XrayVersion + "; would require a separately-pinned older compatibility engine",
			},
			// QUIC tuning fields exposed per protocol (semantics differ, so they live
			// on each protocol's own options — never a single inaccurate generic object).
			"tuning": gin.H{
				"hysteria2": []string{"up_mbps", "down_mbps", "obfs (salamander)", "ignore_client_bandwidth"},
				"tuic":      []string{"congestion_control", "udp_relay_mode", "zero_rtt_handshake", "heartbeat"},
			},
		},
		"securities": []string{"none", "tls", "reality"},
		"note":       "REALITY only wraps tcp/xhttp/grpc; normal HTTP CDNs only front ws/xhttp/httpupgrade (and gRPC on capable accounts).",
	})
}
