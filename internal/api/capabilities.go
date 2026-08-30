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
	CDN       bool   `json:"cdn"`              // frontable through a normal HTTP CDN
	Reason    string `json:"reason,omitempty"` // set when Supported=false
}

// handleCapabilities returns an engine-version-based capability matrix so the UI
// and clients can tell, for the *pinned* engines, which transports/QUIC modes are
// real vs removed. In particular it distinguishes protocol-native QUIC
// (Hysteria2/TUIC/Brook quicserver) from the LEGACY Xray "quic" stream transport,
// which was removed and is never silently offered.
// portHoppingCapability reports whether this host lets the panel install the
// firewall redirects port hopping needs.
//
// Published from /capabilities rather than from an inbound-scoped route because
// the answer is a property of the MACHINE: it is the same before the first
// inbound exists, which is exactly when someone is deciding whether to configure
// a hop range.
func (s *Server) portHoppingCapability() gin.H {
	if s.engine == nil {
		return gin.H{"supported": false, "reason": "no proxy-core controller is running"}
	}
	st := s.engine.PortHopStatus(0, "")
	can, _ := st["can_manage"].(bool)
	out := gin.H{"supported": can, "backend": st["backend"], "net_admin": st["net_admin"]}
	if !can {
		// Say WHICH of the two reasons it is. "No firewall backend" and "no
		// permission" have completely different fixes, and a single vague
		// message sends people to the wrong one.
		if na, _ := st["net_admin"].(bool); !na {
			out["reason"] = "the panel does not hold CAP_NET_ADMIN, so it cannot install the redirect rules " +
				"(systemd: AmbientCapabilities=CAP_NET_ADMIN, or run as root)"
		} else {
			out["reason"] = "no usable firewall backend was found on this host (nftables or iptables is required)"
		}
		out["remediation"] = "the inbound still serves on its base port; the panel can print the exact " +
			"commands to install the range by hand from the inbound's port-hopping panel"
	}
	return out
}

func (s *Server) handleCapabilities(c *gin.Context) {
	c.JSON(200, gin.H{
		// The EFFECTIVE versions, not the compiled constants: once an operator
		// can pin a core, reporting the constant here would describe a core the
		// panel is not running. The Reason strings below stay on the constants
		// on purpose — they are prose about when a transport was removed
		// upstream, and rewriting them to a pinned version would make them false.
		"engines": gin.H{
			"xray":     s.coreVersion(binmgr.EngineXray),
			"sing-box": s.coreVersion(binmgr.EngineSingbox),
			"brook":    s.coreVersion(binmgr.EngineBrook),
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
		// Port hopping needs the panel to install nftables/iptables redirects, so
		// it depends on the HOST's grant of CAP_NET_ADMIN, not on any setting.
		// The capability check existed and NOTHING called it, so an operator
		// typed a hop range into the form, the panel accepted it, and the rules
		// were never installed — the inbound served only its base port and the
		// range silently did nothing.
		"port_hopping": s.portHoppingCapability(),
		"securities":   []string{"none", "tls", "reality"},
		// Every protocol/transport/security triple the builder can offer, each
		// one put through the same model.Validate that would reject it on save.
		// The prose note below says the same thing in English; only this can
		// grey out an option before the operator fills in the rest of the form.
		"combinations": combinationMatrix(),
		"note":         "REALITY only wraps tcp/xhttp/grpc; normal HTTP CDNs only front ws/xhttp/httpupgrade (and gRPC on capable accounts).",
	})
}
