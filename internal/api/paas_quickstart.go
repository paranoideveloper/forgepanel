package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// One click, every config a platform edge can actually carry.
//
// Working out that set by hand is a research project. Of the fifteen protocols
// the panel serves, six can ride a shared HTTP port at all; of those, the ones
// a given client can DIAL is a smaller set again, and nothing in any client
// tells you which. The combination that looks most attractive on paper —
// Shadowsocks-2022 over WebSocket — is the worst of them: it runs perfectly on
// the server, and the ss:// URI has nowhere standard to put a transport, so
// most clients read the link as plain TCP Shadowsocks and time out.
//
// So this creates the set and labels each entry with what can dial it, rather
// than handing over twelve links and letting the operator find out which four
// work by watching relatives fail to connect.

// ClientTier describes how widely a config can actually be dialled.
type ClientTier string

const (
	// TierUniversal is every client in use: v2rayNG, Hiddify, Streisand, NekoBox,
	// sing-box and Xray alike. WebSocket has been in all of them for years.
	TierUniversal ClientTier = "universal"
	// TierModern needs a recent client. HTTPUpgrade is in sing-box from 1.8 and
	// in current Xray, so it covers most of the field but not old installs.
	TierModern ClientTier = "modern"
	// TierPlugin needs a client that ships the v2ray-plugin binary — Shadowsocks
	// for Android, or a desktop client with it installed. iOS cannot: the
	// platform forbids spawning a subprocess, and a SIP003 plugin is one.
	TierPlugin ClientTier = "plugin-required"
	// TierSubscriptionOnly has no share link at all. The inbound works and is
	// reachable; the ss:// URI scheme simply cannot describe its transport, so
	// it is delivered through the Xray or JSON subscription instead — those
	// carry a full client config rather than a link.
	TierSubscriptionOnly ClientTier = "subscription-only"
	// TierXrayOnly is Xray-core clients only. sing-box has no XHTTP
	// implementation at all — a sing-box client cannot even parse the config,
	// let alone connect — and sing-box is what most iOS and desktop apps embed.
	TierXrayOnly ClientTier = "xray-only"
)

// paasQuickstartEntry is one config in the generated set.
type paasQuickstartEntry struct {
	Protocol model.Protocol `json:"protocol"`
	Network  model.Network  `json:"network"`
	Tier     ClientTier     `json:"client_support"`
	Note     string         `json:"note"`
}

// paasQuickstartSet is what a platform deployment gets.
//
// Shadowsocks appears on all three transports, and its three entries carry
// three different answers to "how do I hand this to somebody".
//
// It was excluded outright at first, on the grounds that an ss:// URI cannot
// carry a transport. That was too quick twice over. SIP002 has the plugin
// field, and v2ray-plugin's websocket mode is wire-compatible with what the
// core serves natively — proven against a live deployment, once mux is
// disabled. And for the other two, the missing piece is only the LINK: the
// inbound runs and is reachable, and the Xray and JSON subscriptions carry a
// full client config with the transport in it, so they are deliverable without
// any URI at all.
var paasQuickstartSet = []paasQuickstartEntry{
	{model.ProtoVLESS, model.NetWS, TierUniversal, "Works in every client. Start here."},
	{model.ProtoVMess, model.NetWS, TierUniversal, "Works in every client."},
	{model.ProtoTrojan, model.NetWS, TierUniversal, "Works in every client."},

	{model.ProtoVLESS, model.NetHTTPUpgrade, TierModern, "Needs sing-box 1.8+ or current Xray."},
	{model.ProtoVMess, model.NetHTTPUpgrade, TierModern, "Needs sing-box 1.8+ or current Xray."},
	{model.ProtoTrojan, model.NetHTTPUpgrade, TierModern, "Needs sing-box 1.8+ or current Xray."},

	{model.ProtoVLESS, model.NetXHTTP, TierXrayOnly, "Xray-core clients only; sing-box cannot dial XHTTP."},
	{model.ProtoVMess, model.NetXHTTP, TierXrayOnly, "Xray-core clients only; sing-box cannot dial XHTTP."},
	{model.ProtoTrojan, model.NetXHTTP, TierXrayOnly, "Xray-core clients only; sing-box cannot dial XHTTP."},

	{model.ProtoShadowsocks, model.NetWS, TierPlugin,
		"Needs a client carrying v2ray-plugin (Shadowsocks-Android, desktop). Not possible on iOS."},
	{model.ProtoShadowsocks, model.NetHTTPUpgrade, TierSubscriptionOnly,
		"No ss:// link exists for this transport — deliver it with the Xray or JSON subscription."},
	{model.ProtoShadowsocks, model.NetXHTTP, TierSubscriptionOnly,
		"No ss:// link exists for this transport — deliver it with the Xray or JSON subscription."},
}

// handlePaaSQuickstart creates every config this platform can serve, in one
// call, and returns each with its link and what can dial it.
func (s *Server) handlePaaSQuickstart(c *gin.Context) {
	if s.db == nil {
		c.JSON(501, gin.H{"error": "this server has no database"})
		return
	}
	pa := s.cfg.PaaS()
	if !pa.Enabled {
		c.JSON(409, gin.H{
			"error": "this panel is not running behind a platform edge",
			"remediation": "This creates the set of configs that a single shared HTTP port can carry. " +
				"On a server that owns its ports, create inbounds normally — every protocol is available there.",
		})
		return
	}
	if pa.Domain == "" {
		c.JSON(409, gin.H{
			"error":       "this service has no public hostname yet",
			"remediation": "Generate a domain on the platform first; every link would otherwise be unreachable.",
		})
		return
	}

	type result struct {
		ID       uint           `json:"id"`
		Remark   string         `json:"remark"`
		Protocol model.Protocol `json:"protocol"`
		Network  model.Network  `json:"network"`
		Tier     ClientTier     `json:"client_support"`
		Note     string         `json:"note"`
		URI      string         `json:"uri,omitempty"`
		Error    string         `json:"error,omitempty"`
	}
	existing := map[string]bool{}
	if ins, err := s.db.ListInbounds(); err == nil {
		for _, in := range ins {
			existing[in.Remark] = true
		}
	}

	out := make([]result, 0, len(paasQuickstartSet))
	created := 0
	for _, e := range paasQuickstartSet {
		remark := fmt.Sprintf("%s-%s", e.Protocol, e.Network)
		r := result{Remark: remark, Protocol: e.Protocol, Network: e.Network, Tier: e.Tier, Note: e.Note}
		if existing[remark] {
			// Idempotent: a second click must not pile up duplicates, each with
			// its own credentials, on a panel the operator then has to weed.
			r.Error = "already exists"
			out = append(out, r)
			continue
		}
		n := model.Node{Remark: remark, Protocol: e.Protocol,
			Transport: model.Transport{Network: e.Network},
			Security:  model.Security{Type: model.SecNone},
		}
		applyCreateDefaults(&n)
		s.applyPaaSAddressing(&n) // address, port, TLS and a minted path
		if err := n.Validate(); err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		in, err := s.db.CreateInbound(&n)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		r.ID = in.ID
		if uri, err := export.URI(&n); err == nil {
			r.URI = uri
		}
		created++
		out = append(out, r)
	}
	if created > 0 {
		s.audit(c, "inbound.paas_quickstart", fmt.Sprintf("%d created", created))
		s.startBackground(s.reloadEngines)
	}
	c.JSON(201, gin.H{
		"created": created,
		"configs": out,
		"note": "Hand out the universal ones first — they work in every client. " +
			"XHTTP is Xray-core only: sing-box, which most iOS and desktop apps embed, cannot dial it.",
	})
}
