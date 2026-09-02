package api

import (
	"strconv"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Config fan-out: one inbound can advertise a whole RANGE of client configs, not
// just one — the breadth the sample configs show (a REALITY inbound listed once
// per borrowed SNI, a CDN inbound listed once per clean edge IP). The inbound is
// a single listener; the SUBSCRIPTION is where that listener is offered under
// every camouflage variation, so a client's best-ping picker has many angles to
// try. Expansion is data-driven and opt-out: an inbound with a single SNI / no
// clean-IP list still yields exactly one config.

// expandNodeVariations turns one finalized node into every config variation it
// should advertise. cleanIPs is the operator's clean-edge-IP list (may be empty);
// it is only applied to CDN-frontable TLS transports. Names get a numeric suffix
// so the client shows them apart.
func expandNodeVariations(n *model.Node, cleanIPs []string, expandSNI, frontCleanIP bool) []*model.Node {
	// 1. REALITY with a rotation of borrowed SNIs → one config per SNI.
	if expandSNI && n.Security.Type == model.SecReality && n.Security.Reality != nil &&
		len(n.Security.Reality.ServerNames) > 1 {
		out := make([]*model.Node, 0, len(n.Security.Reality.ServerNames))
		for i, sni := range n.Security.Reality.ServerNames {
			c := cloneNode(n)
			c.Security.ServerName = sni
			// The client only needs the one SNI it presents; keep the full
			// server-side list intact on the inbound itself (not the link).
			c.Security.Reality.ServerNames = []string{sni}
			c.Remark = n.Remark + " · " + shortSNI(sni) + " " + strconv.Itoa(i+1)
			out = append(out, c)
		}
		return out
	}

	// 2. A CDN-frontable TLS transport → one config per clean edge IP, so the
	//    client can reach the same inbound through many Cloudflare addresses.
	if frontCleanIP && len(cleanIPs) > 0 && isCDNFrontable(n) {
		out := make([]*model.Node, 0, len(cleanIPs)+1)
		out = append(out, n) // keep the domain/host entry too
		for i, ip := range cleanIPs {
			c := cloneNode(n)
			c.Address = ip // dial the clean edge IP; SNI/Host still carry the domain
			c.Remark = n.Remark + " · CF " + strconv.Itoa(i+1)
			out = append(out, c)
		}
		return out
	}

	return []*model.Node{n}
}

// isCDNFrontable reports whether a node rides an HTTP-terminated transport over
// TLS — the only kind a Cloudflare-style edge can front by IP.
func isCDNFrontable(n *model.Node) bool {
	if n.Security.Type != model.SecTLS {
		return false
	}
	switch n.Transport.Network {
	case model.NetWS, model.NetXHTTP, model.NetHTTPUpgrade, model.NetGRPC:
		return true
	}
	return false
}

// cloneNode makes a deep-enough copy that per-variation edits (SNI, address,
// remark) do not bleed across configs. The nested Reality/Security pointers are
// the only shared mutable state the variations touch, so copy those explicitly.
func cloneNode(n *model.Node) *model.Node {
	c := *n
	if n.Security.Reality != nil {
		r := *n.Security.Reality
		c.Security.Reality = &r
	}
	if len(n.Security.ALPN) > 0 {
		c.Security.ALPN = append([]string{}, n.Security.ALPN...)
	}
	return &c
}

// shortSNI trims a borrowed SNI to a compact tag for the config name.
func shortSNI(sni string) string {
	// strip a leading "www."
	if len(sni) > 4 && sni[:4] == "www." {
		sni = sni[4:]
	}
	return sni
}
