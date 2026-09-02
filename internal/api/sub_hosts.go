package api

// Applying an inbound's public endpoints ("hosts") to the configs it advertises.
//
// The fan-out that already existed was fixed-shape: one entry per REALITY SNI,
// or one per clean edge IP, with every other field copied from the inbound. It
// could not express the case operators actually run into — the same listener
// reached BOTH directly and through a CDN, where the CDN route needs a different
// port, a different SNI, a different Host header, its own ALPN, and
// allowInsecure because the edge presents its own certificate. Without a way to
// say that, the only route was to create the inbound twice: two listeners, two
// sets of credentials to keep in step, two rows to remember to change together.

import (
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// applyHosts turns one finalized node into one config per enabled endpoint.
//
// With no endpoints defined it returns the node unchanged, so every existing
// inbound behaves exactly as it did — this is opt-in per inbound, not a new
// shape imposed on the whole panel.
func applyHosts(n *model.Node, hosts []store.InboundHost) []*model.Node {
	enabled := make([]store.InboundHost, 0, len(hosts))
	for _, h := range hosts {
		if h.Enabled {
			enabled = append(enabled, h)
		}
	}
	if len(enabled) == 0 {
		return []*model.Node{n}
	}
	out := make([]*model.Node, 0, len(enabled))
	for i, h := range enabled {
		out = append(out, applyHost(n, h, i+1))
	}
	return out
}

// applyHost copies the node and lays one endpoint's overrides over it.
//
// Every field is an override and empty means "inherit". That is what keeps a
// host cheap: a CDN endpoint that differs only in port and Host header says
// exactly that and keeps following the inbound for everything else — including
// the credentials, which is the whole reason this beats a second inbound.
func applyHost(n *model.Node, h store.InboundHost, idx int) *model.Node {
	c := cloneNode(n)

	if a := strings.TrimSpace(h.Address); a != "" {
		c.Address = a
	}
	if h.Port > 0 {
		c.Port = h.Port
	}

	// Security mode. "none" has to be spellable: a plaintext-WS inbound behind a
	// Host-aware CDN is a real deployment, and without an explicit "none" there
	// would be no way to say "this endpoint does NOT speak TLS" — an empty
	// string already means inherit.
	switch strings.ToLower(strings.TrimSpace(h.Security)) {
	case "":
		// inherit
	case "none":
		c.Security.Type = model.SecNone
		c.Security.Reality = nil
	case "tls":
		c.Security.Type = model.SecTLS
		c.Security.Reality = nil
	case "reality":
		c.Security.Type = model.SecReality
	}

	if s := strings.TrimSpace(h.SNI); s != "" {
		c.Security.ServerName = s
	}
	if fp := strings.TrimSpace(h.Fingerprint); fp != "" {
		c.Security.Fingerprint = fp
	}
	if alpn := h.ALPNList(); len(alpn) > 0 {
		c.Security.ALPN = alpn
	}
	// AllowInsecure is a bool, so "inherit" cannot be distinguished from false —
	// but only ever ORing it in is the safe direction: an endpoint can relax
	// verification for itself and can never silently tighten it for an inbound
	// that had it on for a reason.
	if h.AllowInsecure {
		c.Security.AllowInsecure = true
	}

	if host := strings.TrimSpace(h.HostHeader); host != "" {
		c.Transport.Host = host
	}
	if p := strings.TrimSpace(h.Path); p != "" {
		// gRPC carries its route as the service name, not a path. Writing it to
		// Path would render an option the core ignores, so the endpoint would
		// look configured and route nowhere.
		if c.Transport.Network == model.NetGRPC {
			c.Transport.ServiceName = p
		} else {
			c.Transport.Path = p
		}
	}

	c.Remark = hostRemark(n.Remark, h, idx)
	return c
}

// hostRemark names the entry in the client's list.
func hostRemark(base string, h store.InboundHost, idx int) string {
	if r := strings.TrimSpace(h.Remark); r != "" {
		return r
	}
	label := strings.TrimSpace(h.Label)
	if label == "" {
		label = strconv.Itoa(idx)
	}
	if base == "" {
		return label
	}
	return base + " · " + label
}
