package api

// Routing presets: the handful of policies almost every operator wants, as one
// click instead of a dozen hand-typed rules.
//
// The headline one is not a convenience. `block-private` closes a hole that most
// proxy panels ship with: without it, any user of the proxy can ask it to
// connect to 169.254.169.254 and read the VPS provider's instance metadata —
// which on most clouds hands out credentials for the whole account — or reach
// anything else on the server's private network, including the panel's own
// admin port bound to localhost. The proxy is doing exactly what it was asked;
// nothing stops it because nothing was told to.
//
// The rest are the ordinary ones: block ads, block BitTorrent (the traffic that
// actually gets a VPS terminated), and geo-splits.

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
)

// routingPreset is a named bundle of rules.
type routingPreset struct {
	Name string `json:"name"`
	// Title and Why are shown to the operator. A preset whose consequences are
	// not stated is one that gets applied and then blamed for an outage.
	Title string `json:"title"`
	Why   string `json:"why"`
	// Caveat names what the preset will NOT do, or what it needs to work.
	Caveat string              `json:"caveat,omitempty"`
	Rules  []store.RoutingRule `json:"rules"`
}

// privateRanges are the destinations a proxy has no business reaching on behalf
// of a user.
//
// 169.254.0.0/16 is the important one — cloud instance metadata lives at
// 169.254.169.254 and on most providers serves credentials to anything that asks
// — but the whole set matters: the panel's own admin interface, the database,
// and every other service on the host's private network are reachable from the
// proxy unless something says otherwise.
var privateRanges = []string{
	"geoip:private",
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func routingPresets() []routingPreset {
	return []routingPreset{
		{
			Name:  "block-private",
			Title: "Block private networks and cloud metadata",
			Why: "Without this, any user of the proxy can reach 169.254.169.254 and read " +
				"this server's cloud credentials, or connect to anything else on its private " +
				"network — including the panel's own admin port. Apply this first.",
			Rules: []store.RoutingRule{{
				Name: "block private and metadata", Enabled: true,
				IP: privateRanges, OutboundTag: store.OutboundBlock,
			}},
		},
		{
			Name:  "block-ads",
			Title: "Block advertising and tracking domains",
			Why:   "Less traffic to carry, and it is the single most requested policy.",
			Rules: []store.RoutingRule{{
				Name: "block ads", Enabled: true,
				Domain: []string{"geosite:category-ads-all"}, OutboundTag: store.OutboundBlock,
			}},
		},
		{
			Name:  "block-torrent",
			Title: "Block BitTorrent",
			Why: "Torrent traffic through a VPS is what generates abuse reports and gets " +
				"servers terminated, usually without warning.",
			// Sniffed-protocol only. There is deliberately no companion domain
			// rule: geosite.dat has NO torrent category at all — not
			// category-bittorrent, bittorrent, torrent, category-torrent or p2p,
			// all checked against the real database. Shipping one would have
			// made this preset break the entire config the moment it was
			// applied, which is the failure this whole feature exists to avoid.
			Caveat: "Matches on the sniffed protocol, so the inbound must have sniffing enabled. " +
				"With sniffing off it matches nothing and blocks nothing.",
			Rules: []store.RoutingRule{{
				Name: "block bittorrent", Enabled: true,
				Protocol: []string{"bittorrent"}, OutboundTag: store.OutboundBlock,
			}},
		},
		{
			Name:  "ir-direct",
			Title: "Send Iranian destinations out directly",
			Why: "Traffic to Iranian sites does not need to be relayed onward, and going " +
				"direct is faster and cheaper.",
			Caveat: "This applies to inbounds WITHOUT a relay chain. An inbound with a chain " +
				"sends everything through it, deliberately.",
			Rules: []store.RoutingRule{{
				Name: "ir direct", Enabled: true,
				IP: []string{"geoip:ir"}, OutboundTag: store.OutboundDirect,
			}, {
				Name: "ir domains direct", Enabled: true,
				Domain: []string{"geosite:category-ir"}, OutboundTag: store.OutboundDirect,
			}},
		},
		{
			Name:   "cn-direct",
			Title:  "Send Chinese destinations out directly",
			Why:    "The same reasoning as the Iranian split, for a China-facing deployment.",
			Caveat: "Applies to inbounds without a relay chain.",
			Rules: []store.RoutingRule{{
				Name: "cn direct", Enabled: true,
				IP: []string{"geoip:cn"}, OutboundTag: store.OutboundDirect,
			}, {
				Name: "cn domains direct", Enabled: true,
				Domain: []string{"geosite:cn"}, OutboundTag: store.OutboundDirect,
			}},
		},
		{
			Name:   "ru-direct",
			Title:  "Send Russian destinations out directly",
			Why:    "The same reasoning, for a Russia-facing deployment.",
			Caveat: "Applies to inbounds without a relay chain.",
			Rules: []store.RoutingRule{{
				Name: "ru direct", Enabled: true,
				IP: []string{"geoip:ru"}, OutboundTag: store.OutboundDirect,
			}, {
				Name: "ru domains direct", Enabled: true,
				Domain: []string{"geosite:category-ru"}, OutboundTag: store.OutboundDirect,
			}},
		},
	}
}

func (s *Server) handleListRoutingPresets(c *gin.Context) {
	presets := routingPresets()
	// Whether geodata is installed decides whether most of these can work at
	// all, and the core's error for a missing database looks identical to its
	// error for a misspelt category. Saying so up front turns a confusing
	// failure into a known state.
	geo := true
	if s.engine != nil {
		geo = s.engine.GeoDataReady()
	}
	c.JSON(http.StatusOK, gin.H{
		"presets":       presets,
		"geodata_ready": geo,
		"geodata_note": "Presets using geosite:/geoip: need Xray's geodata files, which are " +
			"installed alongside the core. If this reports false, the core has not been " +
			"downloaded yet — create an inbound and the next reload will fetch it.",
	})
}

// handleApplyRoutingPreset appends a preset's rules.
//
// APPENDS, and never replaces. A preset that wiped the existing table would
// destroy hand-written rules an operator spent real time on, in response to a
// single click on something described as a convenience.
func (s *Server) handleApplyRoutingPreset(c *gin.Context) {
	name := c.Param("name")
	var preset *routingPreset
	for i := range routingPresets() {
		if p := routingPresets()[i]; p.Name == name {
			preset = &p
			break
		}
	}
	if preset == nil {
		fail(c, http.StatusNotFound, fmt.Sprintf("no preset named %q", name))
		return
	}

	existing, err := s.db.ListRoutingRules()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	have := make(map[string]bool, len(existing))
	for _, r := range existing {
		have[r.Name] = true
	}

	var added []uint
	var skipped []string
	next := len(existing)
	for _, r := range preset.Rules {
		if have[r.Name] {
			// Idempotent: applying a preset twice must not produce two identical
			// rules, the second of which can never match because the first
			// already did.
			skipped = append(skipped, r.Name)
			continue
		}
		rule := r
		rule.SortOrder = next
		next++
		if err := s.db.SaveRoutingRule(&rule); err != nil {
			// Roll back what this call added: half a preset is a policy nobody
			// chose, and "block private networks" applied halfway is a security
			// control that is not in force while looking like it is.
			for _, id := range added {
				_ = s.db.DeleteRoutingRule(id)
			}
			fail(c, http.StatusBadRequest, fmt.Sprintf("%s: %v", r.Name, err))
			return
		}
		added = append(added, rule.ID)
	}

	if !s.validateRoutingOrFail(c) {
		for _, id := range added {
			_ = s.db.DeleteRoutingRule(id)
		}
		return
	}

	s.audit(c, "routing.preset.applied", preset.Name)
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{
		"applied": len(added),
		"skipped": skipped,
		// The new rules go at the END, below anything already there. On a
		// first-match table that means an existing rule can shadow them, so the
		// operator is told rather than left to discover it.
		"note": "Added at the end of the list. Rules are first-match, so move them up if an " +
			"existing rule already matches the same traffic.",
	})
}
