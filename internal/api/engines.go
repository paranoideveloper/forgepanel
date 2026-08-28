package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// enabledInboundNodes returns the canonical nodes for every enabled inbound.
func (s *Server) enabledInboundNodes() []*model.Node {
	if s.db == nil {
		return nil
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		return nil
	}
	var nodes []*model.Node
	for _, in := range ins {
		if !in.Enabled {
			continue
		}
		if n, err := in.Node(); err == nil {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// enabledInboundSpecs builds the multi-user materialisation: each enabled
// inbound plus a client per active user whose EFFECTIVE access includes it —
// inherited from their group or assigned to them directly. This is what the
// served config must contain for users to authenticate (spec §11), so it has to
// agree with what the subscription hands out: an inbound a user can see in their
// subscription but cannot authenticate on is worse than not offering it.
func (s *Server) enabledInboundSpecs() []engine.InboundSpec {
	if s.db == nil {
		return nil
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		return nil
	}
	groups, _ := s.db.ListGroups()
	users, _ := s.db.ListUsers(0)
	// inbound id -> its active users
	byInbound := map[uint][]store.User{}
	groupInbounds := map[uint][]uint{}
	for _, g := range groups {
		groupInbounds[g.ID] = []uint(g.InboundIDs)
	}
	for _, u := range users {
		// A user who is disabled, expired, OR over their data limit (StatusLimited)
		// must not have their client credential materialized into any inbound, so
		// the core refuses their traffic. Skipping only Disabled/Expired let an
		// over-quota account keep transferring until the next engine reload.
		if u.Status == store.StatusDisabled || u.Status == store.StatusExpired || u.Status == store.StatusLimited {
			continue
		}
		// A user held for exceeding their concurrent-address limit is excluded
		// for as long as the hold lasts. This is what makes User.IPLimit mean
		// anything: it was stored and editable for its whole life while nothing
		// read it, so an operator could cap an account at two devices and have
		// the panel accept the number and do nothing with it.
		if u.IPLimitedUntil != nil && u.IPLimitedUntil.After(time.Now()) {
			continue
		}
		seen := map[uint]bool{}
		for _, inID := range groupInbounds[u.GroupID] {
			if !seen[inID] {
				seen[inID] = true
				byInbound[inID] = append(byInbound[inID], u)
			}
		}
		direct, err := s.db.UserAssignments(u.ID)
		if err != nil {
			continue
		}
		for _, inID := range direct.Direct {
			if !seen[inID] {
				seen[inID] = true
				byInbound[inID] = append(byInbound[inID], u)
			}
		}
	}
	var specs []engine.InboundSpec
	for _, in := range ins {
		if !in.Enabled {
			continue
		}
		n, err := in.Node()
		if err != nil {
			continue
		}
		if in.NodeID > 0 {
			if node, err := s.db.NodeByID(in.NodeID); err == nil && node.Address != "" {
				n.Address = node.Address
			}
		}
		// Per-client WireGuard peers, so several users on one WG inbound each get
		// their own key and tunnel address instead of sharing one and taking the
		// session from each other in turn.
		s.applyWGPeers(n, in.ID, byInbound[in.ID])
		sp := engine.InboundSpec{Node: n}
		// The inbound's OWN credential — the UUID/password embedded in the config
		// link the panel shows and hands out (handleInboundConfig → export.URI) —
		// must always authenticate. Without it a standalone inbound with no assigned
		// users renders an empty `clients` list and VLESS/VMess/Trojan reject every
		// connection; only Shadowsocks (shared-key, no client list) worked. Assigned
		// users are materialized in addition, for per-user multi-tenant access.
		if n.UUID != "" || n.Password != "" {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email:    "inbound-" + strconv.FormatUint(uint64(in.ID), 10),
				Username: n.Username, UUID: n.UUID, Password: n.Password, Flow: n.Flow,
			})
		}
		for _, u := range byInbound[in.ID] {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email: job.UserEmail(u.ID), Username: u.Username, UUID: u.UUID, Password: u.Password, Flow: n.Flow,
			})
		}
		specs = append(specs, sp)
	}
	return specs
}

// engineUnavailable writes the one consistent response used whenever a request
// needs the local proxy engine but none is attached (control-plane-only panel,
// light-server mode, or tests). Every engine-dependent route uses this shape so
// callers can branch on the code, and nothing ever dereferences a nil engine.
func (s *Server) engineUnavailable(c *gin.Context) {
	c.JSON(503, gin.H{"error": "proxy engine is not available on this server", "code": "engine_unavailable"})
}

// reloadEngines regenerates and hot-applies the engine configs for all enabled
// inbounds + their users. Called after any inbound/user mutation and at boot.
// Errors are non-fatal (surfaced via /api/admin/engines): a panel must not crash
// because a core failed to download or a saved config is rejected.
func (s *Server) reloadEngines() {
	defer func() {
		if r := recover(); r != nil {
			// recover gracefully from engine reload panic
		}
	}()
	if s.isClosed() || s.engine == nil {
		return
	}
	specs := s.localInboundSpecs()
	bundle, _ := s.engine.ReloadSpecs(specs)
	// The bundle used to be discarded. It carries the list of inbounds no core
	// could serve, so throwing it away meant an operator created an inbound, the
	// panel accepted it, it never carried a byte, and NOTHING anywhere said why.
	s.recordNotServing(bundle)
	// Keep the host firewall in sync with the inbound ports so a created inbound
	// is actually reachable from the internet — otherwise it listens, passes the
	// loopback Verify, and ufw silently drops every external client (a phone).
	// Best-effort and backgrounded; never blocks or fails the reload.
	ports := make([]int, 0, len(specs))
	for _, sp := range specs {
		if sp.Node != nil && sp.Node.Port > 0 {
			ports = append(ports, sp.Node.Port)
		}
	}
	go firewall.EnsureOpen(ports)
}

// handleEngines returns the supervised cores' live status (spec §6).
func (s *Server) handleEngines(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, []any{})
		return
	}
	c.JSON(200, s.engine.Status())
}

// handleEngineConfig returns the last generated engine configs — the "show
// generated config" debugging superpower (spec §6).
func (s *Server) handleEngineConfig(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, gin.H{})
		return
	}
	b := s.engine.LastBundle()
	if b == nil {
		c.JSON(200, gin.H{"xray": "", "singbox": "", "note": "no inbounds loaded yet"})
		return
	}
	c.JSON(200, gin.H{
		"xray": string(b.Xray), "singbox": string(b.Singbox),
		"xray_inbounds": b.XrayN, "singbox_inbounds": b.SingboxN, "skipped": b.Skipped,
	})
}

// handleEngineValidate builds configs from current inbounds and runs each core's
// own validator without applying them (Config Doctor, spec §8.6).
func (s *Server) handleEngineValidate(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, gin.H{})
		return
	}
	_, results := s.engine.Validate(s.enabledInboundNodes())
	c.JSON(200, results)
}

// enabledInboundSpecsForNodeAddress returns inbound specs filtered for a specific node address.
// localInboundSpecs is the panel's OWN share: everything except the inbounds
// that belong to an enrolled node.
//
// The node side has always had enabledInboundSpecsForNodeAddress; the panel side
// had no filter at all and served the whole list, including inbounds bound to a
// node's address. A core cannot bind another machine's IP, so xray died on
// startup —
//
//	failed to listen TCP on 25443 > listen tcp 94.183.174.37:25443:
//	bind: cannot assign requested address
//
// — and because a core refuses a config as a WHOLE, one node-bound inbound took
// down every inbound the panel served itself. Measured on a live panel: 270
// restart attempts, xray never up, and every locally-created inbound dead while
// the UI showed them all enabled.
//
// An inbound with no address, 0.0.0.0 or :: is served here: that is the default
// a locally-created inbound gets, and it means "this machine".
func (s *Server) localInboundSpecs() []engine.InboundSpec {
	all := s.enabledInboundSpecs()
	if s.db == nil {
		return all
	}
	nodes, err := s.db.ListNodes()
	if err != nil || len(nodes) == 0 {
		return all
	}
	remote := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if a := strings.TrimSpace(n.Address); a != "" {
			remote[a] = true
		}
	}
	out := make([]engine.InboundSpec, 0, len(all))
	for _, sp := range all {
		if sp.Node == nil {
			continue
		}
		a := strings.TrimSpace(sp.Node.Address)
		if a == "" || a == "0.0.0.0" || a == "::" || !remote[a] {
			out = append(out, sp)
		}
	}
	return out
}

func (s *Server) enabledInboundSpecsForNodeAddress(addr string) []engine.InboundSpec {
	all := s.enabledInboundSpecs()
	if addr == "" {
		return all
	}
	var out []engine.InboundSpec
	for _, sp := range all {
		if sp.Node != nil && (sp.Node.Address == "" || sp.Node.Address == "0.0.0.0" || sp.Node.Address == addr) {
			out = append(out, sp)
		}
	}
	return out
}
