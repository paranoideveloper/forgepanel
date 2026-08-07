package api

import (
	"strconv"

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
		sp := engine.InboundSpec{Node: n}
		// The inbound's OWN credential — the UUID/password embedded in the config
		// link the panel shows and hands out (handleInboundConfig → export.URI) —
		// must always authenticate. Without it a standalone inbound with no assigned
		// users renders an empty `clients` list and VLESS/VMess/Trojan reject every
		// connection; only Shadowsocks (shared-key, no client list) worked. Assigned
		// users are materialized in addition, for per-user multi-tenant access.
		if n.UUID != "" || n.Password != "" {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email: "inbound-" + strconv.FormatUint(uint64(in.ID), 10),
				UUID:  n.UUID, Password: n.Password, Flow: n.Flow,
			})
		}
		for _, u := range byInbound[in.ID] {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email: job.UserEmail(u.ID), UUID: u.UUID, Password: u.Password, Flow: n.Flow,
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
	specs := s.enabledInboundSpecs()
	_, _ = s.engine.ReloadSpecs(specs)
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
