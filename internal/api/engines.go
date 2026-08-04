package api

import (
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/engine"
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
// inbound plus a client per active user whose group binds that inbound. This is
// what the served config must contain for users to authenticate (spec §11).
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
		if u.Status != store.StatusActive {
			continue
		}
		for _, inID := range groupInbounds[u.GroupID] {
			byInbound[inID] = append(byInbound[inID], u)
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
		sp := engine.InboundSpec{Node: n}
		for _, u := range byInbound[in.ID] {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email: job.UserEmail(u.ID), UUID: u.UUID, Password: u.Password, Flow: n.Flow,
			})
		}
		specs = append(specs, sp)
	}
	return specs
}

// reloadEngines regenerates and hot-applies the engine configs for all enabled
// inbounds + their users. Called after any inbound/user mutation and at boot.
// Errors are non-fatal (surfaced via /api/admin/engines): a panel must not crash
// because a core failed to download or a saved config is rejected.
func (s *Server) reloadEngines() {
	if s.engine == nil {
		return
	}
	_, _ = s.engine.ReloadSpecs(s.enabledInboundSpecs())
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
