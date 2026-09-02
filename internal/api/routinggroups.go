package api

// Failover groups over HTTP.
//
// A routing rule could name exactly ONE exit. An operator with two relays picked
// one, and when it stopped answering their users' traffic stopped with it until
// somebody noticed and edited the rule by hand. A group is several outbounds
// behind one tag, health-probed by the core, so new connections move to whichever
// member is still up.
//
// Same checkpoint contract as the rest of routing: the candidate config is built
// and handed to the real core BEFORE the row is committed. The core has opinions
// the panel cannot reproduce — an unknown balancing strategy is refused with
// "unknown balancing strategy", and refusing means refusing the whole document,
// so every inbound on the box goes down at the next reload. Asking first is how
// a typo stays a 400 instead of an outage.

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/store"
)

func (s *Server) handleListOutboundGroups(c *gin.Context) {
	groups, err := s.db.ListOutboundGroups()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if groups == nil {
		groups = []store.OutboundGroup{}
	}
	c.JSON(http.StatusOK, gin.H{
		"groups": groups,
		// Published rather than hardcoded in the UI: a strategy the core does
		// not know renders a config it refuses, and the list of what it knows
		// belongs with the code that validates against it.
		"strategies": store.GroupStrategies,
		"defaults": gin.H{
			"strategy":       engine.DefaultGroupStrategy,
			"probe_url":      engine.DefaultProbeURL,
			"probe_interval": engine.DefaultProbeInterval,
		},
	})
}

func (s *Server) handleSaveOutboundGroup(c *gin.Context) {
	var g store.OutboundGroup
	if err := c.ShouldBindJSON(&g); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if id := c.Param("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid group id")
			return
		}
		g.ID = uint(n)
	}
	// Fill the cosmetic defaults HERE, where the store and the renderer meet, so
	// what is stored is what runs. Leaving them empty would still work — the
	// renderer has its own defaults — but the panel would then show a blank
	// probe URL for a group being probed once a minute, which is the kind of gap
	// an operator debugs for an hour. The all-down policy is NOT one of these:
	// the store defaults it, because getting it wrong is a leak rather than a
	// blank field, and that reasoning belongs next to the column.
	if g.Strategy == "" {
		g.Strategy = engine.DefaultGroupStrategy
	}
	if g.ProbeURL == "" {
		g.ProbeURL = engine.DefaultProbeURL
	}
	if g.ProbeInterval == "" {
		g.ProbeInterval = engine.DefaultProbeInterval
	}

	prev, _ := s.db.OutboundGroupByID(g.ID)
	if err := s.db.SaveOutboundGroup(&g); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if !s.validateRoutingOrFail(c) {
		if prev == nil {
			_ = s.db.DeleteOutboundGroup(g.ID)
		} else {
			_ = s.db.SaveOutboundGroup(prev)
		}
		return
	}
	s.auditWithDiff(c, "routing.group.saved", g.Tag, jsonOrNil(prev), jsonOrNil(&g))
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, g)
}

func (s *Server) handleDeleteOutboundGroup(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid group id")
		return
	}
	g, err := s.db.OutboundGroupByID(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "failover group not found")
		return
	}
	if err := s.db.DeleteOutboundGroup(uint(id)); err != nil {
		// Refused while a rule still targets it: that rule would name a
		// balancer nothing defines, which the core accepts and then drops every
		// connection the rule matches — traffic that stops for a reason visible
		// only in the engine log.
		failErr(c, http.StatusConflict, err)
		return
	}
	s.audit(c, "routing.group.deleted", g.Tag)
	s.startBackground(s.reloadEngines)
	c.Status(http.StatusNoContent)
}
