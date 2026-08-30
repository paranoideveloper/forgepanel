package api

// Outbounds and routing rules over HTTP.
//
// The panel could send an inbound's entire traffic through one relay chain and
// nothing else — no blocking, no geo-split, no per-user exit. These endpoints
// are the operator's side of the routing engine in internal/core/engine.
//
// EVERY MUTATION VALIDATES AGAINST THE REAL CORE BEFORE IT IS SAVED. A routing
// table the core refuses does not partly work: the core rejects the WHOLE config
// and every inbound on the box goes down. Saving first and discovering that on
// the next reload turns a typo into an outage, so the candidate config is built
// and validated first and the write only happens if it passed.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

// routingSpecs converts the stored routing definition into render specs.
//
// User ids become the counter emails the core knows them by. Doing it here, at
// the boundary, keeps that encoding in one place — two copies is exactly how the
// panel and a node end up disagreeing about which user owns a rule.
//
// It returns groups alongside outbounds and rules because this function IS the
// controller's routing source (server.go wires it to SetRoutingSource). A group
// left out here is a group that renders correctly in every unit test and appears
// in no config any core is ever handed.
func (s *Server) routingSpecs() ([]engine.OutboundSpec, []engine.RuleSpec, []engine.GroupSpec) {
	if s.db == nil {
		return nil, nil, nil
	}
	obs, err := s.db.ListOutbounds()
	if err != nil {
		return nil, nil, nil
	}
	outs := make([]engine.OutboundSpec, 0, len(obs))
	for _, o := range obs {
		if !o.Enabled {
			continue
		}
		outs = append(outs, engine.OutboundSpec{
			Tag: o.Tag, Protocol: o.Protocol,
			Settings:       json.RawMessage(o.Settings),
			StreamSettings: json.RawMessage(o.StreamSettings),
			SendThrough:    o.SendThrough,
		})
	}

	gs, err := s.db.ListOutboundGroups()
	if err != nil {
		return outs, nil, nil
	}
	groups := make([]engine.GroupSpec, 0, len(gs))
	for _, g := range gs {
		if !g.Enabled {
			continue
		}
		groups = append(groups, engine.GroupSpec{
			Tag: g.Tag, Members: g.Members, Strategy: g.Strategy,
			ProbeURL: g.ProbeURL, ProbeInterval: g.ProbeInterval,
			FallbackTag: g.AllDownPolicy,
		})
	}

	rs, err := s.db.ListRoutingRules()
	if err != nil {
		return outs, nil, groups
	}
	rules := make([]engine.RuleSpec, 0, len(rs))
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		emails := make([]string, 0, len(r.UserIDs))
		for _, id := range r.UserIDs {
			emails = append(emails, job.UserEmail(id))
		}
		rules = append(rules, engine.RuleSpec{
			Name: r.Name, Domain: r.Domain, IP: r.IP, Port: r.Port,
			Network: r.Network, Protocol: r.Protocol,
			InboundTags: r.InboundTags, UserEmails: emails,
			OutboundTag: r.OutboundTag,
		})
	}
	return outs, rules, groups
}

// validateRoutingOrFail builds a candidate config with the current routing
// definition and asks the core to validate it.
//
// It returns false and has already written the response when validation fails.
func (s *Server) validateRoutingOrFail(c *gin.Context) bool {
	if s.engine == nil {
		// No core to ask. Refusing every edit would make routing uneditable on a
		// panel that simply has no inbounds yet; the reload path validates
		// before applying regardless, so nothing unvalidated ever reaches a
		// running core.
		return true
	}
	outs, rules, groups := s.routingSpecs()
	bundle, err := engine.BuildMultiWithRouting(s.candidateSpecs(), 0, "", "", outs, rules, groups)
	if err != nil {
		failErr(c, http.StatusBadRequest, err)
		return false
	}

	// Then ask the CORE. Rendering only proves the panel can produce the JSON;
	// it says nothing about whether the core will accept it. A rule naming a
	// geosite category that does not exist renders perfectly and is refused by
	// the core with "code not found in geosite.dat" — which rejects the WHOLE
	// config and takes every inbound down. That is not hypothetical: a preset
	// written for this very feature referenced a torrent category that turned
	// out not to exist, and only the core could say so.
	//
	// Best-effort: a panel whose core has not been downloaded yet must still be
	// configurable, and the reload path validates before applying regardless, so
	// nothing unvalidated ever reaches a running core.
	if err := s.engine.ValidateGenerated(bundle); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "routing-apply", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Details: map[string]any{"hint": "the core rejected this configuration; a geosite:/geoip: name that does not exist is the usual cause"}})
		return false
	}
	return true
}

// jsonOrNil marshals a value for the audit diff, returning nil for a nil
// pointer so a creation reads as "created" rather than as a change from "null".
//
// Reflection rather than a type switch: the switch only knew two types, so every
// other caller's nil pointer marshalled to the literal "null" and the diff
// reported a creation as a change from a JSON null.
func jsonOrNil(v any) []byte {
	if v == nil {
		return nil
	}
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		// A diff is a convenience; failing the whole mutation because it could
		// not be rendered would be the tail wagging the dog.
		return nil
	}
	return b
}

// --- outbounds --------------------------------------------------------------

func (s *Server) handleListOutbounds(c *gin.Context) {
	out, err := s.db.ListOutbounds()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if out == nil {
		out = []store.Outbound{}
	}
	c.JSON(http.StatusOK, gin.H{
		"outbounds": out,
		// The built-ins always exist and rules may target them, so the UI can
		// offer them without hardcoding names that might change.
		"builtin": []string{store.OutboundDirect, store.OutboundBlock},
	})
}

func (s *Server) handleSaveOutbound(c *gin.Context) {
	var o store.Outbound
	if err := c.ShouldBindJSON(&o); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if id := c.Param("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid outbound id")
			return
		}
		o.ID = uint(n)
	}

	// Save inside a checkpoint: the core validates the whole config, so the only
	// way to know a new outbound is acceptable is to try it. A failure rolls the
	// row back rather than leaving a config the next reload will reject.
	prev, _ := s.db.OutboundByID(o.ID)
	if err := s.db.SaveOutbound(&o); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if !s.validateRoutingOrFail(c) {
		s.rollbackOutbound(prev, o.ID)
		return
	}
	s.auditWithDiff(c, "routing.outbound.saved", o.Tag, jsonOrNil(prev), jsonOrNil(&o))
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, o)
}

// rollbackOutbound restores the previous row, or removes a newly created one.
func (s *Server) rollbackOutbound(prev *store.Outbound, id uint) {
	if prev == nil {
		_ = s.db.DeleteOutbound(id)
		return
	}
	_ = s.db.SaveOutbound(prev)
}

func (s *Server) handleDeleteOutbound(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid outbound id")
		return
	}
	o, err := s.db.OutboundByID(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "outbound not found")
		return
	}
	if err := s.db.DeleteOutbound(uint(id)); err != nil {
		// The store refuses while a rule still points at it, because deleting it
		// anyway leaves the core rejecting the whole config — one delete taking
		// every inbound down.
		failErr(c, http.StatusConflict, err)
		return
	}
	s.audit(c, "routing.outbound.deleted", o.Tag)
	s.startBackground(s.reloadEngines)
	c.Status(http.StatusNoContent)
}

// --- rules ------------------------------------------------------------------

func (s *Server) handleListRoutingRules(c *gin.Context) {
	rules, err := s.db.ListRoutingRules()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if rules == nil {
		rules = []store.RoutingRule{}
	}
	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		// Precedence is published rather than left to be inferred. A routing
		// table whose order has to be discovered by experiment is one people get
		// wrong, and getting this one wrong can expose a server's real address.
		"precedence": []string{
			"the panel's own API",
			"per-inbound relay chains (egress)",
			"these rules, in order",
			"anything unmatched goes direct",
		},
	})
}

func (s *Server) handleSaveRoutingRule(c *gin.Context) {
	var r store.RoutingRule
	if err := c.ShouldBindJSON(&r); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if id := c.Param("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid rule id")
			return
		}
		r.ID = uint(n)
	}

	prev, _ := s.db.RoutingRuleByID(r.ID)
	if err := s.db.SaveRoutingRule(&r); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if !s.validateRoutingOrFail(c) {
		if prev == nil {
			_ = s.db.DeleteRoutingRule(r.ID)
		} else {
			_ = s.db.SaveRoutingRule(prev)
		}
		return
	}
	s.auditWithDiff(c, "routing.rule.saved", r.Name, jsonOrNil(prev), jsonOrNil(&r))
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, r)
}

func (s *Server) handleDeleteRoutingRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid rule id")
		return
	}
	r, err := s.db.RoutingRuleByID(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "rule not found")
		return
	}
	if err := s.db.DeleteRoutingRule(uint(id)); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "routing.rule.deleted", r.Name)
	s.startBackground(s.reloadEngines)
	c.Status(http.StatusNoContent)
}

func (s *Server) handleReorderRoutingRules(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 {
		fail(c, http.StatusBadRequest, "no order given")
		return
	}
	// Every existing rule must appear exactly once. A partial list would leave
	// the omitted rules at whatever position they held, producing an order
	// nobody designed — live, on a first-match routing table.
	existing, err := s.db.ListRoutingRules()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	want := make(map[uint]bool, len(existing))
	for _, r := range existing {
		want[r.ID] = true
	}
	seen := make(map[uint]bool, len(req.IDs))
	for _, id := range req.IDs {
		if !want[id] {
			fail(c, http.StatusBadRequest, "unknown rule id in the new order")
			return
		}
		if seen[id] {
			fail(c, http.StatusBadRequest, "a rule appears twice in the new order")
			return
		}
		seen[id] = true
	}
	if len(seen) != len(want) {
		fail(c, http.StatusBadRequest,
			"the new order must list every rule; omitting one leaves it at an arbitrary position")
		return
	}

	if err := s.db.ReorderRoutingRules(req.IDs); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "routing.rules.reordered", strconv.Itoa(len(req.IDs))+" rules")
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
