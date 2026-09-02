package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
)

// This file rounds out the inbound edit lifecycle (BUG-4): safe-edit change
// detection, clone/duplicate, enable/disable toggle, bulk actions, and a single
// level of undo.

// boolParam reads a boolean from the query string or a JSON body flag.
func boolParam(c *gin.Context, name string) bool {
	return c.Query(name) == "true"
}

// inboundBreakingChanges lists the edits that invalidate client configs already
// handed out — a changed port, protocol, transport network, or security type.
// These are what the safe-edit guard warns about.
func inboundBreakingChanges(oldN, newN *model.Node) []string {
	var out []string
	if oldN.Port != newN.Port {
		out = append(out, fmt.Sprintf("port %d → %d (clients keep dialing the old port)", oldN.Port, newN.Port))
	}
	if oldN.Protocol != newN.Protocol {
		out = append(out, fmt.Sprintf("protocol %s → %s", oldN.Protocol, newN.Protocol))
	}
	if oldN.Transport.Network != newN.Transport.Network {
		out = append(out, fmt.Sprintf("transport %s → %s", oldN.Transport.Network, newN.Transport.Network))
	}
	if oldN.Security.Type != newN.Security.Type {
		out = append(out, fmt.Sprintf("security %s → %s", oldN.Security.Type, newN.Security.Type))
	}
	return out
}

// handleCloneInbound duplicates an inbound onto a fresh free port, disabled, so
// the operator can adjust and enable it without disturbing the original.
func (s *Server) handleCloneInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	n, err := in.Node()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	n.Port = freeHighPort()
	n.Remark = in.Remark + " (copy)"
	clone, err := s.db.CreateInbound(n)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	// A clone starts disabled: it shares everything but the port, and the
	// operator almost always wants to review it before it serves traffic.
	clone.Enabled = false
	_ = s.db.SaveInbound(clone)
	s.audit(c, "inbound.clone", strconv.FormatUint(uint64(id), 10))
	c.JSON(201, gin.H{"id": clone.ID, "remark": clone.Remark, "port": clone.Port, "enabled": false})
}

// handleToggleInbound flips an inbound's enabled state and reloads the engine.
func (s *Server) handleToggleInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	in.Enabled = !in.Enabled
	if err := s.db.SaveInbound(in); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.toggle", strconv.FormatUint(uint64(id), 10))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"id": in.ID, "enabled": in.Enabled})
}

// handleUndoInbound restores an inbound to the config it had before the last
// edit. One level deep — the edit that is undone becomes the new "previous", so
// undo is itself reversible.
func (s *Server) handleUndoInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	if in.PrevNodeJSON == "" {
		fail(c, 409, "nothing to undo for this inbound")
		return
	}
	in.NodeJSON, in.PrevNodeJSON = in.PrevNodeJSON, in.NodeJSON
	// Re-mirror the indexed columns from the restored node.
	if n, err := in.Node(); err == nil {
		in.Remark, in.Protocol, in.Port = n.Remark, string(n.Protocol), n.Port
	}
	if err := s.db.SaveInbound(in); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.undo", strconv.FormatUint(uint64(id), 10))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"id": in.ID, "undone": true})
}

// handleBulkInbounds applies one action to many inbounds in a single call:
// enable, disable, delete, or set-domain (which cascades). Each id's result is
// reported so a partial failure is visible rather than silent.
func (s *Server) handleBulkInbounds(c *gin.Context) {
	var req struct {
		Action string `json:"action"`
		IDs    []uint `json:"ids"`
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	switch req.Action {
	case "enable", "disable", "delete", "set-domain":
	default:
		fail(c, 400, "action must be one of enable, disable, delete, set-domain")
		return
	}
	if req.Action == "set-domain" {
		req.Domain = settings.NormalizeDomain(req.Domain)
		if req.Domain != "" && !settings.ValidDomain(req.Domain) {
			fail(c, 422, "invalid domain")
			return
		}
	}
	results := make([]gin.H, 0, len(req.IDs))
	ok := 0
	for _, id := range req.IDs {
		in, err := s.db.InboundByID(id)
		if err != nil {
			results = append(results, gin.H{"id": id, "ok": false, "error": "not found"})
			continue
		}
		switch req.Action {
		case "enable", "disable":
			in.Enabled = req.Action == "enable"
			err = s.db.SaveInbound(in)
		case "delete":
			err = s.db.DeleteInbound(id)
		case "set-domain":
			n, e := in.Node()
			if e != nil {
				err = e
				break
			}
			n.Domain = req.Domain
			n.ApplyDomainCascade()
			in.PrevNodeJSON = in.NodeJSON
			if err = in.SetNode(n); err == nil {
				err = s.db.SaveInbound(in)
			}
		}
		if err != nil {
			results = append(results, gin.H{"id": id, "ok": false, "error": err.Error()})
			continue
		}
		ok++
		results = append(results, gin.H{"id": id, "ok": true})
	}
	s.audit(c, "inbound.bulk."+req.Action, fmt.Sprintf("%d of %d", ok, len(req.IDs)))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"action": req.Action, "succeeded": ok, "total": len(req.IDs), "results": results})
}

var _ = store.Inbound{}
