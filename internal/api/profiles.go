package api

// Profiles over HTTP, and the sync that materialises them.
//
// A binding OWNS its inbound row. That is what makes everything downstream —
// rendering, traffic accounting, subscriptions, routing — keep working with no
// changes at all: a materialised profile is just inbounds, and the panel already
// knows what to do with inbounds.
//
// The cost of that choice is drift: a row the operator edits directly would be
// silently overwritten by the next sync. So managed rows REFUSE direct edits and
// say where to make the change instead. Silently reverting somebody's work is
// the worse failure, because they watch it succeed and only find out later.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/profile"
	"github.com/forgepanel/forgepanel/internal/store"
)

type profileView struct {
	store.Profile
	Template *model.Node            `json:"template"`
	Bindings []store.ProfileBinding `json:"bindings"`
}

func (s *Server) handleListProfiles(c *gin.Context) {
	ps, err := s.db.ListProfiles()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	out := make([]profileView, 0, len(ps))
	for _, p := range ps {
		v := profileView{Profile: p, Bindings: []store.ProfileBinding{}}
		var n model.Node
		if json.Unmarshal([]byte(p.TemplateJSON), &n) == nil {
			v.Template = &n
		}
		if bs, err := s.db.ListBindings(p.ID); err == nil && bs != nil {
			v.Bindings = bs
		}
		out = append(out, v)
	}
	c.JSON(http.StatusOK, gin.H{"profiles": out})
}

func (s *Server) handleSaveProfile(c *gin.Context) {
	var req struct {
		Name     string      `json:"name"`
		Note     string      `json:"note"`
		Enabled  *bool       `json:"enabled"`
		Template *model.Node `json:"template"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		fail(c, http.StatusBadRequest, "a profile needs a name")
		return
	}
	if req.Template == nil {
		fail(c, http.StatusBadRequest, "a profile needs a template")
		return
	}

	p := &store.Profile{Name: req.Name, Note: req.Note, Enabled: true}
	if id := c.Param("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid profile id")
			return
		}
		existing, err := s.db.ProfileByID(uint(n))
		if err != nil {
			fail(c, http.StatusNotFound, "no such profile")
			return
		}
		p = existing
		p.Name, p.Note = req.Name, req.Note
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}

	tpl := req.Template.Clone()
	applyCreateDefaults(tpl)
	s.applyDomain(tpl)
	// Validate the template ONCE here rather than discovering it is unusable
	// separately on each of N bindings.
	if _, err := profile.Materialise(tpl, req.Name, profile.Binding{NodeName: "validation"}); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	raw, err := json.Marshal(tpl)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	p.TemplateJSON = string(raw)

	if err := s.db.SaveProfile(p); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	applied, syncErr := s.syncProfile(p.ID)
	if syncErr != nil {
		apierr.Fail(c, &apierr.Error{Op: "profile-sync", Kind: apierr.KindValidation,
			Message: syncErr.Error(), Cause: syncErr,
			Details: map[string]any{"profile": p}})
		return
	}
	s.audit(c, "profile.save", p.Name)
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"profile": p, "inbounds_synced": applied})
}

func (s *Server) handleDeleteProfile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid profile id")
		return
	}
	p, err := s.db.ProfileByID(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "no such profile")
		return
	}
	orphaned, err := s.db.DeleteProfile(uint(id))
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	// The rows the bindings owned go WITH the profile. Leaving them would keep
	// serving traffic under a definition nothing in the panel can edit as a
	// group any more — an orphan that looks like an ordinary inbound.
	removed := 0
	for _, inboundID := range orphaned {
		if err := s.db.DeleteInbound(inboundID); err == nil {
			removed++
		}
	}
	s.audit(c, "profile.delete", p.Name)
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"deleted_inbounds": removed})
}

func (s *Server) handleSaveBinding(c *gin.Context) {
	var req struct {
		ProfileID  uint   `json:"profile_id"`
		NodeID     uint   `json:"node_id"`
		Port       int    `json:"port"`
		PublicHost string `json:"public_host"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if req.ProfileID == 0 || req.NodeID == 0 {
		fail(c, http.StatusBadRequest, "a binding needs both a profile and a node")
		return
	}
	if _, err := s.db.ProfileByID(req.ProfileID); err != nil {
		fail(c, http.StatusNotFound, "no such profile")
		return
	}

	b := &store.ProfileBinding{
		ProfileID: req.ProfileID, NodeID: req.NodeID,
		Port: req.Port, PublicHost: req.PublicHost, Enabled: true,
	}
	if id := c.Param("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid binding id")
			return
		}
		b.ID = uint(n)
		// Carry the owned inbound forward, or the sync would create a second row
		// and abandon the first.
		if existing, err := s.db.ListBindings(req.ProfileID); err == nil {
			for _, e := range existing {
				if e.ID == b.ID {
					b.InboundID = e.InboundID
				}
			}
		}
	}
	if req.Enabled != nil {
		b.Enabled = *req.Enabled
	}
	if err := s.db.SaveBinding(b); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	applied, syncErr := s.syncProfile(req.ProfileID)
	if syncErr != nil {
		failErr(c, http.StatusBadRequest, syncErr)
		return
	}
	s.audit(c, "profile.binding.save", strconv.FormatUint(uint64(req.ProfileID), 10))
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"binding": b, "inbounds_synced": applied})
}

func (s *Server) handleDeleteBinding(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid binding id")
		return
	}
	inboundID, err := s.db.DeleteBinding(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "no such binding")
		return
	}
	if inboundID != 0 {
		// Removing the binding removes what it owned. An inbound left behind
		// keeps serving with nothing managing it.
		_ = s.db.DeleteInbound(inboundID)
	}
	s.audit(c, "profile.binding.delete", strconv.FormatUint(id, 10))
	s.startBackground(s.reloadEngines)
	c.Status(http.StatusNoContent)
}

// syncProfile materialises every enabled binding of a profile into its inbound
// row, and removes the rows of bindings that are disabled.
//
// It is called after every profile or binding change rather than on a timer:
// an operator who edits a profile expects the fleet to change now, and a
// scheduled reconcile would leave a window where the panel disagrees with itself.
func (s *Server) syncProfile(profileID uint) (int, error) {
	p, err := s.db.ProfileByID(profileID)
	if err != nil {
		return 0, err
	}
	var tpl model.Node
	if err := json.Unmarshal([]byte(p.TemplateJSON), &tpl); err != nil {
		return 0, fmt.Errorf("profile %q has an unreadable template: %w", p.Name, err)
	}
	bindings, err := s.db.ListBindings(profileID)
	if err != nil {
		return 0, err
	}

	nodeNames := map[uint]string{}
	if nodes, err := s.db.ListNodes(); err == nil {
		for _, n := range nodes {
			nodeNames[n.ID] = n.Name
		}
	}

	applied := 0
	for i := range bindings {
		b := &bindings[i]

		if !b.Enabled || !p.Enabled {
			// A disabled profile or binding must stop serving, not merely stop
			// being edited.
			if b.InboundID != 0 {
				_ = s.db.DeleteInbound(b.InboundID)
				b.InboundID = 0
				_ = s.db.SaveBinding(b)
			}
			continue
		}

		node, err := profile.Materialise(&tpl, p.Name, profile.Binding{
			NodeID: b.NodeID, NodeName: nodeNames[b.NodeID],
			Port: b.Port, PublicHost: b.PublicHost,
		})
		if err != nil {
			// One bad binding fails the WHOLE sync rather than being skipped: a
			// partially-applied profile is a fleet where some nodes carry the
			// new definition and some carry the old, which is the exact
			// inconsistency profiles exist to prevent.
			return applied, err
		}

		if b.InboundID != 0 {
			in, err := s.db.InboundByID(b.InboundID)
			if err == nil && in != nil {
				if err := in.SetNode(node); err != nil {
					return applied, err
				}
				if err := s.db.SaveInbound(in); err != nil {
					return applied, err
				}
				applied++
				continue
			}
			// The row is gone — deleted out from under the binding. Fall through
			// and create a fresh one rather than leaving the binding pointing at
			// nothing forever.
		}
		in, err := s.db.CreateInbound(node)
		if err != nil {
			return applied, err
		}
		b.InboundID = in.ID
		if err := s.db.SaveBinding(b); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}
