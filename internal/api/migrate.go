package api

// Importing a foreign panel: preview first, then write.
//
// The importer read a foreign database and PRINTED JSON. Nothing was written, so
// "migrate from 3x-ui" meant reading the output and re-typing it by hand.
//
// Two endpoints, deliberately: an import runs once, against a panel the operator
// has not used before, with data they cannot easily reconstruct. Seeing "this
// would create 14 inbounds and skip 2 because their ports are taken" before
// anything happens is the difference between a migration and a gamble.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/migrate"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// existingState snapshots what the panel already holds, so a plan can tell a
// fresh import from a repeat.
func (s *Server) existingState() migrate.Existing {
	ex := migrate.Existing{
		PortsInUse:      map[int]string{},
		ImportedSources: map[string]string{},
		Remarks:         map[string]bool{},
		Usernames:       map[string]bool{},
	}
	if s.db == nil {
		return ex
	}
	if ins, err := s.db.ListInbounds(); err == nil {
		for _, in := range ins {
			ex.Remarks[in.Remark] = true
			if in.ImportSource != "" {
				ex.ImportedSources[in.ImportSource] = in.Remark
			}
			if in.Port > 0 {
				ex.PortsInUse[in.Port] = in.Remark
			}
		}
	}
	if users, err := s.db.ListUsers(0); err == nil {
		for _, u := range users {
			ex.Usernames[u.Username] = true
		}
	}
	return ex
}

// planFromRequest reads the foreign database named in the request and builds a
// plan against the panel's current state.
func (s *Server) planFromRequest(c *gin.Context) (*migrate.Plan, bool) {
	var req struct {
		Path string `json:"path"`
		// Panel names the source, for provenance. Defaulted from the file name
		// rather than required: making an operator invent a label to run a
		// migration is friction for no benefit in the common single-source case.
		Panel string `json:"panel"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return nil, false
	}
	if req.Path == "" {
		apierr.Fail(c, &apierr.Error{Op: "migrate-import", Kind: apierr.KindValidation,
			Message: "path to the foreign panel's SQLite database is required",
			Details: map[string]any{"hint": "3x-ui keeps it at /etc/x-ui/x-ui.db"}})
		return nil, false
	}
	if st, err := os.Stat(req.Path); err != nil || st.IsDir() {
		// Named separately from a parse failure: "the file is not there" and
		// "the file is not a panel database" have completely different fixes.
		fail(c, http.StatusBadRequest, "no readable file at "+req.Path)
		return nil, false
	}
	res, err := migrate.ImportPanelDB(req.Path)
	if err != nil {
		failErr(c, http.StatusBadRequest, err)
		return nil, false
	}
	// The source panel names the provenance keys, so importing from two different
	// panels that both number their inbounds from one does not make the second
	// one a no-op.
	panel := strings.TrimSpace(req.Panel)
	if panel == "" {
		panel = defaultSourcePanel(req.Path)
	}
	return migrate.BuildPlanFrom(res, s.existingState(), panel), true
}

// handleMigratePreview is the dry run. It writes nothing.
func (s *Server) handleMigratePreview(c *gin.Context) {
	plan, ok := s.planFromRequest(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"plan": plan})
}

// handleMigrateApply imports everything the plan marks as creatable.
//
// The plan is rebuilt here rather than accepted from the client: a plan posted
// back could have been edited, and it would be stale anyway if anything changed
// between preview and apply. Rebuilding costs one read and removes a whole class
// of "the preview said something else" bug.
func (s *Server) handleMigrateApply(c *gin.Context) {
	plan, ok := s.planFromRequest(c)
	if !ok {
		return
	}

	var items []store.ImportInbound
	for _, pi := range plan.Inbounds {
		if pi.Action != migrate.ActionCreate || pi.Node == nil {
			continue
		}
		item := store.ImportInbound{Node: pi.Node, SourceKey: pi.SourceKey}
		for _, pu := range pi.Users {
			if pu.Action != migrate.ActionCreate {
				continue
			}
			tok, err := keygen.Password(26)
			if err != nil {
				failErr(c, http.StatusInternalServerError, err)
				return
			}
			// A FRESH subscription token. The foreign panel's is not ours, and
			// carrying it over would mean two panels handing out the same URL —
			// with the old one still able to serve it.
			item.Users = append(item.Users, store.ImportUser{
				Username: pu.Username, UUID: pu.Source.UUID,
				Password: pu.Source.Password, SubToken: tok,
			})
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"outcome": &store.ImportOutcome{},
			"plan":    plan,
			"note":    "nothing was importable; the plan explains why for each item",
		})
		return
	}

	outcome, err := s.db.ApplyImport(items)
	if err != nil {
		// The whole import rolled back, so the panel is exactly as it was. Saying
		// so matters: an operator who thinks a partial import landed will go
		// looking for what to clean up.
		apierr.Fail(c, &apierr.Error{Op: "migrate-import", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Details: map[string]any{"note": "nothing was imported; the whole plan was rolled back and the panel is unchanged"}})
		return
	}
	s.auditNote(c, "migrate.import", "foreign panel",
		formatImportSummary(outcome.Inbounds, outcome.Users))
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"outcome": outcome, "plan": plan})
}

func formatImportSummary(inbounds, users int) string {
	return fmt.Sprintf("imported %d inbound(s) and %d user(s)", inbounds, users)
}

// defaultSourcePanel derives a provenance label from the database path.
func defaultSourcePanel(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if base == "" || base == "." {
		return "foreign"
	}
	return base
}
