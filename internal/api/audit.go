package api

// Reading the audit trail.
//
// Audit() wrote rows from the day it was added and nothing ever read them: no
// store method, no route, no view. An audit log nobody can read is not an audit
// log — it is a table that grows forever. The one consumer that looked like a
// reader fetched /admin/stats (which returns counts) typed as AuditLog[], so it
// iterated nothing and rendered nothing.
//
// WHO CAN READ IT. Entries carry the actor, their IP and what they did, across
// every admin. That is exactly the material a reseller must not see about other
// tenants, and a viewer has no business with at all, so this is owner/admin
// only — the same bar as the other credential-adjacent reads.

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
)

// auditPage is the response shape. The total is what makes a page meaningful:
// "50 shown" says nothing about whether that is the whole story.
type auditPage struct {
	Items  []store.AuditLog `json:"items"`
	Total  int64            `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

func (s *Server) handleListAudit(c *gin.Context) {
	f := store.AuditFilter{
		Actor:        strings.TrimSpace(c.Query("actor")),
		Action:       strings.TrimSpace(c.Query("action")),
		ActionPrefix: strings.TrimSpace(c.Query("action_prefix")),
	}
	if v := strings.TrimSpace(c.Query("admin_id")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			f.AdminID = uint(n)
		}
	}
	// Times are RFC3339 so a caller can page a window without guessing a format.
	// A malformed one is refused rather than ignored: silently widening the
	// window to "everything" is how an operator concludes an event never
	// happened.
	var err error
	if f.Since, err = parseAuditTime(c.Query("since")); err != nil {
		fail(c, 400, "since: "+err.Error())
		return
	}
	if f.Until, err = parseAuditTime(c.Query("until")); err != nil {
		fail(c, 400, "until: "+err.Error())
		return
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, convErr := strconv.Atoi(v); convErr == nil {
			f.Limit = n
		}
	}
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if n, convErr := strconv.Atoi(v); convErr == nil {
			f.Offset = n
		}
	}

	entries, total, err := s.db.ListAuditLogs(f)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	limit := f.Limit
	if limit <= 0 {
		limit = store.DefaultAuditLimit
	}
	if limit > store.MaxAuditLimit {
		limit = store.MaxAuditLimit
	}
	c.JSON(200, auditPage{Items: entries, Total: total, Limit: limit, Offset: f.Offset})
}

// handleAuditActions lists the actions present, for a filter control.
//
// Built from the data rather than a hardcoded list: the vocabulary grows
// whenever a handler adds an audit call, and a stale dropdown that omits the
// event an operator is hunting is worse than no dropdown.
func (s *Server) handleAuditActions(c *gin.Context) {
	actions, err := s.db.AuditActions()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"actions": actions})
}

func parseAuditTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}
