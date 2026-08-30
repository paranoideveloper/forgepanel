package api

// Reading the subscription-fetch history.
//
// The panel served /sub/:token and remembered nothing about it, so the first
// question in every support conversation — "has this person's client ever pulled
// the subscription at all?" — had no answer anywhere in the UI. "Imported the
// link and something else is broken" and "never imported the link" looked
// identical, and the operator's only recourse was to guess.
//
// WHO CAN READ IT. This route sits under /api/admin/users, which the authz table
// grants to resellers as their own job. That is safe only because userOr404
// scopes the lookup: without it, one reseller could read another tenant's
// subscriber User-Agents and source IPs by walking user ids.

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
)

// subRequestPage is the response shape. It carries the denormalised pair from
// the user record alongside the page, so "never fetched" is answerable without
// the caller having to interpret an empty first page.
type subRequestPage struct {
	Items         []store.SubRequest `json:"items"`
	Total         int64              `json:"total"`
	Limit         int                `json:"limit"`
	Offset        int                `json:"offset"`
	LastFetchAt   *time.Time         `json:"last_fetch_at"`
	LastUserAgent string             `json:"last_user_agent"`
}

func (s *Server) handleUserSubRequests(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	q := parseListQuery(c)
	limit := effectiveLimit(q)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	items, total, err := s.db.ListSubRequests(u.ID, limit, offset)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	if items == nil {
		// A null items would make the caller distinguish "no history" from "the
		// field is missing"; an empty list says the same thing once.
		items = []store.SubRequest{}
	}
	c.JSON(200, subRequestPage{
		Items: items, Total: total, Limit: limit, Offset: offset,
		LastFetchAt: u.SubUpdatedAt, LastUserAgent: u.SubLastUA,
	})
}
