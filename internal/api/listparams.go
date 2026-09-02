package api

// Turning query parameters into a store.ListQuery.
//
// Pagination is OPT-IN, and that is the whole compatibility story: a request
// with no paging parameters gets the bare array it always got, so every existing
// caller — the panel's own views included — is unaffected. A request that asks
// for a page gets an envelope carrying the total, because a page without a total
// says nothing about whether it is the whole story.

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
)

// listPage is the envelope returned when a caller asks for a page.
type listPage struct {
	Items  any   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// parseListQuery reads the standard list parameters.
//
// `page` is accepted as a convenience alongside offset, because a UI counts
// pages while an API counts rows, and making every caller do that arithmetic is
// how off-by-one paging bugs get written.
func parseListQuery(c *gin.Context) store.ListQuery {
	q := store.ListQuery{
		Search: strings.TrimSpace(c.Query("search")),
		Sort:   strings.TrimSpace(c.Query("sort")),
	}
	switch strings.ToLower(strings.TrimSpace(c.Query("order"))) {
	case "desc":
		q.Desc = true
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Offset = n
		}
	}
	if v := strings.TrimSpace(c.Query("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1 {
			limit := q.Limit
			if limit <= 0 {
				limit = store.DefaultListLimit
				q.Limit = limit
			}
			q.Offset = (n - 1) * limit
		}
	}
	// A search or an explicit sort implies the caller wants the paged envelope:
	// otherwise "search returned 12 of how many?" is unanswerable.
	if q.Search != "" && q.Limit == 0 {
		q.Limit = store.DefaultListLimit
	}
	return q
}

// effectiveLimit reports the page size actually applied, for the envelope.
func effectiveLimit(q store.ListQuery) int {
	if q.Limit <= 0 {
		return store.DefaultListLimit
	}
	if q.Limit > store.MaxListLimit {
		return store.MaxListLimit
	}
	return q.Limit
}
