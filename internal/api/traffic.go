package api

// Serving usage history.
//
// The panel knew a user's TOTAL and nothing about when, so there were no charts,
// no "why did this node spike on Tuesday", and no usage report for a customer
// disputing a bill. These endpoints expose the rollups written alongside the
// billing itself.

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// handleTrafficSeries returns usage over time for one subject.
func (s *Server) handleTrafficSeries(c *gin.Context) {
	scope := strings.TrimSpace(c.Query("scope"))
	if scope == "" {
		scope = store.ScopeUser
	}
	key := strings.TrimSpace(c.Query("key"))
	if key == "" {
		fail(c, 400, "key is required (a user id, node id or inbound id)")
		return
	}
	// A reseller may only chart their own customers. Without this the series
	// endpoint is a way to read another tenant's usage one key at a time.
	if !s.mayReadTrafficFor(c, scope, key) {
		fail(c, 403, "not your user")
		return
	}

	q := store.SeriesQuery{
		Period: strings.TrimSpace(c.Query("period")),
		Scope:  scope,
		Key:    key,
	}
	var err error
	if q.Since, err = parseAuditTime(c.Query("since")); err != nil {
		fail(c, 400, "since: "+err.Error())
		return
	}
	if q.Until, err = parseAuditTime(c.Query("until")); err != nil {
		fail(c, 400, "until: "+err.Error())
		return
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, convErr := strconv.Atoi(v); convErr == nil {
			q.Limit = n
		}
	}
	points, err := s.db.TrafficSeries(q)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	var total int64
	for _, p := range points {
		total += p.Bytes
	}
	c.JSON(200, gin.H{"scope": scope, "key": key, "period": q.Period, "points": points, "total": total})
}

// handleTopConsumers answers the question an operator asks first: who is using
// it all. Fetching every series and sorting in the browser would send the whole
// table to the client.
func (s *Server) handleTopConsumers(c *gin.Context) {
	scope := strings.TrimSpace(c.Query("scope"))
	if scope == "" {
		scope = store.ScopeUser
	}
	period := strings.TrimSpace(c.Query("period"))
	since, err := parseAuditTime(c.Query("since"))
	if err != nil {
		fail(c, 400, "since: "+err.Error())
		return
	}
	until, err := parseAuditTime(c.Query("until"))
	if err != nil {
		fail(c, 400, "until: "+err.Error())
		return
	}
	if since.IsZero() {
		// A default window, because "top consumers of all time" is rarely the
		// question and is the most expensive form of it.
		since = time.Now().Add(-7 * 24 * time.Hour)
	}
	limit := 10
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, convErr := strconv.Atoi(v); convErr == nil {
			limit = n
		}
	}
	rows, err := s.db.TopConsumers(scope, period, since, until, limit)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	// A reseller sees only their own customers here too.
	if scope == store.ScopeUser {
		filtered := rows[:0]
		for _, r := range rows {
			if s.mayReadTrafficFor(c, store.ScopeUser, r.Key) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	c.JSON(200, gin.H{"scope": scope, "since": since, "items": rows})
}

// mayReadTrafficFor scopes usage history to what the caller owns.
//
// Owners and admins see everything. A reseller sees only their own customers:
// otherwise this endpoint reads another tenant's usage one key at a time, which
// is the same leak the user list is already careful about.
func (s *Server) mayReadTrafficFor(c *gin.Context, scope, key string) bool {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil {
		return false
	}
	if claims.Role != string(store.RoleReseller) {
		return true
	}
	if scope != store.ScopeUser {
		// Node and inbound totals aggregate across tenants, so they are not a
		// reseller's to read at all.
		return false
	}
	id, err := strconv.ParseUint(key, 10, 32)
	if err != nil {
		return false
	}
	u, err := s.db.UserByID(uint(id))
	return err == nil && u != nil && u.OwnerAdminID == claims.AdminID
}
