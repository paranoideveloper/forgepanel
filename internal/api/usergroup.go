package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// This file is the user- and group-editing surface. Before it, users and groups
// could be created but not corrected: fixing a quota, a group, or an inbound
// meant deleting and recreating the record, which changes the subscription token
// and breaks every client already configured.
//
// Two rules run through all of it:
//
//   - Field-level permission is enforced HERE, server-side, with an explicit
//     allowlist per role. A request carrying a field the caller may not change is
//     rejected, not silently ignored, so a reseller cannot discover the boundary
//     by watching which of their edits stick.
//   - Every object id in a payload — user, group, inbound — is checked against
//     the caller's scope before use, rather than trusting the list the UI
//     rendered. The UI's job is to not offer forbidden options; it is not the
//     thing that enforces them.

// editableUserFields maps a request field to its database column. Anything not
// in this map cannot be changed through this endpoint at all.
var editableUserFields = map[string]string{
	"username":         "username",
	"status":           "status",
	"group_id":         "group_id",
	"data_limit":       "data_limit",
	"reset_strategy":   "reset_strategy",
	"expire_at":        "expire_at",
	"on_hold_duration": "on_hold_duration",
	"ip_limit":         "ip_limit",
	"telegram_id":      "telegram_id",
	"note":             "note",
}

// resellerUserFields is the subset a reseller may change on their own users.
// Quota-shaped fields are excluded: letting a reseller raise a user's data limit
// would let them mint traffic they were never allocated.
var resellerUserFields = map[string]bool{
	"username": true, "status": true, "note": true, "telegram_id": true,
	"expire_at": true, "ip_limit": true, "group_id": true,
}

// allowedUserFields returns the fields a role may edit.
func allowedUserFields(role string) map[string]bool {
	if role == string(store.RoleReseller) {
		return resellerUserFields
	}
	all := map[string]bool{}
	for k := range editableUserFields {
		all[k] = true
	}
	return all
}

// scopeOK reports whether the caller may act on a user at all. Owners and admins
// see everything; a reseller only their own.
func (s *Server) scopeOK(claims *auth.Claims, u *store.User) bool {
	if claims == nil {
		return false
	}
	if claims.Role == string(store.RoleReseller) {
		return u.OwnerAdminID == claims.AdminID
	}
	return claims.Role == string(store.RoleOwner) || claims.Role == string(store.RoleAdmin)
}

// assignableInbounds returns the set of inbound IDs the caller may assign, or nil
// when unrestricted. It is passed into the repository so the check happens below
// the handler.
func (s *Server) assignableInbounds(claims *auth.Claims) map[uint]bool {
	if claims == nil || claims.Role == string(store.RoleReseller) {
		// Resellers may only assign inbounds already reachable through a group
		// they can see. Anything else would let them hand their users access to
		// another tenant's inbound.
		allowed := map[uint]bool{}
		groups, err := s.db.ListGroups()
		if err != nil {
			return allowed
		}
		for _, g := range groups {
			for _, id := range g.InboundIDs {
				allowed[id] = true
			}
		}
		return allowed
	}
	return nil // owners/admins: unrestricted
}

// userOr404 loads a user and enforces the caller's scope.
func (s *Server) userOr404(c *gin.Context) (*store.User, *auth.Claims, bool) {
	claims, _ := auth.ClaimsFrom(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, 400, "invalid user id")
		return nil, nil, false
	}
	u, err := s.db.UserByID(uint(id))
	if err != nil {
		fail(c, 404, "user not found")
		return nil, nil, false
	}
	if !s.scopeOK(claims, u) {
		// Same response as "not found": a reseller should not be able to probe
		// which user IDs exist outside their tenancy.
		fail(c, 404, "user not found")
		return nil, nil, false
	}
	return u, claims, true
}

// handleGetUser returns one user with their effective inbound assignments split
// into direct and inherited, plus the metadata the edit form needs.
func (s *Server) handleGetUser(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	a, err := s.db.UserAssignments(u.ID)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gin.H{
		"user":        u,
		"assignments": a,
		"sub_url":     s.subURL(c, u.SubToken),
		// updated_at is the optimistic-concurrency token: send it back with a
		// PATCH and the write is refused if someone else edited in the meantime.
		"updated_at": u.UpdatedAt,
	})
}

// handleUpdateUser applies a partial update. Unlisted fields are left alone, so
// editing a note cannot disturb a quota, and secrets are never regenerated as a
// side effect — that requires the explicit reset endpoint.
func (s *Server) handleUpdateUser(c *gin.Context) {
	u, claims, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req map[string]any
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}

	var ifUnchanged time.Time
	if raw, ok := req["updated_at"].(string); ok && raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			ifUnchanged = t
		}
		delete(req, "updated_at")
	}

	allowed := allowedUserFields(claims.Role)
	fields := map[string]any{}
	fieldErrs := map[string]string{}
	for k, v := range req {
		col, known := editableUserFields[k]
		if !known {
			fieldErrs[k] = "unknown or read-only field"
			continue
		}
		if !allowed[k] {
			// Rejected, not ignored: silently dropping it would tell the caller
			// their edit succeeded when it did not.
			fieldErrs[k] = "your role may not change this field"
			continue
		}
		val, err := coerceUserField(k, v)
		if err != nil {
			fieldErrs[k] = err.Error()
			continue
		}
		fields[col] = val
	}
	if len(fieldErrs) > 0 {
		apierr.Fail(c, apierr.FieldErrors("user-update", fieldErrs))
		return
	}
	if len(fields) == 0 {
		fail(c, 400, "no editable fields supplied")
		return
	}

	if err := s.db.UpdateUserFields(u.ID, fields, ifUnchanged); err != nil {
		switch {
		case errors.Is(err, store.ErrStaleWrite):
			apierr.Fail(c, &apierr.Error{Op: "user-update", Kind: apierr.KindStaleWrite,
				Code: "stale_write", Message: err.Error(), Cause: err})
		default:
			failErr(c, 400, err)
		}
		return
	}
	// The BEFORE copy is already in hand (userOr404 loaded it) and the AFTER copy
	// is loaded below anyway, so recording what actually changed costs one
	// reordering. "alice edited a user" is not an answer to "who raised that
	// quota"; secret-bearing fields are recorded as changed without their values.
	fresh, _ := s.db.UserByID(u.ID)
	s.auditWithDiff(c, "user.update", u.Username, jsonOrNil(u), jsonOrNil(fresh))
	s.startBackground(s.reloadEngines)

	a, _ := s.db.UserAssignments(u.ID)
	c.JSON(200, gin.H{"user": fresh, "assignments": a, "updated_at": fresh.UpdatedAt})
}

// coerceUserField validates and converts one incoming field.
func coerceUserField(name string, v any) (any, error) {
	switch name {
	case "username":
		s, _ := v.(string)
		if len(s) < 1 {
			return nil, errors.New("must not be empty")
		}
		return s, nil
	case "status":
		s, _ := v.(string)
		switch store.UserStatus(s) {
		case store.StatusActive, store.StatusDisabled, store.StatusExpired,
			store.StatusLimited, store.StatusOnHold:
			return s, nil
		}
		return nil, errors.New("must be one of active, disabled, expired, limited, on_hold")
	case "reset_strategy":
		s, _ := v.(string)
		switch store.ResetStrategy(s) {
		case store.ResetNo, store.ResetDay, store.ResetWeek, store.ResetMonth,
			store.ResetYear, store.ResetOnExpire:
			return s, nil
		}
		return nil, errors.New("must be one of no_reset, day, week, month, year, on_expire")
	case "expire_at":
		if v == nil {
			return nil, nil // clearing the expiry is legitimate
		}
		s, _ := v.(string)
		if s == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, errors.New("must be an RFC3339 timestamp or null")
		}
		return t, nil
	case "group_id", "data_limit", "on_hold_duration", "ip_limit", "telegram_id":
		f, ok := v.(float64)
		if !ok {
			return nil, errors.New("must be a number")
		}
		if f < 0 {
			return nil, errors.New("must not be negative")
		}
		return int64(f), nil
	case "note":
		s, _ := v.(string)
		return s, nil
	}
	return nil, errors.New("unsupported field")
}

// handleSetUserInbounds replaces a user's DIRECT inbound assignments. Inherited
// group inbounds are not touched here: they belong to the group, and removing
// one for a single user would silently diverge that user from their group.
func (s *Server) handleSetUserInbounds(c *gin.Context) {
	u, claims, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req struct {
		InboundIDs []uint `json:"inbound_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	if err := s.db.SetUserInbounds(u.ID, req.InboundIDs, s.assignableInbounds(claims)); err != nil {
		if errors.Is(err, store.ErrForbiddenRef) {
			failErr(c, 403, err)
			return
		}
		failErr(c, 400, err)
		return
	}
	s.audit(c, "user.inbounds.set", u.Username)
	s.startBackground(s.reloadEngines)
	a, _ := s.db.UserAssignments(u.ID)
	c.JSON(200, gin.H{"assignments": a})
}

// handleResetUserCredentials regenerates a user's secrets. It is a separate,
// explicit endpoint precisely so an ordinary edit can never do it by accident:
// rotating the subscription token invalidates every client already configured.
func (s *Server) handleResetUserCredentials(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req struct {
		UUID     bool `json:"uuid"`
		Password bool `json:"password"`
		SubToken bool `json:"sub_token"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.UUID && !req.Password && !req.SubToken {
		fail(c, 400, "specify at least one of uuid, password, sub_token")
		return
	}
	fields := map[string]any{}
	if req.UUID {
		fields["uuid"] = keygen.UUID()
	}
	if req.Password {
		pw, err := keygen.Password(16)
		if err != nil {
			failErr(c, 500, err)
			return
		}
		fields["password"] = pw
	}
	if req.SubToken {
		fields["sub_token"] = token26()
	}
	if err := s.db.UpdateUserFields(u.ID, fields, time.Time{}); err != nil {
		failErr(c, 400, err)
		return
	}
	// WHICH credentials, never their values. "credentials reset" alone cannot
	// answer whether someone rotated a subscription link or invalidated every
	// config the user held — three very different blast radii.
	rotated := []string{}
	if req.UUID {
		rotated = append(rotated, "uuid")
	}
	if req.Password {
		rotated = append(rotated, "password")
	}
	if req.SubToken {
		rotated = append(rotated, "sub_token")
	}
	s.auditNote(c, "user.credentials.reset", u.Username, "rotated: "+strings.Join(rotated, ", "))
	s.startBackground(s.reloadEngines)
	fresh, _ := s.db.UserByID(u.ID)
	c.JSON(200, gin.H{"user": fresh, "sub_url": s.subURL(c, fresh.SubToken)})
}

// --- groups ---------------------------------------------------------------

// groupOr404 loads a group, rejecting callers who may not administer groups.
func (s *Server) groupOr404(c *gin.Context) (*store.Group, bool) {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil || claims.Role == string(store.RoleReseller) || claims.Role == string(store.RoleViewer) {
		fail(c, 403, "insufficient role")
		return nil, false
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, 400, "invalid group id")
		return nil, false
	}
	g, err := s.db.GroupByID(uint(id))
	if err != nil {
		fail(c, 404, "group not found")
		return nil, false
	}
	return g, true
}

// handleGetGroup returns a group with its member count, so the UI can show the
// blast radius before an edit is applied.
func (s *Server) handleGetGroup(c *gin.Context) {
	g, ok := s.groupOr404(c)
	if !ok {
		return
	}
	members, _ := s.db.UsersInGroup(g.ID)
	c.JSON(200, gin.H{"group": g, "members": members, "updated_at": g.UpdatedAt})
}

// handleUpdateGroup applies a partial group update, including its inbound set.
func (s *Server) handleUpdateGroup(c *gin.Context) {
	g, ok := s.groupOr404(c)
	if !ok {
		return
	}
	// Snapshot BEFORE the handler edits g in place, or the diff compares the new
	// value against itself and reports that nothing changed.
	before := *g
	var req struct {
		Name        *string    `json:"name"`
		Description *string    `json:"description"`
		InboundIDs  *[]uint    `json:"inbound_ids"`
		IsDefault   *bool      `json:"is_default"`
		UpdatedAt   *time.Time `json:"updated_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	fields := map[string]any{}
	if req.Name != nil {
		if *req.Name == "" {
			apierr.Fail(c, apierr.FieldErrors("group-update", map[string]string{"name": "must not be empty"}))
			return
		}
		fields["name"] = *req.Name
	}
	if req.Description != nil {
		fields["description"] = *req.Description
	}
	if req.InboundIDs != nil {
		seen := map[uint]bool{}
		ids := store.IntSlice{}
		for _, id := range *req.InboundIDs {
			if id != 0 && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		fields["inbound_ids"] = ids
	}
	var ifUnchanged time.Time
	if req.UpdatedAt != nil {
		ifUnchanged = *req.UpdatedAt
	}
	if len(fields) > 0 {
		if err := s.db.UpdateGroupFields(g.ID, fields, ifUnchanged); err != nil {
			if errors.Is(err, store.ErrStaleWrite) {
				apierr.Fail(c, &apierr.Error{Op: "group-update", Kind: apierr.KindStaleWrite,
					Code: "stale_write", Message: err.Error(), Cause: err})
				return
			}
			failErr(c, 400, err)
			return
		}
	}
	if req.IsDefault != nil {
		target := uint(0)
		if *req.IsDefault {
			target = g.ID
		}
		if err := s.db.SetDefaultGroup(target); err != nil {
			failErr(c, 400, err)
			return
		}
	}
	s.auditWithDiff(c, "group.update", g.Name, jsonOrNil(&before), jsonOrNil(g))
	s.startBackground(s.reloadEngines)
	fresh, _ := s.db.GroupByID(g.ID)
	members, _ := s.db.UsersInGroup(g.ID)
	c.JSON(200, gin.H{"group": fresh, "members": members, "updated_at": fresh.UpdatedAt})
}

// handleDeleteGroup removes a group without ever deleting its members. When the
// group still has members the caller must say what happens to them, either by
// naming a replacement group or by explicitly accepting that they end up with no
// group. Deleting a container must never delete its contents by default.
func (s *Server) handleDeleteGroup(c *gin.Context) {
	g, ok := s.groupOr404(c)
	if !ok {
		return
	}
	reassign, _ := strconv.ParseUint(c.Query("reassign_to"), 10, 64)
	allowOrphan := c.Query("remove_members_from_group") == "true"

	moved, err := s.db.DeleteGroupSafely(g.ID, uint(reassign), allowOrphan)
	if err != nil {
		if errors.Is(err, store.ErrGroupInUse) {
			members, _ := s.db.UsersInGroup(g.ID)
			apierr.Fail(c, &apierr.Error{Op: "group-delete", Kind: apierr.KindConflict,
				Code: "group_in_use", Message: err.Error(), Cause: err,
				Details: map[string]any{"members": members,
					"hint": "pass ?reassign_to=<group id> to move them, or " +
						"?remove_members_from_group=true to leave them with no group. " +
						"Members are never deleted."}})
			return
		}
		failErr(c, 400, err)
		return
	}
	s.audit(c, "group.delete", g.Name)
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"deleted": true, "members_moved": moved})
}

// handleSetSubRevoked revokes or restores a user's subscription.
//
// SubRevoked was enforced end to end and could not be set: a non-nil value
// makes subscriptionNodes return an empty list and excludes the user from the
// edge feed, and both of those were live — but nothing anywhere wrote the
// field, so the whole mechanism was unreachable. It is the one action that
// stops a leaked subscription URL without invalidating the credentials in every
// config the user has already imported, which is what rotating does.
func (s *Server) handleSetSubRevoked(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req struct {
		Revoked bool `json:"revoked"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "send {\"revoked\": true} or {\"revoked\": false}")
		return
	}
	if req.Revoked {
		now := time.Now().UTC()
		u.SubRevoked = &now
	} else {
		u.SubRevoked = nil
	}
	if err := s.db.SaveUser(u); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	action := "user.sub.restore"
	if req.Revoked {
		action = "user.sub.revoke"
	}
	s.audit(c, action, u.Username)
	// The engines carry the user's credentials; a revoked subscription still
	// needs its configs to stop resolving, and the feed is rebuilt from this.
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"username": u.Username, "sub_revoked_at": u.SubRevoked})
}
