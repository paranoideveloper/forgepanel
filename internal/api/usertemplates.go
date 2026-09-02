package api

// Saved plans: the CRUD surface over store.UserTemplate, plus the one endpoint
// that stamps a plan onto an account that already exists.
//
// The plan itself is not the feature. The feature is handleCreateUser reading
// one (internal/api/admin.go) — a template table with a green CRUD round-trip
// and nothing calling it is a settings page that changes nothing.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// usernameAffixMax matches the column width on UsernamePrefix/UsernameSuffix. A
// longer affix would be silently truncated by the database on some dialects, so
// the plan an operator saved and the names it produces would disagree.
const usernameAffixMax = 20

type userTemplateRequest struct {
	Name           *string `json:"name"`
	Note           *string `json:"note"`
	DataLimit      *int64  `json:"data_limit"`
	ExpireDays     *int    `json:"expire_days"`
	OnHoldDuration *int64  `json:"on_hold_duration"`
	ResetStrategy  *string `json:"reset_strategy"`
	Status         *string `json:"status"`
	GroupID        *uint   `json:"group_id"`
	InboundIDs     *[]uint `json:"inbound_ids"`
	IPLimit        *int    `json:"ip_limit"`
	UsernamePrefix *string `json:"username_prefix"`
	UsernameSuffix *string `json:"username_suffix"`
}

// templateScope returns the owner id a plan listing must be narrowed to, or zero
// for unrestricted. Owners and admins see every tenant's plans; a reseller sees
// only their own, because a plan carries another tenant's group and inbound ids.
func templateScope(claims *auth.Claims) uint {
	if claims == nil {
		return 0
	}
	if claims.Role == string(store.RoleReseller) {
		return claims.AdminID
	}
	return 0
}

// templateOr404 loads a plan and enforces the caller's scope. A reseller asking
// for another tenant's plan gets the same answer as one asking for a plan that
// never existed, so ids cannot be probed.
func (s *Server) templateOr404(c *gin.Context) (*store.UserTemplate, *auth.Claims, bool) {
	claims, _ := auth.ClaimsFrom(c)
	t, err := s.db.UserTemplateByID(parseID(c))
	if err != nil || (templateScope(claims) != 0 && t.OwnerAdminID != claims.AdminID) {
		apierr.Fail(c, &apierr.Error{Op: "user-template", Kind: apierr.KindNotFound,
			Status: http.StatusNotFound, Message: "no such user template"})
		return nil, nil, false
	}
	return t, claims, true
}

// applyTemplateRequest folds a request onto a plan row, refusing anything that
// would not survive the round trip.
func applyTemplateRequest(t *store.UserTemplate, req userTemplateRequest) error {
	fields := map[string]string{}
	if req.Name != nil {
		t.Name = strings.TrimSpace(*req.Name)
	}
	if req.Note != nil {
		t.Note = strings.TrimSpace(*req.Note)
	}
	if req.DataLimit != nil {
		if *req.DataLimit < 0 {
			fields["data_limit"] = "must not be negative"
		} else {
			t.DataLimit = *req.DataLimit
		}
	}
	if req.ExpireDays != nil {
		if *req.ExpireDays < 0 {
			fields["expire_days"] = "must not be negative; 0 means never"
		} else {
			t.ExpireDays = *req.ExpireDays
		}
	}
	if req.OnHoldDuration != nil {
		if *req.OnHoldDuration < 0 {
			fields["on_hold_duration"] = "must not be negative"
		} else {
			t.OnHoldDuration = *req.OnHoldDuration
		}
	}
	if req.IPLimit != nil {
		if *req.IPLimit < 0 {
			fields["ip_limit"] = "must not be negative; 0 means unlimited"
		} else {
			t.IPLimit = *req.IPLimit
		}
	}
	if req.ResetStrategy != nil {
		v := store.ResetStrategy(strings.TrimSpace(*req.ResetStrategy))
		switch v {
		case "":
			t.ResetStrategy = store.ResetNo
		case store.ResetNo, store.ResetDay, store.ResetWeek, store.ResetMonth,
			store.ResetYear, store.ResetOnExpire:
			t.ResetStrategy = v
		default:
			fields["reset_strategy"] = "not a reset cadence this panel knows"
		}
	}
	if req.Status != nil {
		v := store.UserStatus(strings.TrimSpace(*req.Status))
		switch v {
		case "":
			t.Status = store.StatusActive
		case store.StatusActive, store.StatusDisabled, store.StatusOnHold:
			t.Status = v
		default:
			// limited and expired are states the panel DERIVES from usage and
			// the clock. A plan that stamped one would create an account already
			// dead, which no reset or top-up brings back.
			fields["status"] = "a plan may only create accounts active, disabled or on_hold"
		}
	}
	if req.GroupID != nil {
		t.GroupID = *req.GroupID
	}
	if req.InboundIDs != nil {
		t.InboundIDs = store.IntSlice(*req.InboundIDs)
	}
	if req.UsernamePrefix != nil {
		t.UsernamePrefix = strings.TrimSpace(*req.UsernamePrefix)
	}
	if req.UsernameSuffix != nil {
		t.UsernameSuffix = strings.TrimSpace(*req.UsernameSuffix)
	}
	if len(t.UsernamePrefix) > usernameAffixMax {
		fields["username_prefix"] = "at most 20 characters"
	}
	if len(t.UsernameSuffix) > usernameAffixMax {
		fields["username_suffix"] = "at most 20 characters"
	}
	if t.Name == "" {
		fields["name"] = "a plan needs a name to be picked from a list"
	}
	if len(fields) > 0 {
		// FieldErrors is already KindValidation with a 422 — the UI puts each
		// message under the input that caused it.
		return apierr.FieldErrors("user-template", fields)
	}
	return nil
}

func (s *Server) handleListUserTemplates(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	rows, err := s.db.ListUserTemplates(templateScope(claims))
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []store.UserTemplate{}
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) handleGetUserTemplate(c *gin.Context) {
	t, _, ok := s.templateOr404(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, t)
}

func (s *Server) handleCreateUserTemplate(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req userTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	t := &store.UserTemplate{OwnerAdminID: claims.AdminID}
	if err := applyTemplateRequest(t, req); err != nil {
		apierr.Fail(c, err)
		return
	}
	// Validated here as well as at apply time: a plan holding an inbound the
	// author may not assign is a trap that only springs on whoever uses it,
	// weeks later, as an opaque 403 on a create they did nothing wrong in.
	if allowed := s.assignableInbounds(claims); allowed != nil {
		for _, id := range t.InboundIDs {
			if !allowed[id] {
				failErr(c, http.StatusForbidden, store.ErrForbiddenRef)
				return
			}
		}
	}
	if err := s.db.CreateUserTemplate(t); err != nil {
		s.failTemplateWrite(c, err)
		return
	}
	s.audit(c, "user-template.create", t.Name)
	c.JSON(http.StatusCreated, t)
}

func (s *Server) handleUpdateUserTemplate(c *gin.Context) {
	t, claims, ok := s.templateOr404(c)
	if !ok {
		return
	}
	var req userTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := applyTemplateRequest(t, req); err != nil {
		apierr.Fail(c, err)
		return
	}
	if allowed := s.assignableInbounds(claims); allowed != nil {
		for _, id := range t.InboundIDs {
			if !allowed[id] {
				failErr(c, http.StatusForbidden, store.ErrForbiddenRef)
				return
			}
		}
	}
	fields := map[string]any{
		"name": t.Name, "note": t.Note, "data_limit": t.DataLimit,
		"expire_days": t.ExpireDays, "on_hold_duration": t.OnHoldDuration,
		"reset_strategy": t.ResetStrategy, "status": t.Status,
		"group_id": t.GroupID, "inbound_ids": t.InboundIDs, "ip_limit": t.IPLimit,
		"username_prefix": t.UsernamePrefix, "username_suffix": t.UsernameSuffix,
	}
	if err := s.db.UpdateUserTemplate(t.ID, fields); err != nil {
		s.failTemplateWrite(c, err)
		return
	}
	s.audit(c, "user-template.update", t.Name)
	c.JSON(http.StatusOK, t)
}

func (s *Server) handleDeleteUserTemplate(c *gin.Context) {
	t, _, ok := s.templateOr404(c)
	if !ok {
		return
	}
	if err := s.db.DeleteUserTemplate(t.ID); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "user-template.delete", t.Name)
	c.JSON(http.StatusOK, gin.H{"deleted": t.ID})
}

// handleApplyUserTemplate stamps a plan onto ONE account that already exists.
//
// It does not rename the account. The username is part of every generated config
// and the subscription token is already in a client somewhere, so a rename is a
// separate, deliberate act — not a side effect of moving someone onto a new plan.
func (s *Server) handleApplyUserTemplate(c *gin.Context) {
	u, claims, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req struct {
		TemplateID uint `json:"template_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.TemplateID == 0 {
		fail(c, http.StatusBadRequest, "template_id required")
		return
	}
	tpl, err := s.db.UserTemplateByID(req.TemplateID)
	if err != nil || (templateScope(claims) != 0 && tpl.OwnerAdminID != claims.AdminID) {
		apierr.Fail(c, &apierr.Error{Op: "user-template", Kind: apierr.KindNotFound,
			Status: http.StatusNotFound, Message: "no such user template"})
		return
	}
	if err := s.db.ApplyTemplateToUser(u.ID, tpl.ID, s.assignableInbounds(claims)); err != nil {
		if errors.Is(err, store.ErrForbiddenRef) {
			failErr(c, http.StatusForbidden, err)
			return
		}
		failErr(c, http.StatusBadRequest, err)
		return
	}
	s.audit(c, "user.template.apply", u.Username+" ← "+tpl.Name)
	s.startBackground(s.reloadEngines)
	a, _ := s.db.UserAssignments(u.ID)
	c.JSON(http.StatusOK, gin.H{"applied": tpl.Name, "assignments": a})
}

// failTemplateWrite maps a plan write failure to the answer the UI can act on.
// A name collision is a 409 the operator fixes by typing another name, not a 500
// they can only report.
func (s *Server) failTemplateWrite(c *gin.Context, err error) {
	if errors.Is(err, store.ErrTemplateNameTaken) {
		apierr.Fail(c, &apierr.Error{Op: "user-template", Kind: apierr.KindConflict,
			Status: http.StatusConflict, Code: "template_name_taken",
			Message: "a plan with that name already exists", Cause: err})
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apierr.Fail(c, &apierr.Error{Op: "user-template", Kind: apierr.KindNotFound,
			Status: http.StatusNotFound, Message: "no such user template", Cause: err})
		return
	}
	failErr(c, http.StatusInternalServerError, err)
}
