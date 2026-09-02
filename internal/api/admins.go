package api

// Admin and reseller provisioning.
//
// The reseller model was fully built and fully enforced — roles, per-admin user
// quotas, traffic credit, OwnerAdminID scoping, quota checks in the repository
// layer — and had no way to create a second admin. Multi-tenancy was
// unreachable: a panel could only ever hold the single account setup minted, so
// every quota check in the codebase guarded a case that could not occur.
//
// This is privilege management, so the rules that matter are the refusals:
//
//   - Only an OWNER may touch these routes. A reseller able to mint another
//     reseller, or to raise its own quota, is a privilege escalation with no
//     audit trail distinguishing it from legitimate use.
//   - The last owner can never be deleted, demoted or disabled. There is no
//     recovery path through the panel from an ownerless state — no account could
//     grant the role back — and the only fix is editing the database by hand.
//   - Deleting an admin that owns users REQUIRES saying where those users go.
//     A user whose owner no longer exists belongs to nobody: no reseller sees
//     them, quota accounting stops counting them, and they keep being served
//     with no one able to manage them.
//   - A role change, a disable, or a password reset bumps the session epoch, so
//     the account does not keep acting under its old authority until the token
//     happens to expire.

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// adminView is the API shape for an admin account. It deliberately carries no
// secret material: PasswordHash, TOTPSecret and RecoveryCodes are all json:"-"
// on the model, and this makes that explicit rather than incidental.
type adminView struct {
	ID            uint   `json:"id"`
	Username      string `json:"username"`
	Role          string `json:"role"`
	Disabled      bool   `json:"disabled"`
	TwoFactor     bool   `json:"two_factor_enabled"`
	UserQuota     int    `json:"user_quota"`
	TrafficCredit int64  `json:"traffic_credit"`
	// UsersOwned and TrafficAllocated are what makes the list actionable: an
	// owner deciding whether to delete a reseller needs to see what would have
	// to move first.
	UsersOwned       int64  `json:"users_owned"`
	TrafficAllocated int64  `json:"traffic_allocated"`
	CreatedAt        string `json:"created_at"`
}

func (s *Server) adminToView(a store.Admin) adminView {
	users, allocated, _ := s.db.ResellerUsage(a.ID)
	return adminView{
		ID: a.ID, Username: a.Username, Role: string(a.Role), Disabled: a.Disabled,
		TwoFactor: a.TOTPSecret != "", UserQuota: a.UserQuota, TrafficCredit: a.TrafficCredit,
		UsersOwned: users, TrafficAllocated: allocated,
		CreatedAt: a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (s *Server) handleListAdmins(c *gin.Context) {
	admins, err := s.db.ListAdmins()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	out := make([]adminView, 0, len(admins))
	for _, a := range admins {
		out = append(out, s.adminToView(a))
	}
	c.JSON(200, out)
}

func (s *Server) handleCreateAdmin(c *gin.Context) {
	var req struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Role          string `json:"role"`
		UserQuota     int    `json:"user_quota"`
		TrafficCredit int64  `json:"traffic_credit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		fail(c, 400, "a username is required")
		return
	}
	if len(req.Password) < 8 {
		fail(c, 400, "the password must be at least 8 characters")
		return
	}
	role := store.Role(strings.TrimSpace(req.Role))
	if role == "" {
		role = store.RoleReseller
	}
	if !store.ValidRole(role) {
		// An unknown role matches no authorization rule and fails closed, so the
		// account would exist, sign in, and be able to do nothing — with nothing
		// anywhere explaining why.
		fail(c, 400, "unknown role "+strconv.Quote(string(role))+
			"; valid roles are owner, admin, reseller, viewer")
		return
	}
	if existing, _ := s.db.AdminByUsername(username); existing != nil {
		fail(c, http.StatusConflict, "an admin named "+strconv.Quote(username)+" already exists")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		fail(c, 500, "could not hash the password: "+err.Error())
		return
	}
	a := &store.Admin{
		Username: username, PasswordHash: hash, Role: role,
		UserQuota: req.UserQuota, TrafficCredit: req.TrafficCredit,
	}
	if err := s.db.CreateAdmin(a); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "admin.create", username+" as "+string(role))
	c.JSON(201, s.adminToView(*a))
}

func (s *Server) handleUpdateAdmin(c *gin.Context) {
	id, ok := adminIDParam(c)
	if !ok {
		return
	}
	a, err := s.db.AdminByID(id)
	if err != nil || a == nil {
		fail(c, 404, "no such admin")
		return
	}
	// Snapshot BEFORE the handler edits a in place. This is the most
	// security-relevant diff in the panel: a role change, a raised quota or a
	// granted traffic credit is a privilege escalation that looks identical to
	// legitimate use unless the trail records what the value WAS.
	before := *a
	// Pointers so "not sent" and "sent as zero" are distinguishable: a quota of
	// 0 means unlimited, and treating an omitted field as 0 would silently make
	// every edit remove the limit.
	var req struct {
		Role          *string `json:"role"`
		Disabled      *bool   `json:"disabled"`
		UserQuota     *int    `json:"user_quota"`
		TrafficCredit *int64  `json:"traffic_credit"`
		Password      *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}

	claims, _ := auth.ClaimsFrom(c)
	authorityChanged := false

	if req.Role != nil {
		role := store.Role(strings.TrimSpace(*req.Role))
		if !store.ValidRole(role) {
			fail(c, 400, "unknown role "+strconv.Quote(string(role)))
			return
		}
		if role != a.Role {
			a.Role = role
			authorityChanged = true
		}
	}
	if req.Disabled != nil {
		if *req.Disabled && a.ID == claims.AdminID {
			// Locking yourself out is never the intent, and the panel cannot
			// undo it for you.
			fail(c, 400, "you cannot disable your own account")
			return
		}
		if *req.Disabled != a.Disabled {
			a.Disabled = *req.Disabled
			authorityChanged = true
		}
	}
	if req.UserQuota != nil {
		a.UserQuota = *req.UserQuota
	}
	if req.TrafficCredit != nil {
		a.TrafficCredit = *req.TrafficCredit
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			fail(c, 400, "the password must be at least 8 characters")
			return
		}
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			fail(c, 500, "could not hash the password: "+err.Error())
			return
		}
		a.PasswordHash = hash
		authorityChanged = true
	}

	if err := s.db.SaveAdminChecked(a); err != nil {
		if errors.Is(err, store.ErrLastOwner) {
			apierr.Fail(c, apierr.Conflict("admin-update", "last_owner",
				"this is the last owner: demoting, disabling or deleting it would leave "+
					"nobody able to administer the panel, and no account could grant the role back. "+
					"Promote another account to owner first."))
			return
		}
		failErr(c, 500, err)
		return
	}

	if authorityChanged {
		// Whatever this account was authorised to do has changed, so the tokens
		// it already holds must stop working. Without this a demoted owner keeps
		// owner access until their token happens to expire.
		_ = s.db.BumpAdminSessionEpoch(a.ID)
		s.audit(c, "sessions.revoke", a.Username)
	}
	s.auditWithDiff(c, "admin.update", a.Username, jsonOrNil(&before), jsonOrNil(a))
	c.JSON(200, s.adminToView(*a))
}

func (s *Server) handleDeleteAdmin(c *gin.Context) {
	id, ok := adminIDParam(c)
	if !ok {
		return
	}
	claims, _ := auth.ClaimsFrom(c)
	if id == claims.AdminID {
		fail(c, 400, "you cannot delete your own account")
		return
	}
	a, err := s.db.AdminByID(id)
	if err != nil || a == nil {
		fail(c, 404, "no such admin")
		return
	}

	// reassign_to names the admin inheriting this one's users. It is required
	// when the account owns any: see store.DeleteAdmin for why orphaning is not
	// an acceptable outcome.
	var reassign uint
	if v := strings.TrimSpace(c.Query("reassign_to")); v != "" {
		n, convErr := strconv.ParseUint(v, 10, 32)
		if convErr != nil {
			fail(c, 400, "reassign_to must be an admin id")
			return
		}
		reassign = uint(n)
	}

	if err := s.db.DeleteAdmin(id, reassign); err != nil {
		switch {
		case errors.Is(err, store.ErrLastOwner):
			apierr.Fail(c, apierr.Conflict("admin-delete", "last_owner",
				"this is the last owner; promote another account to owner first"))
		case errors.Is(err, store.ErrAdminOwnsUsers):
			owned, _ := s.db.CountUsersOwnedBy(id)
			apierr.Fail(c, &apierr.Error{Op: "admin-delete", Kind: apierr.KindConflict,
				Code: "owns_users",
				Message: "this admin still owns " + strconv.FormatInt(owned, 10) +
					" user(s). Pass ?reassign_to=<admin id> to move them, or they would belong to " +
					"nobody: no reseller could see them and nothing could manage them.",
				Details: map[string]any{"users_owned": owned}})
		default:
			failErr(c, 500, err)
		}
		return
	}
	s.audit(c, "admin.delete", a.Username)
	c.JSON(200, gin.H{"deleted": id, "reassigned_to": reassign})
}

func adminIDParam(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || n == 0 {
		fail(c, 400, "invalid admin id")
		return 0, false
	}
	return uint(n), true
}
