package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/version"
	"github.com/forgepanel/forgepanel/internal/webhook"
)

// handleLogin authenticates an admin and returns an access+refresh token pair.
func (s *Server) handleLogin(c *gin.Context) {
	if s.db == nil {
		fail(c, 501, "this server has no user database")
		return
	}
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		TOTP         string `json:"totp"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	ip := c.ClientIP()
	// Scoped on the source AND the target. IP alone stops one host hammering one
	// account and does nothing about a credential list tried against one
	// username from a thousand addresses — the attack that actually works.
	if !s.loginAllowed(ip, req.Username) {
		fail(c, 429, "too many attempts; try again later")
		return
	}
	admin, err := s.db.AdminByUsername(req.Username)
	if err != nil || admin.Disabled {
		s.loginFailed(ip, req.Username)
		fail(c, 401, "invalid credentials")
		return
	}
	ok, _ := auth.VerifyPassword(req.Password, admin.PasswordHash)
	if !ok {
		s.loginFailed(ip, req.Username)
		fail(c, 401, "invalid credentials")
		return
	}
	if admin.TOTPSecret != "" {
		switch {
		case req.TOTP != "":
			// Reject a code whose time step was already spent. A TOTP stays valid
			// across the skew window, so without this an intercepted code could be
			// replayed for up to 90 seconds. The claim is a conditional UPDATE, so
			// two concurrent logins with the same code cannot both win.
			step, ok := auth.VerifyTOTPStep(admin.TOTPSecret, req.TOTP, time.Now(), admin.LastTOTPStep)
			if ok {
				claimed, cerr := s.db.ClaimTOTPStep(admin.ID, step)
				ok = cerr == nil && claimed
			}
			if !ok {
				s.loginFailed(ip, req.Username)
				apierr.Fail(c, &apierr.Error{Op: "admin-login", Kind: apierr.KindAuth,
					Message: "invalid 2fa code",
					Details: map[string]any{"totp_required": true}})
				return
			}
		case req.RecoveryCode != "":
			used, remaining, err := s.db.ConsumeRecoveryCode(admin.ID, func(h string) bool {
				return auth.RecoveryCodeMatches(h, req.RecoveryCode)
			})
			if err != nil || !used {
				s.loginFailed(ip, req.Username)
				apierr.Fail(c, &apierr.Error{Op: "admin-login", Kind: apierr.KindAuth,
					Message: "invalid or already-used recovery code",
					Details: map[string]any{"totp_required": true}})
				return
			}
			// A recovery-code login means the owner lost their authenticator, which
			// is exactly the situation where an attacker may already hold a
			// session. Revoke every existing token for the account before issuing
			// the new one.
			_ = s.db.BumpAdminSessionEpoch(admin.ID)
			s.db.Audit(&store.AuditLog{AdminID: admin.ID, Actor: admin.Username, IP: c.ClientIP(), Action: "2fa.recovery.use"})
			s.db.Audit(&store.AuditLog{AdminID: admin.ID, Actor: admin.Username, IP: c.ClientIP(), Action: "sessions.revoke"})
			c.Header("X-Recovery-Codes-Remaining", strconv.Itoa(remaining))
		default:
			apierr.Fail(c, &apierr.Error{Op: "admin-login", Kind: apierr.KindAuth,
				Message: "2fa/totp code required",
				Details: map[string]any{"totp_required": true}})
			return
		}
	}
	if s.login != nil {
		s.loginSucceeded(ip, req.Username)
	}
	// Re-read the epoch: a recovery-code login just advanced it, and the new
	// token must carry the new value or it would invalidate itself.
	epoch, _ := s.db.AdminSessionEpoch(admin.ID)
	access, refresh, err := s.signer.IssueAt(admin.ID, admin.Username, string(admin.Role), epoch)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	s.db.Audit(&store.AuditLog{AdminID: admin.ID, Actor: admin.Username, IP: c.ClientIP(), Action: "login"})
	c.JSON(200, gin.H{"access_token": access, "refresh_token": refresh, "role": admin.Role, "expires_in": int(auth.AccessTTL.Seconds())})
}

// handleRefresh exchanges a refresh token for a new access token.
func (s *Server) handleRefresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	claims, err := s.signer.Verify(req.RefreshToken)
	if err != nil || claims.Kind != "refresh" {
		fail(c, 401, "invalid refresh token")
		return
	}
	// A revoked session must not be able to mint itself a fresh access token —
	// otherwise the refresh endpoint would quietly undo every invalidation.
	if !s.signer.SessionValid(claims) {
		fail(c, 401, "session revoked; sign in again")
		return
	}
	access, refresh, err := s.signer.IssueAt(claims.AdminID, claims.Username, claims.Role, claims.SessionEpoch)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"access_token": access, "refresh_token": refresh})
}

// handleMe returns the authenticated admin's claims.
func (s *Server) handleMe(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	out := gin.H{"admin_id": claims.AdminID, "username": claims.Username, "role": claims.Role}
	// two_factor_enabled is what the panel's security card binds its state to.
	// It was never returned, so the card read `undefined` and showed 2FA as OFF
	// for an admin who had it ON — offering "Enable" to someone already enrolled
	// and hiding the fact that the account was protected at all.
	// recovery_codes_remaining goes with it: a single-use code count that only
	// ever falls is the one number that tells an operator to regenerate BEFORE
	// running out and losing the account.
	if admin, err := s.db.AdminByID(claims.AdminID); err == nil {
		out["two_factor_enabled"] = admin.TOTPSecret != ""
		out["recovery_codes_remaining"] = recoveryRemaining(admin.RecoveryCodes)
	}
	c.JSON(200, out)
}

// --- inbounds -------------------------------------------------------------

func (s *Server) handleListInbounds(c *gin.Context) {
	// Page the rows BEFORE the per-inbound work below: reachability probes the
	// firewall per port, so transforming the whole table and then slicing it
	// would keep the cost pagination is meant to remove.
	q := parseListQuery(c)
	ins, total, err := s.db.ListInboundsPage(q)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	reach := firewall.Reachability()
	out := make([]gin.H, 0, len(ins))
	for _, in := range ins {
		n, _ := in.Node()
		out = append(out, gin.H{"id": in.ID, "remark": in.Remark, "protocol": in.Protocol, "port": in.Port,
			"enabled": in.Enabled, "node": n, "reachable": reach(in.Port),
			// Why an enabled inbound is not in the running configuration. The
			// detection, the storage and the audit trail for this were all built,
			// and the list — the only place the panel could show it — left the
			// field out of the payload, so the badge in the table could never
			// render and an inbound carrying no traffic still read as "Enabled".
			"not_serving_reason": in.NotServingReason,
			"not_serving_since":  in.NotServingSince,
			// Whether the undo endpoint has anything to restore. Without it the
			// only way to learn there is nothing to undo is to press Undo and
			// read a 409.
			"can_undo": in.PrevNodeJSON != "",
		})
	}
	if !q.Paged() {
		c.JSON(200, out)
		return
	}
	c.JSON(200, listPage{Items: out, Total: total, Limit: effectiveLimit(q), Offset: q.Offset})
}

func (s *Server) handleCreateInbound(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		failErr(c, 400, err)
		return
	}
	// Refuse a protocol no core can LISTEN on, before it is stored. SSH is
	// dialable as an egress hop and has no server side here: sing-box provides
	// an SSH outbound and no SSH inbound. Accepting it created an inbound that
	// sat in the database, failed to render on every reload, and served nobody —
	// with a default credential minted for it, which made it look configured.
	if !render.ServesInbound(n.Protocol) {
		apierr.Fail(c, apierr.Validation("inbound-create",
			fmt.Sprintf("%s cannot be served as an inbound: no core in this panel implements an %s server",
				n.Protocol, n.Protocol),
			"SSH can be used as an egress hop on another inbound's relay chain. "+
				"For SSH tunnelling to this host, use the system's own sshd, which the panel does not manage."))
		return
	}
	// Behind a platform edge, refuse what the platform can never carry rather
	// than storing a row that looks configured and moves nothing.
	if bad := s.paasCreateRefusal(&n); bad != nil {
		apierr.Fail(c, bad)
		return
	}
	applyCreateDefaults(&n)   // panel fills in keys/dest/flow/creds so it "just works"
	s.applyDomain(&n)         // inherit default domain + cascade to SNI/Host/etc.
	s.applyPaaSAddressing(&n) // behind a platform edge the address is not ours to choose
	if err := n.Validate(); err != nil {
		failErr(c, 400, err)
		return
	}
	// A hop range that swallows another inbound's port silently reroutes THAT
	// inbound's traffic here. The operator is looking at this one; the one that
	// breaks is a different one, with no error anywhere.
	if msg := s.portHopConflict(&n, 0); msg != "" {
		apierr.Fail(c, apierr.Conflict("inbound-write", "port_hop_conflict", msg))
		return
	}
	in, err := s.db.CreateInbound(&n)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.create", in.Remark)
	s.startBackground(s.reloadEngines)
	c.JSON(201, gin.H{"id": in.ID, "remark": in.Remark, "protocol": in.Protocol, "port": in.Port})
}

func (s *Server) handleUpdateInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		failErr(c, 400, err)
		return
	}
	if bad := s.paasCreateRefusal(&n); bad != nil {
		apierr.Fail(c, bad)
		return
	}
	applyCreateDefaults(&n)
	s.applyDomain(&n)         // inherit default domain + cascade
	s.applyPaaSAddressing(&n) // an edit must not reintroduce an address the platform will not serve
	if err := n.Validate(); err != nil {
		failErr(c, 400, err)
		return
	}
	// A row a profile binding owns is rewritten on the next sync, so a direct
	// edit here would be silently reverted — the operator watches it succeed and
	// finds out later. Refuse, and say where the change belongs.
	if b, err := s.db.BindingByInbound(id); err == nil && b != nil {
		apierr.Fail(c, &apierr.Error{Op: "inbound-update", Kind: apierr.KindConflict,
			Code: "profile_managed",
			Message: "this inbound is managed by a config profile; editing it here would be " +
				"overwritten by the next profile sync",
			Remediation: "edit the profile to change every node at once, or the binding to change " +
				"this node's port or public host",
			Details: map[string]any{"profile_id": b.ProfileID}})
		return
	}
	// Excluding this inbound's own id, or widening a range on an existing
	// inbound would report it as conflicting with itself.
	if msg := s.portHopConflict(&n, id); msg != "" {
		apierr.Fail(c, apierr.Conflict("inbound-write", "port_hop_conflict", msg))
		return
	}

	// Safe edit: a port, protocol or transport change invalidates every client
	// config already handed out for this inbound. Refuse such a change unless the
	// caller confirms, and report exactly what breaks — never silently orphan
	// users. keep_old clones the current inbound (disabled) as a migration copy
	// so the old config keeps working during the switch-over window.
	old, _ := in.Node()
	if old != nil {
		breaking := inboundBreakingChanges(old, &n)
		if len(breaking) > 0 && !boolParam(c, "confirm") {
			apierr.Fail(c, &apierr.Error{Op: "inbound-update", Kind: apierr.KindConflict,
				Code:    "breaking_edit",
				Message: "this change invalidates existing client configurations",
				Details: map[string]any{"breaking": breaking,
					"hint": "re-send with ?confirm=true to apply. Add ?keep_old=true to keep the current inbound alive (disabled) as a migration copy so existing clients are not cut off immediately."}})
			return
		}
		if len(breaking) > 0 && boolParam(c, "keep_old") {
			// Keep the current config as a DISABLED "pre-edit" snapshot the
			// operator can re-enable if the edit goes wrong. Disabled, so it does
			// not fight the edited inbound for the port.
			if clone, cerr := s.db.CreateInbound(old); cerr == nil {
				clone.Enabled = false
				clone.Remark = old.Remark + " (pre-edit)"
				_ = clone.SetNode(old)
				_ = s.db.SaveInbound(clone)
			}
		}
	}

	in.PrevNodeJSON = in.NodeJSON // capture for one-level undo
	if err := in.SetNode(&n); err != nil {
		failErr(c, 500, err)
		return
	}
	if err := s.db.SaveInbound(in); err != nil {
		failErr(c, 500, err)
		return
	}
	// PrevNodeJSON is captured above for one-level undo, and it is exactly the
	// "before" an audit entry needs. Without a diff the trail says someone
	// edited an inbound and nothing about what — which is not an answer to
	// "who opened this port".
	s.auditWithDiff(c, "inbound.update", strconv.FormatUint(uint64(id), 10),
		[]byte(in.PrevNodeJSON), []byte(in.NodeJSON))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"id": in.ID, "remark": in.Remark, "protocol": in.Protocol, "port": in.Port})
}

// handleInboundConfig returns the ready-to-use CLIENT config for one inbound with
// the public address substituted: a wg-quick .conf for WireGuard, otherwise the
// share URI. This is what the UI hands the user to connect.
// handlePortHop reports the Hysteria2 port-hopping firewall status for one
// inbound: the backend (nftables/iptables/none), whether the panel can manage
// rules, the effective rules, and — when it lacks CAP_NET_ADMIN — the copyable
// manual commands the operator can run themselves.
func (s *Server) handlePortHop(c *gin.Context) {
	if s.engine == nil {
		fail(c, 501, "engine not available")
		return
	}
	id := parseID(c)
	ins, err := s.db.ListInbounds()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	var n *model.Node
	for i := range ins {
		if ins[i].ID == id {
			n, _ = ins[i].Node()
			break
		}
	}
	if n == nil {
		fail(c, 404, "inbound not found")
		return
	}
	spec := ""
	if n.Protocol == model.ProtoHysteria2 && n.Hysteria2 != nil {
		spec = n.Hysteria2.PortHopping
	}
	if s.engine == nil {
		s.engineUnavailable(c)
		return
	}
	c.JSON(200, s.engine.PortHopStatus(n.Port, spec))
}

func (s *Server) handleInboundConfig(c *gin.Context) {
	id := parseID(c)
	ins, err := s.db.ListInbounds()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	var n *model.Node
	for i := range ins {
		if ins[i].ID == id {
			n, _ = ins[i].Node()
			break
		}
	}
	if n == nil {
		fail(c, 404, "inbound not found")
		return
	}
	for i := range ins {
		if ins[i].ID == id && ins[i].NodeID > 0 {
			if node, err := s.db.NodeByID(ins[i].NodeID); err == nil && node.Address != "" {
				n.Address = node.Address
			}
			break
		}
	}
	s.substituteAddr(n, hostOnly(c.Request.Host))
	s.applyExportDefaults(n)
	// For a multi-user SS-2022 inbound the engine requires "serverPSK:userPSK"
	// from every client, including this inbound's OWN credential (the engine
	// materialises a user for it seeded on "inbound-<id>"). Stamp that same
	// combined password here so the config link the panel shows authenticates.
	if n.Protocol == model.ProtoShadowsocks {
		if _, is2022 := model.KeySizeForMethod(n.Method); is2022 {
			seed := "inbound-" + strconv.FormatUint(uint64(id), 10)
			n.Password = model.SS2022Combined(n.Password, model.DeriveSSUserPSK(seed, n.Method), n.Method)
		}
	}
	if n.Protocol == model.ProtoWireGuard {
		conf, err := export.WireGuardConf(n, n.Address)
		if err != nil {
			failErr(c, 400, err)
			return
		}
		c.JSON(200, gin.H{"kind": "wireguard", "filename": safeName(n.Remark, n.Port) + ".conf", "config": conf})
		return
	}
	if n.Protocol == model.ProtoAmneziaWG {
		conf, err := export.AmneziaWGConf(n, n.Address)
		if err != nil {
			failErr(c, 400, err)
			return
		}
		c.JSON(200, gin.H{"kind": "amneziawg", "filename": safeName(n.Remark, n.Port) + ".conf", "config": conf})
		return
	}
	uri, err := export.URI(n)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	c.JSON(200, gin.H{"kind": "uri", "uri": uri})
}

// safeName builds a filename-safe label from a remark + port.
func safeName(remark string, port int) string {
	out := ""
	for _, r := range remark {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out += string(r)
		}
	}
	if out == "" {
		out = "wg"
	}
	return out + "-" + strconv.Itoa(port)
}

func (s *Server) handleDeleteInbound(c *gin.Context) {
	id := parseID(c)
	if err := s.db.DeleteInbound(id); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.delete", strconv.FormatUint(uint64(id), 10))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"deleted": id})
}

// --- groups ---------------------------------------------------------------

func (s *Server) handleListGroups(c *gin.Context) {
	gs, err := s.db.ListGroups()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gs)
}

func (s *Server) handleCreateGroup(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		InboundIDs  []uint `json:"inbound_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		fail(c, 400, "name and inbound_ids required")
		return
	}
	g := &store.Group{Name: req.Name, Description: req.Description,
		InboundIDs: store.IntSlice(req.InboundIDs)}
	if err := s.db.CreateGroup(g); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "group.create", g.Name)
	c.JSON(201, g)
}

// --- users ----------------------------------------------------------------

func (s *Server) handleListUsers(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	owner := uint(0)
	if claims.Role == string(store.RoleReseller) {
		owner = claims.AdminID // resellers see only their own users (spec §4)
	}
	// Pagination is opt-in: with no paging parameters this returns the bare
	// array it always has, so every existing caller is unaffected. A request
	// that asks for a page gets the total with it, because "50 shown" says
	// nothing about how many there are.
	q := parseListQuery(c)
	us, total, err := s.db.ListUsersPage(owner, q)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	if !q.Paged() {
		c.JSON(200, us)
		return
	}
	c.JSON(200, listPage{Items: us, Total: total, Limit: effectiveLimit(q), Offset: q.Offset})
}

// handleQuota reports the current admin's reseller limits and remaining headroom
// (users + traffic). Owners/admins are reported as unlimited.
func (s *Server) handleQuota(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	admin, err := s.db.AdminByID(claims.AdminID)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	unlimited := admin.Role == store.RoleOwner || admin.Role == store.RoleAdmin
	usedUsers, allocated, _ := s.db.ResellerUsage(admin.ID)
	resp := gin.H{
		"role": admin.Role, "unlimited": unlimited,
		"user_quota": admin.UserQuota, "users_used": usedUsers,
		"traffic_credit": admin.TrafficCredit, "traffic_allocated": allocated,
	}
	if !unlimited {
		if admin.UserQuota > 0 {
			resp["users_remaining"] = max64(0, int64(admin.UserQuota)-usedUsers)
		}
		if admin.TrafficCredit > 0 {
			resp["traffic_remaining"] = max64(0, admin.TrafficCredit-allocated)
		}
	}
	c.JSON(200, resp)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) handleCreateUser(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req struct {
		Username string `json:"username"`
		GroupID  uint   `json:"group_id"`
		// DataLimitGB is whole gigabytes, kept for existing callers. It cannot
		// express a sub-gigabyte plan: a 500 MB trial arrives as 0, and 0 means
		// UNLIMITED — the exact opposite of the intent, discovered only when the
		// account has moved a hundred gigabytes.
		DataLimitGB int64 `json:"data_limit_gb"`
		// DataLimit is bytes and takes precedence when present. Bytes rather
		// than a float so there is no rounding to argue about at the boundary.
		DataLimit  *int64 `json:"data_limit"`
		ExpireDays int    `json:"expire_days"`
		// TemplateID names a saved plan (store.UserTemplate) whose limits are
		// stamped onto this account. Every field it supplies is a BASE that an
		// explicitly-sent request field still overrides, so picking a plan never
		// silently discards something the operator typed next to it.
		TemplateID uint `json:"template_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" {
		fail(c, 400, "username required")
		return
	}
	pw, _ := keygen.Password(16)
	u := &store.User{
		Username: req.Username, Status: store.StatusActive, GroupID: req.GroupID,
		OwnerAdminID: claims.AdminID, UUID: keygen.UUID(), Password: pw,
		SubToken: token26(), DataLimit: req.DataLimitGB * 1024 * 1024 * 1024,
	}
	var tpl *store.UserTemplate
	if req.TemplateID != 0 {
		found, err := s.db.UserTemplateByID(req.TemplateID)
		// A reseller may only stamp their own plans: another tenant's plan
		// carries that tenant's group and inbound ids. Answered the same as a
		// plan that does not exist, so ids cannot be probed across tenants.
		if err != nil || (templateScope(claims) != 0 && found.OwnerAdminID != claims.AdminID) {
			apierr.Fail(c, &apierr.Error{Op: "user-create", Kind: apierr.KindNotFound,
				Status: 404, Message: "no such user template", Cause: err})
			return
		}
		tpl = found
		// Composed SERVER-side. The affixes are the plan's naming convention,
		// and a browser that forgot to prepend them would produce an account
		// that looks hand-made and sorts nowhere near its cohort.
		u.Username = tpl.UsernamePrefix + strings.TrimSpace(req.Username) + tpl.UsernameSuffix
		u.DataLimit = tpl.DataLimit
		u.OnHoldDuration = tpl.OnHoldDuration
		u.ResetStrategy = tpl.ResetStrategy
		u.IPLimit = tpl.IPLimit
		if tpl.Status != "" {
			u.Status = tpl.Status
		}
		if req.GroupID == 0 {
			u.GroupID = tpl.GroupID
		}
		if tpl.ExpireDays > 0 {
			exp := time.Now().AddDate(0, 0, tpl.ExpireDays)
			u.ExpireAt = &exp
		}
	}
	if req.DataLimit != nil {
		if *req.DataLimit < 0 {
			fail(c, 400, "data_limit must not be negative")
			return
		}
		// A zero alongside a template is "not specified", not "unlimited".
		//
		// The panel sends data_limit on every create — the GB box starts at 0
		// and an emptied number input coerces to 0 — so this field is never
		// absent from a browser request. Applying it unconditionally meant
		// picking a 5 GB plan and not touching the box produced an UNLIMITED
		// account and charged the reseller's traffic credit nothing, which is
		// the precise opposite of what choosing that plan means. Without a
		// template a zero still means unlimited, exactly as before.
		if tpl == nil || *req.DataLimit != 0 {
			u.DataLimit = *req.DataLimit
		}
	}
	if req.ExpireDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpireDays)
		u.ExpireAt = &t
	}
	// Enforce reseller quotas transactionally: the creating admin's UserQuota and
	// TrafficCredit are checked and the row is written atomically (spec §4). Owners
	// and admins are unlimited and bypass. A quota rejection is a 409, not a 500.
	owner, _ := s.db.AdminByID(claims.AdminID)
	if err := s.db.CreateUserEnforcingQuota(u, owner); err != nil {
		var qe *store.QuotaError
		if errors.As(err, &qe) {
			apierr.Fail(c, &apierr.Error{Op: "user-create", Kind: apierr.KindQuotaExceeded,
				Code: "quota_exceeded", Message: qe.Error(), Cause: err,
				Details: map[string]any{"limit": qe.Limit}})
			return
		}
		failErr(c, 500, err)
		return
	}
	if tpl != nil && len(tpl.InboundIDs) > 0 {
		// Through the scope-checked path, not a direct insert: a plan must not
		// be a way to assign an inbound the caller could not have assigned by
		// hand. The account itself is already created, so a refusal here is
		// reported without unwinding it — the operator fixes the plan and
		// assigns, rather than losing the user and its quota charge.
		if err := s.db.SetUserInbounds(u.ID, tpl.InboundIDs, s.assignableInbounds(claims)); err != nil {
			s.audit(c, "user.create", u.Username)
			if errors.Is(err, store.ErrForbiddenRef) {
				failErr(c, 403, err)
				return
			}
			failErr(c, 400, err)
			return
		}
	}
	s.audit(c, "user.create", u.Username)
	s.startBackground(s.reloadEngines)
	c.JSON(201, gin.H{"id": u.ID, "username": u.Username, "sub_token": u.SubToken,
		"sub_url": s.subURL(c, u.SubToken), "uuid": u.UUID})
}

func (s *Server) handleDeleteUser(c *gin.Context) {
	id := parseID(c)
	// Read the name BEFORE the row goes. The audit trail recorded a bare row id,
	// which is unresolvable the moment the row is gone — the one entry where
	// knowing WHO was deleted is the entire point — and a webhook receiver
	// cannot act on a number either.
	target := strconv.FormatUint(uint64(id), 10)
	if u, err := s.db.UserByID(id); err == nil && u.Username != "" {
		target = u.Username
	}
	if err := s.db.DeleteUserCascade(id); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "user.delete", target)
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"deleted": id})
}

// handleStats returns a small dashboard summary.
//
// Three COUNT(*) queries, not three whole tables decoded so their lengths can be
// taken. The dashboard polls this.
func (s *Server) handleStats(c *gin.Context) {
	ins, us, gs, err := s.db.Counts()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"inbounds": ins, "users": us, "groups": gs})
}

// processStart is when this panel process started, for the uptime the dashboard
// shows.
var processStart = time.Now()

// handleOverview backs the dashboard's top-level health card. The frontend
// OverviewView was calling /api/health (which did not exist → a 404 toast on
// every login); this is the endpoint it needs, returning the exact shape it
// renders: liveness, build version, node online/total counts, and uptime.
func (s *Server) handleOverview(c *gin.Context) {
	online, total := 0, 0
	cutoff := time.Now().Add(-3 * time.Minute)
	if nodes, err := s.db.ListNodes(); err == nil {
		total = len(nodes)
		for _, n := range nodes {
			if n.Enrolled && n.LastSeen != nil && n.LastSeen.After(cutoff) {
				online++
			}
		}
	}
	// The UI has to know it is on a platform: the set of protocols that can be
	// served there is a fraction of the whole, and offering the operator the
	// same choices as on a real server is how they end up creating inbounds
	// that cannot carry anything.
	pa := s.paas()
	c.JSON(200, gin.H{
		"status":         "ok",
		"version":        version.Get().Version,
		"nodes_online":   online,
		"nodes_total":    total,
		"uptime_seconds": int64(time.Since(processStart).Seconds()),
		"paas":           pa.Enabled,
		"paas_platform":  pa.Platform,
		"paas_domain":    pa.Domain,
	})
}

// --- subscription materialisation (spec §4/§9) ----------------------------

// subscriptionNodes materialises a user's subscription: for every inbound bound
// to the user's group, it clones the inbound node and stamps the user's identity
// (UUID/password) onto it, so one user gets one entry per binding.
func (s *Server) subscriptionNodes(token, hostFromCtx string) []*model.Node {
	if s.db == nil {
		return s.mem.Get(token)
	}
	u, err := s.db.UserBySubToken(token)
	if err != nil {
		return nil
	}
	if u.SubRevoked != nil || u.Status == store.StatusDisabled || u.Status == store.StatusExpired {
		return []*model.Node{}
	}
	// Effective access = inbounds assigned to this user directly, plus those
	// inherited from their group. A user with no group is valid and still gets
	// their direct assignments; previously a missing group meant an empty
	// subscription regardless of what was assigned to the user.
	inboundIDs, err := s.db.InboundsForUser(u.ID)
	if err != nil {
		return []*model.Node{}
	}
	tmpl := s.subNameTemplate()
	frontDomain := s.subFrontDomain()
	frontMode := s.subFrontMode()
	expandSNI := s.subExpandSNI()
	frontCleanIP := s.subFrontCleanIP()
	cleanIPs := s.subCleanIPs()
	// One query for every inbound's endpoints rather than one per inbound: this
	// runs on every client refresh, and a panel with 200 inbounds would
	// otherwise issue 200 queries per fetch.
	hostsByInbound, hostErr := s.db.HostsForInbounds(inboundIDs)
	if hostErr != nil {
		hostsByInbound = nil
	}
	date := time.Now().UTC().Format("2006-01-02")
	var out []*model.Node
	for idx, inID := range inboundIDs {
		in, err := s.db.InboundByID(inID)
		if err != nil || !in.Enabled {
			continue
		}
		n, err := in.Node()
		if err != nil {
			continue
		}
		stampIdentity(n, u)
		// A WireGuard user's .conf must carry THEIR key and tunnel address, not
		// the inbound's shared pair — otherwise every user downloads the same
		// config and they take the tunnel from each other in turn.
		s.stampWGIdentity(n, inID, u.ID)
		if in.NodeID > 0 {
			if node, err := s.db.NodeByID(in.NodeID); err == nil && node.Address != "" {
				n.Address = node.Address
			}
		}
		s.substituteAddr(n, hostFromCtx)
		s.applyExportDefaults(n)
		// Fancy wizard: front every node behind the operator's camouflage domain
		// (SNI/Host or CDN) before the name is stamped, so {HOST} in a template
		// reflects the fronting domain the client will actually present.
		model.ApplyFront(n, frontDomain, frontMode)
		// Apply the operator's naming template last, when every field it can
		// interpolate (address, port, protocol, transport) is final. Empty
		// template ⇒ leave the node's own remark untouched (opt-in).
		if tmpl != "" {
			base := in.Remark
			if base == "" {
				base = n.Remark
			}
			if name := model.ExpandNameTemplate(tmpl, model.NameFieldsFromNode(n, base, u.Username, idx+1, date)); name != "" {
				n.Remark = name
			}
		}
		// Fan the inbound out into every camouflage variation it advertises: one
		// config per borrowed REALITY SNI, and (when a clean-IP list is set) one
		// per clean Cloudflare edge IP for CDN-frontable transports.
		// Endpoints first, then the existing camouflage fan-out on each one.
		//
		// This order is the useful one: a CDN endpoint fanned across the clean
		// edge IPs is exactly what an operator wants, whereas fanning first and
		// then applying endpoints would multiply every SNI variation by every
		// endpoint and produce a subscription nobody can read.
		for _, hosted := range applyHosts(n, hostsByInbound[inID]) {
			out = append(out, expandNodeVariations(hosted, cleanIPs, expandSNI, frontCleanIP)...)
		}
	}
	return out
}

// stampIdentity replaces an inbound template's credentials with the user's, so
// each user connects with their own UUID/password over the shared inbound.
func stampIdentity(n *model.Node, u *store.User) {
	switch n.Protocol {
	case model.ProtoVLESS, model.ProtoVMess:
		if u.UUID != "" {
			n.UUID = u.UUID
		}
	case model.ProtoTUIC:
		if u.UUID != "" {
			n.UUID = u.UUID
		}
		if u.Password != "" {
			n.Password = u.Password
		}
	case model.ProtoTrojan, model.ProtoHysteria2, model.ProtoAnyTLS:
		if u.Password != "" {
			n.Password = u.Password
		}
	case model.ProtoShadowsocks:
		// SS-2022 carries a per-user identity header, so each user authenticates
		// with the SERVER PSK (the inbound's own key) joined to a per-user PSK
		// derived from their email. The engine materialises the IDENTICAL user
		// PSK for the same email, so the served inbound and this link agree. A
		// non-2022 method has no per-user identity — it stays the shared key
		// (overwriting it with the user's arbitrary password would hand them a
		// key the single-key server does not hold).
		if _, is2022 := model.KeySizeForMethod(n.Method); is2022 && u.ID != 0 {
			userPSK := model.DeriveSSUserPSK(job.UserEmail(u.ID), n.Method)
			n.Password = model.SS2022Combined(n.Password, userPSK, n.Method)
		}
	case model.ProtoSOCKS, model.ProtoHTTP:
		if u.Username != "" {
			n.Username = u.Username
		}
		if u.Password != "" {
			n.Password = u.Password
		}
	case model.ProtoSSH:
		if n.SSH == nil {
			n.SSH = &model.SSHOptions{}
		}
		if u.Username != "" {
			n.SSH.User = u.Username
		}
		if u.Password != "" {
			n.SSH.Password = u.Password
		}
	}
	if n.Remark == "" {
		n.Remark = u.Username
	}
	n.Normalize()
}

// --- helpers --------------------------------------------------------------

func (s *Server) audit(c *gin.Context, action, target string) {
	if s.db == nil {
		return
	}
	claims, _ := auth.ClaimsFrom(c)
	al := &store.AuditLog{IP: c.ClientIP(), Action: action, Target: target}
	if claims != nil {
		al.AdminID = claims.AdminID
		al.Actor = claims.Username
	}
	s.db.Audit(al)

	// The USER lifecycle rides on the audit trail rather than on the two
	// handlers, because every path that creates or removes a user already
	// audits it — the import, the bulk operations, anything added later — and
	// hanging the event here is what makes "all of them" true instead of "the
	// two I remembered". It goes to webhooks only: a provisioning system wants
	// the POST, and nobody wants a chat message per account created.
	switch action {
	case "user.create":
		s.webhooks.Dispatch(webhook.Event{Type: eventUserCreated, Subject: target,
			Message: "Account " + target + " was created."})
	case "user.delete":
		s.webhooks.Dispatch(webhook.Event{Type: eventUserDeleted, Subject: target,
			Message: "Account " + target + " was deleted."})
	}
}

func parseID(c *gin.Context) uint {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	return uint(id)
}

func (s *Server) subURL(c *gin.Context, token string) string {
	return s.subScheme() + "://" + c.Request.Host + "/sub/" + token
}

// subScheme is the scheme a CLIENT uses to reach this panel, which is always
// https and is not always what this process is listening with.
//
// It used to be read off c.Request.TLS, which is the wrong question. Off-platform
// that happens to give the right answer, because the panel serves its own TLS —
// ACME with a domain, self-signed without one. Behind a platform edge it gives
// exactly the wrong one: the panel deliberately serves plain HTTP there and the
// client's connection was TLS all the way to the edge, so every subscription URL
// came out as "http://app.up.railway.app/sub/…". That is the link an operator
// copies and sends to somebody, and announcing itself as cleartext is both
// something some clients refuse and an invitation to read the token off the wire.
//
// X-Forwarded-Proto is deliberately not consulted. It is client-supplied, and on
// an ordinary install trusting it would let anyone change what the panel says
// about itself — while here it would only confirm what is already known.
func (s *Server) subScheme() string { return "https" }

// token26 returns a 26-hex-char subscription token.
func token26() string {
	t, _ := keygen.Password(13)
	return t
}

var _ = http.StatusOK
