package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/version"
)

// handleLogin authenticates an admin and returns an access+refresh token pair.
func (s *Server) handleLogin(c *gin.Context) {
	if s.db == nil {
		c.JSON(501, gin.H{"error": "this server has no user database"})
		return
	}
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		TOTP         string `json:"totp"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	ip := c.ClientIP()
	if s.login != nil && !s.login.Allowed(ip) {
		c.JSON(429, gin.H{"error": "too many attempts; try again later"})
		return
	}
	admin, err := s.db.AdminByUsername(req.Username)
	if err != nil || admin.Disabled {
		if s.login != nil {
			s.login.Fail(ip)
		}
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	ok, _ := auth.VerifyPassword(req.Password, admin.PasswordHash)
	if !ok {
		if s.login != nil {
			s.login.Fail(ip)
		}
		c.JSON(401, gin.H{"error": "invalid credentials"})
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
				if s.login != nil {
					s.login.Fail(ip)
				}
				c.JSON(401, gin.H{"error": "invalid 2fa code", "totp_required": true})
				return
			}
		case req.RecoveryCode != "":
			used, remaining, err := s.db.ConsumeRecoveryCode(admin.ID, func(h string) bool {
				return auth.RecoveryCodeMatches(h, req.RecoveryCode)
			})
			if err != nil || !used {
				if s.login != nil {
					s.login.Fail(ip)
				}
				c.JSON(401, gin.H{"error": "invalid or already-used recovery code", "totp_required": true})
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
			c.JSON(401, gin.H{"error": "2fa/totp code required", "totp_required": true})
			return
		}
	}
	if s.login != nil {
		s.login.Success(ip)
	}
	// Re-read the epoch: a recovery-code login just advanced it, and the new
	// token must carry the new value or it would invalidate itself.
	epoch, _ := s.db.AdminSessionEpoch(admin.ID)
	access, refresh, err := s.signer.IssueAt(admin.ID, admin.Username, string(admin.Role), epoch)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	claims, err := s.signer.Verify(req.RefreshToken)
	if err != nil || claims.Kind != "refresh" {
		c.JSON(401, gin.H{"error": "invalid refresh token"})
		return
	}
	// A revoked session must not be able to mint itself a fresh access token —
	// otherwise the refresh endpoint would quietly undo every invalidation.
	if !s.signer.SessionValid(claims) {
		c.JSON(401, gin.H{"error": "session revoked; sign in again"})
		return
	}
	access, refresh, err := s.signer.IssueAt(claims.AdminID, claims.Username, claims.Role, claims.SessionEpoch)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"access_token": access, "refresh_token": refresh})
}

// handleMe returns the authenticated admin's claims.
func (s *Server) handleMe(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	c.JSON(200, gin.H{"admin_id": claims.AdminID, "username": claims.Username, "role": claims.Role})
}

// --- inbounds -------------------------------------------------------------

func (s *Server) handleListInbounds(c *gin.Context) {
	ins, err := s.db.ListInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	out := make([]gin.H, 0, len(ins))
	for _, in := range ins {
		n, _ := in.Node()
		out = append(out, gin.H{"id": in.ID, "remark": in.Remark, "protocol": in.Protocol, "port": in.Port, "enabled": in.Enabled, "node": n})
	}
	c.JSON(200, out)
}

func (s *Server) handleCreateInbound(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	applyCreateDefaults(&n) // panel fills in keys/dest/flow/creds so it "just works"
	s.applyDomain(&n)       // inherit default domain + cascade to SNI/Host/etc.
	if err := n.Validate(); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	in, err := s.db.CreateInbound(&n)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(404, gin.H{"error": "inbound not found"})
		return
	}
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	applyCreateDefaults(&n)
	s.applyDomain(&n) // inherit default domain + cascade
	if err := n.Validate(); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusConflict, gin.H{
				"error": "this change invalidates existing client configurations",
				"code":  "breaking_edit", "breaking": breaking,
				"hint": "re-send with ?confirm=true to apply. Add ?keep_old=true to keep the current inbound alive (disabled) as a migration copy so existing clients are not cut off immediately.",
			})
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
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.SaveInbound(in); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "inbound.update", strconv.FormatUint(uint64(id), 10))
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
		c.JSON(501, gin.H{"error": "engine not available"})
		return
	}
	id := parseID(c)
	ins, err := s.db.ListInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(404, gin.H{"error": "inbound not found"})
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
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(404, gin.H{"error": "inbound not found"})
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
	if n.Protocol == model.ProtoWireGuard {
		conf, err := export.WireGuardConf(n, n.Address)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"kind": "wireguard", "filename": safeName(n.Remark, n.Port) + ".conf", "config": conf})
		return
	}
	if n.Protocol == model.ProtoAmneziaWG {
		conf, err := export.AmneziaWGConf(n, n.Address)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"kind": "amneziawg", "filename": safeName(n.Remark, n.Port) + ".conf", "config": conf})
		return
	}
	uri, err := export.URI(n)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(400, gin.H{"error": "name and inbound_ids required"})
		return
	}
	g := &store.Group{Name: req.Name, Description: req.Description,
		InboundIDs: store.IntSlice(req.InboundIDs)}
	if err := s.db.CreateGroup(g); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
	us, err := s.db.ListUsers(owner)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, us)
}

// handleQuota reports the current admin's reseller limits and remaining headroom
// (users + traffic). Owners/admins are reported as unlimited.
func (s *Server) handleQuota(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	admin, err := s.db.AdminByID(claims.AdminID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
		Username    string `json:"username"`
		GroupID     uint   `json:"group_id"`
		DataLimitGB int64  `json:"data_limit_gb"`
		ExpireDays  int    `json:"expire_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" {
		c.JSON(400, gin.H{"error": "username required"})
		return
	}
	pw, _ := keygen.Password(16)
	u := &store.User{
		Username: req.Username, Status: store.StatusActive, GroupID: req.GroupID,
		OwnerAdminID: claims.AdminID, UUID: keygen.UUID(), Password: pw,
		SubToken: token26(), DataLimit: req.DataLimitGB * 1024 * 1024 * 1024,
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
			c.JSON(409, gin.H{"error": qe.Error(), "code": "quota_exceeded", "limit": qe.Limit})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user.create", u.Username)
	s.startBackground(s.reloadEngines)
	c.JSON(201, gin.H{"id": u.ID, "username": u.Username, "sub_token": u.SubToken,
		"sub_url": subURL(c, u.SubToken), "uuid": u.UUID})
}

func (s *Server) handleDeleteUser(c *gin.Context) {
	id := parseID(c)
	if err := s.db.DeleteUserCascade(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user.delete", strconv.FormatUint(uint64(id), 10))
	s.startBackground(s.reloadEngines)
	c.JSON(200, gin.H{"deleted": id})
}

// handleStats returns a small dashboard summary.
func (s *Server) handleStats(c *gin.Context) {
	ins, _ := s.db.ListInbounds()
	us, _ := s.db.ListUsers(0)
	gs, _ := s.db.ListGroups()
	c.JSON(200, gin.H{"inbounds": len(ins), "users": len(us), "groups": len(gs)})
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
	c.JSON(200, gin.H{
		"status":         "ok",
		"version":        version.Get().Version,
		"nodes_online":   online,
		"nodes_total":    total,
		"uptime_seconds": int64(time.Since(processStart).Seconds()),
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
	var out []*model.Node
	for _, inID := range inboundIDs {
		in, err := s.db.InboundByID(inID)
		if err != nil || !in.Enabled {
			continue
		}
		n, err := in.Node()
		if err != nil {
			continue
		}
		stampIdentity(n, u)
		if in.NodeID > 0 {
			if node, err := s.db.NodeByID(in.NodeID); err == nil && node.Address != "" {
				n.Address = node.Address
			}
		}
		s.substituteAddr(n, hostFromCtx)
		s.applyExportDefaults(n)
		out = append(out, n)
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
	case model.ProtoTrojan, model.ProtoHysteria2, model.ProtoAnyTLS, model.ProtoShadowsocks:
		if u.Password != "" {
			n.Password = u.Password
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
}

func parseID(c *gin.Context) uint {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	return uint(id)
}

func subURL(c *gin.Context, token string) string {
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host + "/sub/" + token
}

// token26 returns a 26-hex-char subscription token.
func token26() string {
	t, _ := keygen.Password(13)
	return t
}

var _ = http.StatusOK
