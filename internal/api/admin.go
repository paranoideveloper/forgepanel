package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// handleLogin authenticates an admin and returns an access+refresh token pair.
func (s *Server) handleLogin(c *gin.Context) {
	if s.db == nil {
		c.JSON(501, gin.H{"error": "this server has no user database"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
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
		if s.login != nil { s.login.Fail(ip) }
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	ok, _ := auth.VerifyPassword(req.Password, admin.PasswordHash)
	if !ok {
		if s.login != nil { s.login.Fail(ip) }
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	if admin.TOTPSecret != "" {
		if req.TOTP == "" {
			c.JSON(401, gin.H{"error": "2fa/totp code required", "totp_required": true})
			return
		}
		if !auth.VerifyTOTP(admin.TOTPSecret, req.TOTP, time.Now()) {
			if s.login != nil { s.login.Fail(ip) }
			c.JSON(401, gin.H{"error": "invalid 2fa code", "totp_required": true})
			return
		}
	}
	if s.login != nil { s.login.Success(ip) }
	access, refresh, err := s.signer.Issue(admin.ID, admin.Username, string(admin.Role))
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
	access, refresh, err := s.signer.Issue(claims.AdminID, claims.Username, claims.Role)
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
	go s.reloadEngines()
	c.JSON(201, gin.H{"id": in.ID, "remark": in.Remark, "protocol": in.Protocol, "port": in.Port})
}

// handleInboundConfig returns the ready-to-use CLIENT config for one inbound with
// the public address substituted: a wg-quick .conf for WireGuard, otherwise the
// share URI. This is what the UI hands the user to connect.
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
	go s.reloadEngines()
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
		Name       string `json:"name"`
		InboundIDs []uint `json:"inbound_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.JSON(400, gin.H{"error": "name and inbound_ids required"})
		return
	}
	g := &store.Group{Name: req.Name, InboundIDs: store.IntSlice(req.InboundIDs)}
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
	if err := s.db.CreateUser(u); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user.create", u.Username)
	go s.reloadEngines()
	c.JSON(201, gin.H{"id": u.ID, "username": u.Username, "sub_token": u.SubToken,
		"sub_url": subURL(c, u.SubToken), "uuid": u.UUID})
}

func (s *Server) handleDeleteUser(c *gin.Context) {
	id := parseID(c)
	if err := s.db.DeleteUser(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user.delete", strconv.FormatUint(uint64(id), 10))
	go s.reloadEngines()
	c.JSON(200, gin.H{"deleted": id})
}

// handleStats returns a small dashboard summary.
func (s *Server) handleStats(c *gin.Context) {
	ins, _ := s.db.ListInbounds()
	us, _ := s.db.ListUsers(0)
	gs, _ := s.db.ListGroups()
	c.JSON(200, gin.H{"inbounds": len(ins), "users": len(us), "groups": len(gs)})
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
	g, err := s.db.GroupByID(u.GroupID)
	if err != nil {
		return []*model.Node{}
	}
	var out []*model.Node
	for _, inID := range g.InboundIDs {
		in, err := s.db.InboundByID(inID)
		if err != nil || !in.Enabled {
			continue
		}
		n, err := in.Node()
		if err != nil {
			continue
		}
		stampIdentity(n, u)
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
