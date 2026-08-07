package api

// ForgeEdge wiring (§6). This is the Go side of the contract in
// deploy/cloudflare/forgeedge/docs/GO_WIRING.md: the panel builds one canonical
// feed from its own database and either pushes it to every registered edge or
// serves it for the Worker's cron to pull. The result is that a subscriber's
// single URL resolves to the union of their VPS inbounds and the edge entries.
//
// The one invariant that matters here: every node in the feed has been through
// redactNodesForClient(). The edge does NOT re-redact — a REALITY or WireGuard
// server private key that reaches KV is a key you have published.

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// EdgeFeedVersion is bumped when the document shape changes. It must stay in
// step with FEED_VERSION in deploy/cloudflare/forgeedge/src/edge/feed.ts.
const EdgeFeedVersion = 1

// edgeFeedPullTokenKey is the settings key holding the bearer the Worker's cron
// presents to GET /api/edge/feed.
const edgeFeedPullTokenKey = "edge_feed_pull_token"

// edgePushDebounce coalesces a burst of changes into one push. A bulk import
// touches every user in turn; without this it would fire one PUT per user at
// every registered edge.
const edgePushDebounce = 5 * time.Second

// EdgeFeedPanel identifies the panel that produced a feed.
type EdgeFeedPanel struct {
	Name    string `json:"name,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
}

// EdgeFeedUser is one subscriber as the edge sees them.
type EdgeFeedUser struct {
	ID          string `json:"id"`
	SubToken    string `json:"sub_token"`
	Email       string `json:"email,omitempty"`
	Enabled     bool   `json:"enabled"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	UsedTraffic int64  `json:"used_traffic"`
	DataLimit   int64  `json:"data_limit"`
	// VLESSUUID / TrojanPassword are what make the edge multi-tenant: they are
	// the identity the edge stamps onto the entries it mints itself. Omit them
	// and every subscriber shares one edge identity.
	VLESSUUID      string        `json:"vless_uuid,omitempty"`
	TrojanPassword string        `json:"trojan_password,omitempty"`
	Nodes          []*model.Node `json:"nodes"`
}

// EdgeFeedDoc is the canonical feed (GO_WIRING.md §2.1).
type EdgeFeedDoc struct {
	Version     int            `json:"version"`
	GeneratedAt string         `json:"generated_at"`
	Panel       *EdgeFeedPanel `json:"panel,omitempty"`
	Users       []EdgeFeedUser `json:"users"`
	SharedNodes []*model.Node  `json:"shared_nodes,omitempty"`
}

// EdgeFeed builds the canonical feed from the panel database.
//
// Per-user nodes come from the same subscriptionNodes() that serves /sub/:token,
// so the edge and the VPS never disagree about what a user is entitled to, and
// every node — per-user and shared alike — is passed through
// redactNodesForClient() before it leaves this function.
func (s *Server) EdgeFeed() (*EdgeFeedDoc, error) {
	if s.db == nil {
		return nil, fmt.Errorf("edge feed: this panel has no database attached")
	}
	users, err := s.db.ListUsers(0)
	if err != nil {
		return nil, fmt.Errorf("edge feed: could not list users: %w", err)
	}
	host := hostOnly(s.panelHost())
	doc := &EdgeFeedDoc{
		Version:     EdgeFeedVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Panel:       &EdgeFeedPanel{Name: "ForgePanel", BaseURL: s.panelBaseURL()},
		Users:       make([]EdgeFeedUser, 0, len(users)),
	}
	for i := range users {
		u := &users[i]
		if u.SubToken == "" {
			// A user with no subscription token has no URL to resolve; sending
			// them would just be a row the edge drops with a warning.
			continue
		}
		fu := EdgeFeedUser{
			ID:             strconv.FormatUint(uint64(u.ID), 10),
			SubToken:       u.SubToken,
			Email:          u.Username,
			Enabled:        edgeUserEnabled(u),
			UsedTraffic:    u.UsedTraffic,
			DataLimit:      u.DataLimit,
			VLESSUUID:      u.UUID,
			TrojanPassword: u.Password,
			Nodes:          redactNodesForClient(s.subscriptionNodes(u.SubToken, host)),
		}
		if u.ExpireAt != nil {
			fu.ExpiresAt = u.ExpireAt.UTC().Format(time.RFC3339)
		}
		doc.Users = append(doc.Users, fu)
	}
	doc.SharedNodes = redactNodesForClient(s.edgeSharedNodes())
	return doc, nil
}

// edgeUserEnabled mirrors what subscriptionNodes() will actually return: a
// revoked, disabled or expired account gets an empty list, so reporting it as
// enabled would tell the edge to serve a subscription that resolves to nothing.
// A "limited" (over-quota) account stays enabled, exactly as it does on the VPS.
func edgeUserEnabled(u *store.User) bool {
	return u.SubRevoked == nil &&
		u.Status != store.StatusDisabled &&
		u.Status != store.StatusExpired
}

// edgeSharedNodes are the nodes every subscriber receives in addition to their
// own — in practice the panel's ForgeDNS tunnels, which are not bound to an
// inbound and so never appear in subscriptionNodes().
func (s *Server) edgeSharedNodes() []*model.Node {
	zones, err := s.db.ListZones()
	if err != nil {
		return nil
	}
	var out []*model.Node
	for i := range zones {
		z := &zones[i]
		if !z.Enabled {
			continue
		}
		addr := z.NSHost
		if addr == "" {
			addr = z.Zone
		}
		if addr == "" {
			continue
		}
		port := z.BindPort
		if port == 0 {
			port = 53
		}
		out = append(out, &model.Node{
			Protocol: model.ProtoForgeDNS,
			Address:  addr,
			Port:     port,
			Remark:   "ForgeDNS " + z.Zone,
			Tag:      "ForgeDNS " + z.Zone,
			ForgeDNS: &model.ForgeDNSOptions{
				Adapter: z.Adapter,
				Zone:    z.Zone,
				NSHost:  z.NSHost,
				// Key is the client-facing tunnel key, the same one the client
				// bundle carries. The server-side EncryptKey is never included.
				Key:    z.Key,
				RRType: "TXT",
			},
		})
	}
	return out
}

// panelBaseURL is the panel's public origin without the randomised admin path —
// the edge shows it to operators, it is not somewhere it posts.
func (s *Server) panelBaseURL() string {
	// A panel constructed without persisted settings (the light constructor, and
	// most unit tests) has no public address to advertise. Reporting "" is
	// correct there: it is omitted from the feed rather than invented.
	if s.cfg == nil || s.cfg.Panel() == nil {
		return ""
	}
	full := s.PublicURL()
	if p := s.cfg.Panel(); p.AdminPath != "" && p.AdminPath != "/" {
		full = strings.TrimSuffix(full, p.AdminPath)
	}
	return strings.TrimSuffix(full, "/")
}

// panelHost is the host exported links should dial, used as the fallback when
// an inbound listens on 0.0.0.0.
func (s *Server) panelHost() string {
	base := s.panelBaseURL()
	base = strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(base, '/'); i >= 0 {
		base = base[:i]
	}
	return base
}

// --- push -------------------------------------------------------------------

// EdgePushResult is one edge's outcome from a push.
type EdgePushResult struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	OK          bool     `json:"ok"`
	Users       int      `json:"users,omitempty"`
	SharedNodes int      `json:"shared_nodes,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// edgePushState carries the debounce timer. It lives on the Server rather than
// in a package global so two panels in one test binary do not share it.
type edgePushState struct {
	mu    sync.Mutex
	timer *time.Timer
}

// EdgePushSoon schedules a debounced push of the canonical feed. Call it after
// anything that changes what a subscriber should receive — user created,
// edited, enabled, disabled or deleted; inbound created, edited or deleted;
// traffic or quota reset (GO_WIRING.md §2.4).
//
// It returns immediately and is safe to call in a tight loop: fifty calls in a
// bulk import collapse into one push.
func (s *Server) EdgePushSoon() {
	if s.db == nil || s.isClosed() {
		return
	}
	s.edgePush.mu.Lock()
	defer s.edgePush.mu.Unlock()
	if s.edgePush.timer != nil {
		s.edgePush.timer.Reset(edgePushDebounce)
		return
	}
	s.edgePush.timer = time.AfterFunc(edgePushDebounce, func() {
		s.edgePush.mu.Lock()
		s.edgePush.timer = nil
		s.edgePush.mu.Unlock()
		if s.isClosed() {
			return
		}
		_, _ = s.pushFeedToAll()
	})
}

// pushFeedToAll builds the feed once and POSTs it to every registered edge.
func (s *Server) pushFeedToAll() ([]EdgePushResult, error) {
	doc, err := s.EdgeFeed()
	if err != nil {
		return nil, err
	}
	deps, err := s.db.ListEdgeDeployments()
	if err != nil {
		return nil, err
	}
	out := make([]EdgePushResult, 0, len(deps))
	for i := range deps {
		out = append(out, s.pushFeedTo(&deps[i], doc))
	}
	return out, nil
}

// pushFeedTo POSTs one document to one edge and records the outcome.
func (s *Server) pushFeedTo(d *store.EdgeDeployment, doc *EdgeFeedDoc) EdgePushResult {
	res := EdgePushResult{ID: d.ID, Name: d.Name}
	if d.PushToken == "" {
		res.Error = "no push token is stored for this edge"
		res.Remediation = "open the Worker's panel, copy feedPushToken from its status page, and re-register the deployment with it."
		_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), res.Error)
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pr, err := edge.PushFeed(ctx, nil, d.FeedURL(), d.PushToken, doc)
	if err != nil {
		res.Error = err.Error()
		if e, ok := edge.AsError(err); ok {
			res.Error = e.Message
			res.Remediation = e.Remediation
		}
		_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), res.Error)
		return res
	}
	res.OK = true
	res.Users, res.SharedNodes, res.Warnings = pr.Users, pr.SharedNodes, pr.Warnings
	status := fmt.Sprintf("ok: %d user(s)", pr.Users)
	if len(pr.Warnings) > 0 {
		// Surfaced, never swallowed: a warning means the edge dropped users or
		// nodes it could not parse, and those subscribers get a short list
		// without knowing it.
		status += "; warnings: " + strings.Join(pr.Warnings, "; ")
	}
	_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), status)
	return res
}

// --- HTTP handlers ----------------------------------------------------------

// handleEdgeFeed serves the canonical feed for the PULL direction: the Worker's
// cron fetches it when feedPullURL is set. It is deliberately outside the admin
// group (a Worker has no admin session) and is authorised by a bearer token that
// must be minted first — an unauthenticated feed would hand every subscriber's
// credentials to anyone who guessed the URL.
func (s *Server) handleEdgeFeed(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	want := s.db.GetSetting(edgeFeedPullTokenKey)
	if want == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "the pull feed is not enabled on this panel",
			"remediation": "mint a token with GET /api/admin/edge/feed-token, then set feedPullURL and feedPullToken in the Worker's config.",
		})
		return
	}
	got := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if !constantTimeEqualString(got, want) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid feed pull token"})
		return
	}
	doc, err := s.EdgeFeed()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// The raw document, not an envelope: the Worker feeds the response straight
	// into sanitizeFeed().
	c.JSON(http.StatusOK, doc)
}

// handleEdgeFeedToken returns (minting on first use) the bearer the Worker
// presents to the pull endpoint.
func (s *Server) handleEdgeFeedToken(c *gin.Context) {
	rotate := c.Query("rotate") == "1" || c.Query("rotate") == "true"
	tok := s.db.GetSetting(edgeFeedPullTokenKey)
	if tok == "" || rotate {
		tok = randHex(24)
		if err := s.db.SetSetting(edgeFeedPullTokenKey, tok); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		s.audit(c, "edge.feed-token.rotate", "edge")
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "url": s.panelBaseURL() + "/api/edge/feed"})
}

// handleEdgePreviewFeed returns the document the panel would push, so an
// operator can see exactly what leaves the box before it does.
func (s *Server) handleEdgePreviewFeed(c *gin.Context) {
	doc, err := s.EdgeFeed()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, doc)
}

// handleListEdgeDeployments lists the registered edges with their last push
// status.
func (s *Server) handleListEdgeDeployments(c *gin.Context) {
	deps, err := s.db.ListEdgeDeployments()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]gin.H, 0, len(deps))
	for i := range deps {
		d := &deps[i]
		out = append(out, gin.H{
			"id": d.ID, "name": d.Name, "target": d.Target, "origin": d.Origin,
			"secure_path": d.SecurePath, "account_id": d.AccountID,
			"created_at": d.CreatedAt, "last_push_at": d.LastPushAt, "last_status": d.LastStatus,
			// The token itself is never returned; whether one is held is what the
			// UI needs to show "ready to push" versus "finish registering".
			"has_push_token": d.PushToken != "",
			"feed_url":       d.FeedURL(), "status_url": d.StatusURL(),
		})
	}
	c.JSON(http.StatusOK, out)
}

// handleRegisterEdgeDeployment records an edge the panel should feed.
func (s *Server) handleRegisterEdgeDeployment(c *gin.Context) {
	var req struct {
		Name       string `json:"name"`
		Target     string `json:"target"`
		Origin     string `json:"origin"`
		SecurePath string `json:"secure_path"`
		PushToken  string `json:"push_token"`
		AccountID  string `json:"account_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not parse the request body: " + err.Error(),
			"remediation": `send {"name":"forgeedge-a1b2c3","origin":"https://forgeedge-a1b2c3.acme.workers.dev","secure_path":"<24 chars>","push_token":"<from the Worker's status page>"}`})
		return
	}
	d := &store.EdgeDeployment{
		Name: req.Name, Target: req.Target, Origin: req.Origin,
		SecurePath: req.SecurePath, PushToken: req.PushToken, AccountID: req.AccountID,
	}
	if err := s.db.CreateEdgeDeployment(d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "edge.deployment.register", d.Name)
	c.JSON(http.StatusCreated, gin.H{"id": d.ID, "name": d.Name, "origin": d.Origin,
		"secure_path": d.SecurePath, "feed_url": d.FeedURL()})
}

// handleDeleteEdgeDeployment forgets an edge. It does NOT delete the Worker;
// that is DELETE /edge/deploy/:name, and conflating the two would let a stray
// click kill every subscription the edge serves.
func (s *Server) handleDeleteEdgeDeployment(c *gin.Context) {
	if err := s.db.DeleteEdgeDeployment(parseID(c)); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such edge deployment"})
		return
	}
	s.audit(c, "edge.deployment.delete", c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"deleted": true,
		"note": "the Worker is untouched and still serving; use DELETE /api/admin/edge/deploy/<name> to destroy it."})
}

// handleEdgePush pushes the canonical feed to every registered edge, or to one
// when :id is present.
func (s *Server) handleEdgePush(c *gin.Context) {
	doc, err := s.EdgeFeed()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var results []EdgePushResult
	if idStr := c.Param("id"); idStr != "" {
		d, err := s.db.EdgeDeploymentByID(parseID(c))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no such edge deployment"})
			return
		}
		results = []EdgePushResult{s.pushFeedTo(d, doc)}
	} else {
		deps, err := s.db.ListEdgeDeployments()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for i := range deps {
			results = append(results, s.pushFeedTo(&deps[i], doc))
		}
	}
	s.audit(c, "edge.push", strconv.Itoa(len(results)))
	failed := 0
	for _, r := range results {
		if !r.OK {
			failed++
		}
	}
	status := http.StatusOK
	if failed > 0 && failed == len(results) && len(results) > 0 {
		status = http.StatusBadGateway
	}
	c.JSON(status, gin.H{"users": len(doc.Users), "pushed": len(results) - failed,
		"failed": failed, "results": results})
}

// handleEdgeStatus proxies GET <origin>/<path>/api/status.
//
// That endpoint is session-authenticated on the Worker — the secure path gets
// you to the door, the password opens it — so a password must be supplied.
// Without one the Worker's own 401 is returned verbatim rather than dressed up.
func (s *Server) handleEdgeStatus(c *gin.Context) {
	d, err := s.db.EdgeDeploymentByID(parseID(c))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such edge deployment"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	wc := edge.NewWorkerClient(d.Origin, d.SecurePath)
	st, err := wc.Status(ctx, c.Query("password"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.JSON(http.StatusOK, st)
}

// handleEdgeDeploy starts a deploy from the panel.
//
// A live Cloudflare deploy needs a credential. The panel holds none by design —
// the OAuth flow needs a browser, and a token written into the panel is a
// long-lived secret sitting on the box. So an api_token must be supplied for
// this call, and when it is absent the request fails with exactly that, never
// with a fabricated success.
func (s *Server) handleEdgeDeploy(c *gin.Context) {
	var req struct {
		Name       string `json:"name"`
		Target     string `json:"target"`
		APIToken   string `json:"api_token"`
		AccountID  string `json:"account_id"`
		SecurePath string `json:"secure_path"`
		Bundle     string `json:"bundle"`
		Force      bool   `json:"force"`
		// APIBase redirects the Cloudflare API root, for an operator behind an
		// egress proxy (and for the tests that exercise this handler).
		APIBase string `json:"api_base"`
	}
	_ = c.ShouldBindJSON(&req)
	if strings.TrimSpace(req.APIToken) == "" {
		edgeFail(c, edge.ErrNoCredentials("edge-deploy"))
		return
	}
	if strings.TrimSpace(req.Bundle) == "" {
		edgeFail(c, &edge.Error{Op: "edge-deploy", Kind: edge.KindValidation,
			Message: "no Worker bundle was supplied",
			Remediation: "the panel binary does not carry the ForgeEdge bundle. Build it with " +
				"`cd deploy/cloudflare/forgeedge && bun run build` and deploy with `forgectl edge deploy`, " +
				"or POST the built worker.js as the `bundle` field."})
		return
	}
	if req.Name == "" {
		n, err := edge.RandomName()
		if err != nil {
			edgeFail(c, err)
			return
		}
		req.Name = n
	}
	if req.SecurePath == "" {
		p, err := edge.GenerateSecurePath(edge.SecurePathLength)
		if err != nil {
			edgeFail(c, err)
			return
		}
		req.SecurePath = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cl := edge.NewClient(req.APIToken, req.AccountID)
	if req.APIBase != "" {
		cl.BaseURL = req.APIBase
	}
	out, err := edge.Deploy(ctx, cl, edge.DeploySpec{
		Name: req.Name, Target: req.Target, SecurePath: req.SecurePath,
		Bundle: []byte(req.Bundle), Force: req.Force,
	})
	if err != nil {
		edgeFail(c, err)
		return
	}
	d := &store.EdgeDeployment{Name: out.Name, Target: out.Target, Origin: out.Origin,
		SecurePath: out.SecurePath, AccountID: cl.AccountID}
	if err := s.db.CreateEdgeDeployment(d); err != nil {
		// The Worker is live even though the row failed; say so rather than
		// reporting a failure that would send the operator hunting for nothing.
		c.JSON(http.StatusOK, gin.H{"deployment": out, "registered": false, "register_error": err.Error()})
		return
	}
	s.audit(c, "edge.deploy", out.Name)
	c.JSON(http.StatusOK, gin.H{"deployment": out, "registered": true, "id": d.ID})
}

// handleEdgeDeleteWorker destroys the Worker at Cloudflare. Every subscription
// URL it serves dies immediately.
func (s *Server) handleEdgeDeleteWorker(c *gin.Context) {
	name := c.Param("name")
	token := c.Query("api_token")
	if token == "" {
		edgeFail(c, edge.ErrNoCredentials("edge-delete"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl := edge.NewClient(token, c.Query("account_id"))
	if base := c.Query("api_base"); base != "" {
		cl.BaseURL = base
	}
	keepKV := c.Query("keep_kv") == "1" || c.Query("keep_kv") == "true"
	if err := edge.Destroy(ctx, cl, name, c.DefaultQuery("target", "workers"), keepKV); err != nil {
		edgeFail(c, err)
		return
	}
	if d, err := s.db.EdgeDeploymentByName(name); err == nil {
		_ = s.db.DeleteEdgeDeployment(d.ID)
	}
	s.audit(c, "edge.delete", name)
	c.JSON(http.StatusOK, gin.H{"deleted": name})
}

// handleEdgeUpdateCheck reports whether a newer ForgeEdge release exists. It is
// read-only by design: ForgeEdge never fetches and self-executes remote code.
func (s *Server) handleEdgeUpdateCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	info, err := edge.CheckForUpdate(ctx, nil, c.Query("repo"), c.DefaultQuery("current", "0.0.0"))
	if err != nil {
		edgeFail(c, err)
		return
	}
	c.JSON(http.StatusOK, info)
}

// registerEdgeRoutes mounts the admin-side edge API under the caller's group
// (which is /api/admin, matching how the §5 DNS wizard is mounted).
func (s *Server) registerEdgeRoutes(rg gin.IRouter) {
	g := rg.Group("/edge")
	g.GET("/deployments", s.handleListEdgeDeployments)
	g.POST("/deployments", s.handleRegisterEdgeDeployment)
	g.DELETE("/deployments/:id", s.handleDeleteEdgeDeployment)
	g.POST("/deployments/:id/push", s.handleEdgePush)
	g.GET("/deployments/:id/status", s.handleEdgeStatus)
	g.POST("/push", s.handleEdgePush)
	g.GET("/feed", s.handleEdgePreviewFeed)
	g.GET("/feed-token", s.handleEdgeFeedToken)
	g.POST("/deploy", s.handleEdgeDeploy)
	g.DELETE("/deploy/:name", s.handleEdgeDeleteWorker)
	g.GET("/update-check", s.handleEdgeUpdateCheck)
}

// constantTimeEqualString compares two bearer tokens without leaking their
// length relationship through timing. The length check is unavoidable and is
// itself constant-time-safe: it reveals only that the lengths differ.
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// edgeFail writes a typed edge error with the HTTP status its kind implies.
func edgeFail(c *gin.Context, err error) {
	e, ok := edge.AsError(err)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	status := http.StatusInternalServerError
	switch e.Kind {
	case edge.KindValidation:
		status = http.StatusBadRequest
	case edge.KindAuth:
		status = http.StatusUnauthorized
	case edge.KindPermission:
		status = http.StatusForbidden
	case edge.KindNotFound:
		status = http.StatusNotFound
	case edge.KindConflict:
		status = http.StatusConflict
	case edge.KindRateLimit:
		status = http.StatusTooManyRequests
	case edge.KindNetwork:
		status = http.StatusBadGateway
	case edge.KindNoCredentials:
		status = http.StatusPreconditionRequired
	}
	c.JSON(status, gin.H{"error": e.Message, "kind": string(e.Kind), "op": e.Op,
		"remediation": e.Remediation, "missing_scope": e.MissingScope})
}
