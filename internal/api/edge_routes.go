package api

// The ForgeEdge HTTP surface (§6): the panel's admin routes for registered
// edges, and the token-authenticated PULL feed the Worker's cron fetches.
// The document these serve is built in edge.go.

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/store"
)

// --- HTTP handlers ----------------------------------------------------------

// handleEdgeFeed serves the canonical feed for the PULL direction: the Worker's
// cron fetches it when feedPullURL is set. It is deliberately outside the admin
// group (a Worker has no admin session) and is authorised by a bearer token that
// must be minted first — an unauthenticated feed would hand every subscriber's
// credentials to anyone who guessed the URL.
func (s *Server) handleEdgeFeed(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	want := s.knobs().String(edgeFeedPullTokenKey)
	if want == "" {
		apierr.Fail(c, &apierr.Error{Op: "edge-feed-pull", Kind: apierr.KindNotFound,
			Message:     "the pull feed is not enabled on this panel",
			Remediation: "mint a token with GET /api/admin/edge/feed-token, then set feedPullURL and feedPullToken in the Worker's config."})
		return
	}
	got := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if !constantTimeEqualString(got, want) {
		fail(c, http.StatusUnauthorized, "invalid feed pull token")
		return
	}
	doc, err := s.EdgeFeed()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
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
	tok := s.knobs().String(edgeFeedPullTokenKey)
	if tok == "" || rotate {
		tok = randHex(24)
		if err := s.knobs().Set(edgeFeedPullTokenKey, tok); err != nil {
			failErr(c, http.StatusInternalServerError, err)
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
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, doc)
}

// handleListEdgeDeployments lists the registered edges with their last push
// status.
func (s *Server) handleListEdgeDeployments(c *gin.Context) {
	deps, err := s.db.ListEdgeDeployments()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
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
		apierr.Fail(c, &apierr.Error{Op: "edge-register", Kind: apierr.KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Cause:       err,
			Remediation: `send {"name":"forgeedge-a1b2c3","origin":"https://forgeedge-a1b2c3.acme.workers.dev","secure_path":"<24 chars>","push_token":"<from the Worker's status page>"}`})
		return
	}
	d := &store.EdgeDeployment{
		Name: req.Name, Target: req.Target, Origin: req.Origin,
		SecurePath: req.SecurePath, PushToken: req.PushToken, AccountID: req.AccountID,
	}
	if err := s.db.CreateEdgeDeployment(d); err != nil {
		failErr(c, http.StatusBadRequest, err)
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
		fail(c, http.StatusNotFound, "no such edge deployment")
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
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	var results []EdgePushResult
	if idStr := c.Param("id"); idStr != "" {
		d, err := s.db.EdgeDeploymentByID(parseID(c))
		if err != nil {
			fail(c, http.StatusNotFound, "no such edge deployment")
			return
		}
		results = []EdgePushResult{s.pushFeedTo(d, doc)}
	} else {
		deps, err := s.db.ListEdgeDeployments()
		if err != nil {
			failErr(c, http.StatusInternalServerError, err)
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
		fail(c, http.StatusNotFound, "no such edge deployment")
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

// handleEdgeWarpRegister registers WARP accounts on a deployed Worker (via its
// push token, no admin password) and immediately pushes the feed so the Worker's
// subscription starts serving the WireGuard + AmneziaWG nodes. This is the
// one-click "free WARP + Amnezia" the panel offers per deployment.
func (s *Server) handleEdgeWarpRegister(c *gin.Context) {
	d, err := s.db.EdgeDeploymentByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such edge deployment")
		return
	}
	if d.PushToken == "" {
		apierr.Fail(c, apierr.Validation("edge-warp",
			"no push token is stored for this edge, so the panel cannot drive it",
			"re-deploy from the panel (new deploys store the token), or open the Worker's own panel and register WARP there."))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	// Register on THIS host: a Worker cannot reach Cloudflare's WARP API (CF→CF),
	// but the panel VPS can. Then push the accounts into the Worker's KV.
	registered, err := edge.RegisterWarpAccounts(ctx, nil)
	if err != nil {
		edgeFail(c, err)
		return
	}
	wc := edge.NewWorkerClient(d.Origin, d.SecurePath)
	wc.Bearer = d.PushToken
	accounts, err := wc.StoreWarp(ctx, registered)
	if err != nil {
		edgeFail(c, err)
		return
	}
	// Push the feed so the subscription reflects the new WARP nodes right away.
	var push EdgePushResult
	if doc, derr := s.EdgeFeed(); derr == nil {
		push = s.pushFeedTo(d, doc)
	}
	s.audit(c, "edge.warp.register", d.Name)
	c.JSON(http.StatusOK, gin.H{"accounts": accounts, "count": len(accounts), "pushed": push.OK})
}

// handleEdgeWarpConf streams the WARP wg-quick .conf for import into the Amnezia
// app or any WireGuard client. ?pro=1 returns the AmneziaWG (junk-packet
// obfuscated) variant; otherwise the plain WireGuard tunnel.
func (s *Server) handleEdgeWarpConf(c *gin.Context) {
	d, err := s.db.EdgeDeploymentByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such edge deployment")
		return
	}
	if d.PushToken == "" {
		fail(c, http.StatusBadRequest, "no push token is stored for this edge, so the panel cannot fetch its .conf")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wc := edge.NewWorkerClient(d.Origin, d.SecurePath)
	wc.Bearer = d.PushToken
	plain, pro, err := wc.WarpConf(ctx)
	if err != nil {
		edgeFail(c, err)
		return
	}
	conf, name := plain, "warp.conf"
	if c.Query("pro") == "1" || c.Query("pro") == "true" {
		conf, name = pro, "warp-amnezia.conf"
	}
	c.Header("Content-Disposition", "attachment; filename=\""+name+"\"")
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(conf))
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
		// SkipVerify returns as soon as Cloudflare accepts the upload, without
		// checking the Worker actually serves. Off by default: "the API accepted
		// it" and "it serves" are not the same thing, and the gap between them is
		// what hands an operator a panel link that is dead on arrival. Only for a
		// panel host with no route to the edge.
		SkipVerify bool `json:"skip_verify"`
		// ProxyIP is the relay a Worker dials when the destination is itself on
		// Cloudflare. A Worker's connect() to a Cloudflare IP is refused (the
		// CF->CF block), so without this every Cloudflare-hosted destination is
		// simply unreachable through the edge.
		//
		// The deploy form has always had this input and always sent it, but the
		// handler bound no such field, so the value was parsed and dropped: the
		// operator set a proxy IP, saw "deployed", and got an edge that still
		// could not reach Cloudflare-hosted sites. It is applied to the freshly
		// deployed Worker's config below.
		ProxyIP string `json:"proxy_ip"`
		// SelfManage binds this account's Cloudflare credential into the Worker
		// so its own Deployment panel can report the script name and hostnames
		// it is serving on. Opt-in, and the form says what it costs: a token in
		// a binding is readable by anyone who can deploy to this account.
		SelfManage bool `json:"self_manage"`
	}
	_ = c.ShouldBindJSON(&req)
	if strings.TrimSpace(req.APIToken) == "" {
		edgeFail(c, edge.ErrNoCredentials("edge-deploy"))
		return
	}
	if strings.TrimSpace(req.Bundle) == "" {
		// Default to the bundle compiled into the panel binary, so a one-click
		// deploy from the UI (or `forgectl edge deploy`) needs no external build.
		if edge.HasBundle() {
			req.Bundle = string(edge.Bundle())
		} else {
			edgeFail(c, &edge.Error{Op: "edge-deploy", Kind: edge.KindValidation,
				Message: "no Worker bundle was supplied and none is compiled in",
				Remediation: "rebuild the panel with the embedded bundle (`make edge-bundle` then rebuild), " +
					"or POST the built worker.js as the `bundle` field."})
			return
		}
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
		Bundle: []byte(req.Bundle), Force: req.Force, SkipVerify: req.SkipVerify,
		SelfManage: req.SelfManage,
	})
	if err == nil && strings.TrimSpace(req.ProxyIP) != "" {
		// Best effort, and reported rather than fatal: the Worker IS deployed at
		// this point, so failing the whole request would send the operator
		// hunting for something that is actually running. The warning tells them
		// the one thing that did not take.
		if aerr := applyEdgeProxyIP(ctx, out, req.ProxyIP); aerr != nil {
			out.Warnings = append(out.Warnings,
				"deployed, but the proxy IP could not be applied: "+aerr.Error()+
					" — set it from the Worker's own panel.")
		}
	}
	if err != nil {
		edgeFail(c, err)
		return
	}
	d := &store.EdgeDeployment{Name: out.Name, Target: out.Target, Origin: out.Origin,
		SecurePath: out.SecurePath, PushToken: out.FeedPushToken, AccountID: cl.AccountID,
		SelfManage: out.SelfManage}
	// A force redeploy over a Worker the panel already knows would collide with
	// the unique name index, and the handler used to answer registered:false and
	// leave the old row untouched. That row is what `forgectl edge update` reads
	// its bindings back from, so a stale one is the whole bug returning: tick
	// self-manage on a redeploy, get a working Deployment panel, and the next
	// update silently strips the credential. Update in place, as the CLI does.
	if existing, lerr := s.db.EdgeDeploymentByName(out.Name); lerr == nil {
		existing.Origin, existing.SecurePath, existing.AccountID = out.Origin, out.SecurePath, cl.AccountID
		existing.SelfManage = out.SelfManage
		if out.FeedPushToken != "" {
			existing.PushToken = out.FeedPushToken
		}
		if serr := s.db.SaveEdgeDeployment(existing); serr != nil {
			c.JSON(http.StatusOK, gin.H{"deployment": out, "registered": false, "register_error": serr.Error()})
			return
		}
		s.audit(c, "edge.deploy", out.Name)
		c.JSON(http.StatusOK, gin.H{"deployment": out, "registered": true, "id": existing.ID})
		return
	}
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
	g.POST("/deployments/:id/warp", s.handleEdgeWarpRegister)
	g.GET("/deployments/:id/warp.conf", s.handleEdgeWarpConf)
	g.GET("/deployments/:id/status", s.handleEdgeStatus)
	g.GET("/deployments/:id/config", s.handleEdgeGetConfig)
	g.PUT("/deployments/:id/config", s.handleEdgeUpdateConfig)
	g.POST("/push", s.handleEdgePush)
	g.GET("/feed", s.handleEdgePreviewFeed)
	g.GET("/feed-token", s.handleEdgeFeedToken)
	g.POST("/deploy", s.handleEdgeDeploy)
	g.DELETE("/deploy/:name", s.handleEdgeDeleteWorker)
	g.GET("/update-check", s.handleEdgeUpdateCheck)
	g.GET("/token-url", s.handleEdgeTokenURL)
	g.GET("/bundle", s.handleEdgeBundleInfo)
}

// handleEdgeTokenURL returns a Cloudflare token-creation URL pre-filled with the
// exact scopes a ForgeEdge deploy needs, so the UI's "Connect Cloudflare" step
// is one click instead of a scope-hunting exercise.
func (s *Server) handleEdgeTokenURL(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"url": edge.TokenURL()})
}

// handleEdgeBundleInfo reports whether the panel binary carries the ForgeEdge
// worker bundle, so the UI can offer one-click deploy (or tell the operator to
// supply a bundle when it does not).
func (s *Server) handleEdgeBundleInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"embedded": edge.HasBundle(), "bytes": len(edge.Bundle())})
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

// edgeFail writes a typed edge error. It kept its name because sixteen call
// sites use it, but its kind->status switch — the second of three copies of the
// same table — now lives in internal/apierr, so an edge failure and a DNS
// failure reach the browser in the same shape.
func edgeFail(c *gin.Context, err error) {
	apierr.Fail(c, err)
}

// applyEdgeProxyIP writes the operator's proxy IP into a freshly deployed
// Worker's configuration.
//
// It runs after the deploy rather than as a deploy binding because proxyIPs
// lives in the Worker's KV-backed config, not in its script bindings. The
// Worker authenticates this with the feed push token it was just given, so no
// admin password is involved.
//
// Setting proxyIPMode alongside the address matters: the list alone does
// nothing while the mode is "off", which would look exactly like the value
// having been ignored — the bug this function exists to fix.
func applyEdgeProxyIP(ctx context.Context, res *edge.DeployResult, proxyIP string) error {
	wc := edge.NewWorkerClient(res.Origin, res.SecurePath)
	wc.Bearer = res.FeedPushToken
	cfg, err := wc.GetConfigRaw(ctx)
	if err != nil {
		return err
	}
	cfg["proxyIPs"] = []string{strings.TrimSpace(proxyIP)}
	cfg["proxyIPMode"] = "proxyip"
	_, err = wc.PutConfigRaw(ctx, cfg)
	return err
}
