// Package api is the ForgePanel HTTP server: the Config Studio backend, the
// keygen endpoints, the protocol registry, and the subscription endpoint. The
// frontend (spec §13) consumes only this public API. Every config-generation
// endpoint runs through the same tested protocol engine (export/render), so the
// live preview a user sees is byte-identical to what the panel deploys.
package api

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/domain"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/store"
)

//go:embed web/*
var webFS embed.FS

// Server wraps the gin engine, configuration, persistence and auth.
type Server struct {
	cfg     *config.Config
	router  *gin.Engine
	db      *store.Store             // GORM-backed persistence (spec §4); nil in the light constructor
	signer  *auth.Signer             // JWT signer (spec §2)
	mem     *NodeStore               // in-memory fallback store for stateless previews/tests
	engine  *core.Controller         // proxy-core supervisor (spec §6); nil in the light constructor
	sched   *job.Scheduler           // cron scheduler (spec §11); nil in the light constructor
	login   *loginLimiter            // per-IP login rate limiter (spec §12)
	subs    *loginLimiter            // per-IP subscription-token guess limiter
	fdns    *core.ForgeDNSController // DNS-tunnel manager (spec §5)
	domains *domain.Registry         // domain registry + DNS health (spec §7)
	certs   *cert.Store              // cert store + ACME (spec §7)

	// FirstAdminPassword is retained for API compatibility but is no longer used:
	// fresh installs create the owner via the token-protected first-run setup flow
	// instead of a printed random password. It stays empty.
	FirstAdminPassword string

	// SetupToken is the one-time first-run setup token when administrator setup is
	// still pending (no admin exists); empty once setup is complete. The caller
	// prints it once and the installer surfaces it to the operator.
	SetupToken string
}

// New constructs a stateless API server (no DB) — used by unit tests and the
// pure Config Studio. Use NewWithStore for a persistent panel.
func New(cfg *config.Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	s := &Server{cfg: cfg, router: gin.New(), mem: NewNodeStore(), signer: auth.NewSigner([]byte(deriveSecret(cfg))), domains: domain.New(nil), certs: cert.NewStore(filepath.Join(cfg.DataDir, "acme"), false, nil), login: newLoginLimiter(), subs: newLoginLimiter()}
	s.router.Use(gin.Recovery(), securityHeaders())
	s.routes()
	return s
}

// NewWithStore constructs a persistent panel: it opens (or creates) the SQLite
// database, mints the JWT signer from the master key, seeds the owner admin on
// first boot, then registers every route including the authenticated admin API.
func NewWithStore(cfg *config.Config) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	db, err := store.Open(filepath.Join(cfg.DataDir, "forgepanel.db"))
	if err != nil {
		return nil, err
	}
	// ACME issuance is restricted to the configured panel domain (read live, so a
	// later domain change is honored without reconstructing the manager). A nil
	// policy would let any SNI trigger a Let's Encrypt order.
	staging := false
	if p := cfg.Panel(); p != nil {
		staging = p.ACME.Staging
	}
	allowPanelHost := func(host string) bool {
		p := cfg.Panel()
		return p != nil && p.Domain != "" && strings.EqualFold(host, p.Domain)
	}
	s := &Server{
		cfg: cfg, router: gin.New(), db: db, mem: NewNodeStore(),
		signer:  auth.NewSigner([]byte(deriveSecret(cfg))),
		engine:  core.NewController(cfg.DataDir, cfg.APIPort+1),
		fdns:    core.NewForgeDNSController(fmt.Sprintf(":%d", cfg.DNSPort), cfg.DataDir),
		domains: domain.New(nil),
		certs:   cert.NewStore(filepath.Join(cfg.DataDir, "acme"), staging, allowPanelHost),
		login:   newLoginLimiter(),
		subs:    newLoginLimiter(),
	}
	// Honour session revocation: a token whose epoch is behind the account's
	// current one was invalidated by a recovery-code login, a 2FA disable or a
	// password change. Fail closed — if the epoch cannot be read, reject.
	s.signer.SetSessionValidator(func(adminID, epoch uint) bool {
		cur, err := db.AdminSessionEpoch(adminID)
		if err != nil {
			return false
		}
		return epoch >= cur
	})
	if err := s.reconcileSetup(); err != nil {
		return nil, err
	}
	s.router.Use(gin.Recovery(), securityHeaders())
	s.routes()
	// Best-effort: bring the engines up for already-persisted inbounds. A fresh
	// or offline panel simply has nothing to start yet.
	go s.reloadEngines()
	go s.syncForgeDNS()
	// Cron scheduler: poll traffic, enforce quotas/expiry, reset by strategy.
	s.sched = job.New(job.Config{
		DB:         db,
		ReloadHook: s.reloadEngines,
		PollTraffic: func(reset bool) (map[string]int64, error) {
			if s.engine == nil {
				return nil, nil
			}
			stats, err := s.engine.QueryUserStats(reset)
			if err != nil {
				return nil, err
			}
			out := make(map[string]int64, len(stats))
			for email, ut := range stats {
				out[email] = ut.Uplink + ut.Downlink
			}
			return out, nil
		},
	})
	s.sched.Start()
	s.startBot(context.Background())
	return s, nil
}

// deriveSecret returns HMAC secret material bound to the panel master key.
func deriveSecret(cfg *config.Config) string {
	if cfg != nil && cfg.MasterKey != "" {
		return "forgepanel-jwt:" + cfg.MasterKey
	}
	return "forgepanel-jwt:ephemeral"
}

// reconcileSetup aligns the persisted first-run state with the admin table
// (spec: first-run setup + upgrade compatibility). No random administrator
// password is ever generated or printed.
//
//   - Admins already exist  → mark setup complete, clear any setup token
//     (an existing install upgrading keeps its credentials untouched).
//   - No admins yet         → setup is pending: mint (or reuse a still-valid)
//     one-time setup token, persist it, and drop setup-token.txt for the
//     installer. The owner account is created later via /api/setup/init.
//
// Either way it (re)writes panel-url.txt with the current public URL so the
// installer can display the exact address.
func (s *Server) reconcileSetup() error {
	p := s.cfg.Panel()
	n, err := s.db.CountAdmins()
	if err != nil {
		return err
	}
	if n > 0 {
		if !p.SetupCompleted || p.SetupToken != "" {
			p.SetupCompleted = true
			p.SetupToken, p.SetupExpires = "", ""
			if err := s.cfg.SavePanel(); err != nil {
				return err
			}
		}
		_ = os.Remove(filepath.Join(s.cfg.DataDir, "setup-token.txt"))
		s.writePublicURLFile()
		return nil
	}

	// Setup pending: ensure a valid one-time token exists.
	p.SetupCompleted = false
	needToken := p.SetupToken == ""
	if !needToken {
		if exp, perr := time.Parse(time.RFC3339, p.SetupExpires); perr != nil || time.Now().After(exp) {
			needToken = true
		}
	}
	if needToken {
		p.SetupToken = randHex(24)
		p.SetupExpires = time.Now().Add(24 * time.Hour).Format(time.RFC3339)
		if err := s.cfg.SavePanel(); err != nil {
			return err
		}
	}
	s.SetupToken = p.SetupToken
	// setup-token.txt (0600) is read by the installer to show the operator.
	_ = os.WriteFile(filepath.Join(s.cfg.DataDir, "setup-token.txt"), []byte(p.SetupToken+"\n"), 0o600)
	s.writePublicURLFile()
	return nil
}

// writePublicURLFile drops panel-url.txt (0600) with the full public panel URL
// so the installer can print the exact address the operator should open.
func (s *Server) writePublicURLFile() {
	_ = os.WriteFile(filepath.Join(s.cfg.DataDir, "panel-url.txt"), []byte(s.PublicURL()+"\n"), 0o600)
}

// PublicURL computes the panel's externally-reachable URL from the persisted
// panel settings, falling back to the detected server IP when no domain is set.
func (s *Server) PublicURL() string {
	p := s.cfg.Panel()
	scheme, defPort := "http", 80
	if p.HTTPSEnabled && p.Domain != "" {
		scheme, defPort = "https", 443
	}
	host := p.Domain
	if host == "" {
		host = detectServerIP()
	}
	url := scheme + "://" + host
	if p.Port != defPort {
		url += fmt.Sprintf(":%d", p.Port)
	}
	return url + p.AdminPath
}

// Handler exposes the underlying http.Handler (for tests and embedding).
func (s *Server) Handler() http.Handler { return s.router }

// CertTLSConfig returns the panel's TLS config (imported certs + ACME fallback),
// used by main to serve the panel over HTTPS.
func (s *Server) CertTLSConfig() *tls.Config { return s.certs.TLSConfig() }

// ACMEHTTPHandler returns the handler for the :80 helper: it answers ACME
// HTTP-01 challenges and redirects everything else to HTTPS.
func (s *Server) ACMEHTTPHandler() http.Handler { return s.certs.ACMEManager().HTTPHandler(nil) }

// configureTrustedProxies decides whether gin honors X-Forwarded-For. The secure
// default is to trust NO proxy, so an untrusted client cannot spoof its source
// IP (which the login rate limiter keys on). Operators who front the panel with a
// reverse proxy set FORGEPANEL_TRUSTED_PROXIES to a comma-separated CIDR/IP list.
func configureTrustedProxies(r *gin.Engine) {
	v := strings.TrimSpace(os.Getenv("FORGEPANEL_TRUSTED_PROXIES"))
	if v == "" {
		_ = r.SetTrustedProxies(nil)
		return
	}
	var list []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, p)
		}
	}
	_ = r.SetTrustedProxies(list)
}

func (s *Server) routes() {
	r := s.router
	configureTrustedProxies(r)
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	api := r.Group("/api")
	{
		// Public (studio) endpoints — stateless config generation.
		api.GET("/protocols", s.handleProtocols)
		api.GET("/protocols/schema", s.handleSchema)
		api.GET("/protocols/presets", s.handlePresets)
		api.GET("/capabilities", s.handleCapabilities)
		api.POST("/protocols/switch/preview", s.handleProtocolSwitchPreview)
		api.GET("/deploy/compose", s.handleDeployCompose)
		api.POST("/studio/preview", s.handlePreview)
		api.POST("/keygen", s.handleKeygen)
		api.POST("/import", s.handleImport)
		api.POST("/login", s.handleLogin)
		api.POST("/refresh", s.handleRefresh)
		api.GET("/setup/status", s.handleSetupStatus)
		api.POST("/setup/init", s.handleSetupInit)

		// Authenticated admin endpoints — only when a DB is attached.
		if s.db != nil {
			admin := api.Group("/admin", s.signer.Middleware())
			admin.GET("/me", s.handleMe)
			admin.GET("/inbounds", s.handleListInbounds)
			admin.POST("/inbounds", s.handleCreateInbound)
			admin.GET("/inbounds/:id/config", s.handleInboundConfig)
			admin.GET("/inbounds/:id/porthop", s.handlePortHop)
			admin.DELETE("/inbounds/:id", s.handleDeleteInbound)
			admin.GET("/groups", s.handleListGroups)
			admin.POST("/groups", s.handleCreateGroup)
			admin.GET("/users", s.handleListUsers)
			admin.POST("/users", s.handleCreateUser)
			admin.GET("/quota", s.handleQuota)
			admin.DELETE("/users/:id", s.handleDeleteUser)
			admin.GET("/stats", s.handleStats)
			admin.GET("/engines", s.handleEngines)
			admin.GET("/engines/config", s.handleEngineConfig)
			admin.POST("/engines/validate", s.handleEngineValidate)
			admin.POST("/engines/reload", func(c *gin.Context) {
				if s.engine == nil {
					s.engineUnavailable(c)
					return
				}
				s.reloadEngines()
				c.JSON(200, s.engine.Status())
			})
			admin.GET("/domains/check", s.handleDomainCheck)
			admin.GET("/domains/ns-wizard", s.handleNSWizard)
			admin.POST("/certs/import", s.handleCertImport)
			admin.GET("/certs", s.handleCertList)
			admin.GET("/nodes", s.handleListNodes)
			admin.POST("/nodes/enroll", s.handleEnrollNode)
			admin.DELETE("/nodes/:id", s.handleDeleteNode)
			admin.GET("/forgedns/adapters", s.handleForgeDNSAdapters)
			admin.GET("/forgedns/upstream/adapters", s.handleForgeDNSUpstreamAdapters)
			admin.GET("/forgedns/upstream/adapters/:adapter/options", s.handleForgeDNSAdapterOptions)
			admin.GET("/forgedns/zones/:id/config", s.handleForgeDNSZoneConfig)
			admin.PUT("/forgedns/zones/:id/config", s.handleForgeDNSZoneOverride)
			admin.POST("/forgedns/zones/:id/config/import", s.handleForgeDNSZoneImport)
			admin.GET("/forgedns/zones", s.handleForgeDNSList)
			admin.POST("/forgedns/zones", s.handleForgeDNSCreate)
			admin.PUT("/forgedns/zones/:id", s.handleForgeDNSUpdate)
			admin.POST("/forgedns/zones/:id/toggle", s.handleForgeDNSToggle)
			admin.POST("/forgedns/zones/:id/install", s.handleForgeDNSInstall)
			admin.DELETE("/forgedns/zones/:id", s.handleForgeDNSDelete)
			admin.GET("/forgedns/zones/:id/sessions", s.handleForgeDNSSessions)
			admin.GET("/forgedns/zones/:id/client", s.handleForgeDNSClientConfig)
			admin.GET("/forgedns/zones/:id/bundle", s.handleForgeDNSBundle)
			admin.GET("/forgedns/status", s.handleForgeDNSStatus)
			admin.POST("/2fa/setup", s.handle2FASetup)
			admin.POST("/2fa/enable", s.handle2FAEnable)
			admin.POST("/2fa/disable", s.handle2FADisable)
			admin.GET("/2fa/recovery", s.handle2FARecoveryStatus)
			admin.POST("/2fa/recovery/regenerate", s.handle2FARecoveryRegenerate)
			admin.POST("/change-password", s.handleChangePassword)
			admin.GET("/panel-address", s.handlePanelAddress)
			admin.POST("/panel-address", s.handlePanelAddressUpdate)
			admin.GET("/panel-address/dns-check", s.handlePanelDNSCheck)
			admin.GET("/panel-address/port-check", s.handlePanelPortCheck)
			admin.POST("/panel-address/cert/renew", s.handlePanelCertRenew)
		}
	}

	// Subscription endpoint (spec §9): format auto-detect by UA + explicit
	// suffix. DB-backed when a store is attached, else the in-memory demo store.
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)

	// Node agent endpoints (token-authenticated, spec §10).
	if s.db != nil {
		r.POST("/api/node/register", s.handleNodeRegister)
		r.POST("/api/node/heartbeat", s.handleNodeHeartbeat)
		r.GET("/node-install.sh", s.handleNodeInstallScript)
	}

	// The full admin panel at root + the randomized admin path; the Config Studio
	// remains available as a tool at /studio.
	studio := s.studioHTML()
	serveStudio := func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", studio) }
	adminPage := s.assetOr("web/admin.html", string(studio)) // falls back to the studio until the panel asset is present
	serveAdmin := func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", adminPage) }
	r.GET("/", serveAdmin)
	r.GET("/studio", serveStudio)
	if s.cfg.AdminPath != "" && s.cfg.AdminPath != "/" {
		r.GET(s.cfg.AdminPath, serveAdmin)
	}
	// ForgeDNS admin page — clickable tunnel management, no terminal (spec §5).
	if s.db != nil {
		fdnsPage := s.assetOr("web/forgedns.html", "")
		r.GET("/forgedns", func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", fdnsPage) })
	}
}

func (s *Server) studioHTML() []byte {
	if b, err := webFS.ReadFile("web/studio.html"); err == nil {
		return b
	}
	return []byte(fallbackStudio)
}

// --- /api/protocols -------------------------------------------------------

type protoMeta struct {
	Proto      string   `json:"proto"`
	Label      string   `json:"label"`
	Transports []string `json:"transports"`
	Securities []string `json:"securities"`
	Engine     string   `json:"engine"`
}

func (s *Server) handleProtocols(c *gin.Context) {
	transportsAll := []string{}
	for _, n := range model.AllNetworks() {
		transportsAll = append(transportsAll, string(n))
	}
	securitiesAll := []string{string(model.SecNone), string(model.SecTLS), string(model.SecReality)}
	labels := map[model.Protocol]string{
		model.ProtoVLESS: "VLESS", model.ProtoVMess: "VMess", model.ProtoTrojan: "Trojan",
		model.ProtoShadowsocks: "Shadowsocks", model.ProtoSOCKS: "SOCKS", model.ProtoHTTP: "HTTP",
		model.ProtoHysteria2: "Hysteria2", model.ProtoTUIC: "TUIC", model.ProtoAnyTLS: "AnyTLS",
		model.ProtoWireGuard: "WireGuard", model.ProtoShadowTLS: "ShadowTLS", model.ProtoSSH: "SSH",
		model.ProtoBrook: "Brook", model.ProtoForgeDNS: "ForgeDNS",
	}
	out := []protoMeta{}
	for _, p := range model.AllProtocols() {
		m := protoMeta{Proto: string(p), Label: labels[p], Engine: render.EngineFor(p)}
		if p.UsesTransport() {
			m.Transports = transportsAll
			m.Securities = securitiesAll
		} else if p.IsQUICBased() {
			m.Securities = []string{string(model.SecTLS)}
		}
		out = append(out, m)
	}
	c.JSON(200, out)
}

// --- /api/studio/preview --------------------------------------------------

// PreviewResponse is the live-preview payload the Config Studio renders.
type PreviewResponse struct {
	OK      bool             `json:"ok"`
	URI     string           `json:"uri"`
	Xray    string           `json:"xray"`
	Singbox string           `json:"singbox"`
	Clash   string           `json:"clash"`
	Errors  []PreviewFinding `json:"errors"`
}

// PreviewFinding is a Config Doctor style validation result (spec §8.6).
type PreviewFinding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func (s *Server) handlePreview(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		c.JSON(400, PreviewResponse{Errors: []PreviewFinding{{Severity: "error", Message: "bad JSON: " + err.Error()}}})
		return
	}
	applyCreateDefaults(&n)
	s.substituteAddr(&n, hostOnly(c.Request.Host))
	s.applyExportDefaults(&n)
	resp := PreviewResponse{OK: true}
	if err := n.Validate(); err != nil {
		resp.OK = false
		resp.Errors = append(resp.Errors, PreviewFinding{Severity: "error", Message: err.Error()})
	}
	// Config Doctor advisory checks (non-fatal).
	resp.Errors = append(resp.Errors, doctor(&n)...)

	if uri, err := export.URI(&n); err == nil {
		resp.URI = uri
	} else if resp.OK {
		resp.Errors = append(resp.Errors, PreviewFinding{Severity: "warn", Message: "no client link for this protocol: " + err.Error()})
	}
	if b, err := render.RenderXrayJSON(&n); err == nil {
		resp.Xray = string(b)
	}
	if b, err := render.RenderSingboxJSON(&n); err == nil {
		resp.Singbox = string(b)
	}
	if y, err := export.ClashYAML([]*model.Node{&n}); err == nil {
		resp.Clash = y
	}
	c.JSON(200, resp)
}

// doctor runs the lightweight, dependency-free subset of Config Doctor checks
// (spec §8.6) that need no network probe.
func doctor(n *model.Node) []PreviewFinding {
	var f []PreviewFinding
	if n.Security.Type == model.SecReality && n.Transport.Network != model.NetTCP && n.Transport.Network != model.NetGRPC && n.Transport.Network != model.NetXHTTP {
		f = append(f, PreviewFinding{"warn", "REALITY is normally used with tcp/grpc/xhttp; check client support for this transport"})
	}
	if n.Protocol == model.ProtoVLESS && n.Flow == "xtls-rprx-vision" && n.Security.Type == model.SecNone {
		f = append(f, PreviewFinding{"error", "xtls-rprx-vision requires TLS or REALITY, not security=none"})
	}
	if n.Security.Type == model.SecTLS && n.Security.ServerName == "" && n.Transport.Host == "" {
		f = append(f, PreviewFinding{"warn", "TLS with no SNI/host: clients may fail certificate validation"})
	}
	if n.Security.Type == model.SecReality && n.Security.Reality != nil {
		dest := n.Security.Reality.Dest
		if dest == "" && len(n.Security.Reality.ServerNames) > 0 {
			dest = n.Security.Reality.ServerNames[0]
		}
		badDests := []string{"microsoft.com", "www.microsoft.com", "bing.com", "amazon.com"}
		for _, bad := range badDests {
			if strings.Contains(dest, bad) {
				f = append(f, PreviewFinding{"warn", "REALITY dest '" + dest + "' is unreliable (redirects / no clean X25519). Use a proven steal-site: www.cloudflare.com, www.apple.com, dl.google.com, swift.org, or an Iran-domestic CDN (aparat.ir, digikala.com)."})
				break
			}
		}
	}
	if n.Protocol == model.ProtoWireGuard && n.WireGuard != nil && n.WireGuard.MTU > 1420 {
		f = append(f, PreviewFinding{"warn", "WireGuard MTU above 1420 often fragments; 1280–1420 is safer"})
	}
	return f
}

// --- /api/keygen ----------------------------------------------------------

func (s *Server) handleKeygen(c *gin.Context) {
	var req struct {
		Kind   string `json:"kind"`
		Method string `json:"method"`
		Bytes  int    `json:"bytes"`
	}
	_ = c.ShouldBindJSON(&req)
	switch strings.ToLower(req.Kind) {
	case "reality":
		kp, err := keygen.RealityKeys()
		respond(c, kp, err)
	case "uuid":
		c.JSON(200, gin.H{"uuid": keygen.UUID()})
	case "shortid":
		sid, err := keygen.ShortID(8)
		respond(c, gin.H{"short_id": sid}, err)
	case "ss2022":
		psk, err := keygen.SS2022PSK(req.Method)
		respond(c, gin.H{"psk": psk, "method": req.Method}, err)
	case "wireguard":
		kp, err := keygen.WireGuardKeys()
		respond(c, kp, err)
	case "ssh":
		kp, err := keygen.SSHKeys()
		respond(c, kp, err)
	case "password":
		b := req.Bytes
		if b == 0 {
			b = 16
		}
		pw, err := keygen.Password(b)
		respond(c, gin.H{"password": pw}, err)
	case "mldsa65":
		seed, err := keygen.MLDSA65Seed()
		respond(c, gin.H{"seed": seed}, err)
	default:
		c.JSON(400, gin.H{"error": "unknown keygen kind: " + req.Kind})
	}
}

func respond(c *gin.Context, v any, err error) {
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, v)
}

// --- /api/import (Paste-Anything importer, spec §8.3) ---------------------

func (s *Server) handleImport(c *gin.Context) {
	var req struct {
		Text string `json:"text"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	nodes, errs := ImportAny(req.Text)
	out := make([]json.RawMessage, 0, len(nodes))
	for _, n := range nodes {
		b, _ := json.Marshal(n)
		out = append(out, b)
	}
	c.JSON(200, gin.H{"count": len(nodes), "nodes": out, "errors": errs})
}

// securityHeaders sets the hardened headers required by spec §12.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		c.Next()
	}
}

// staticFS exposes the embedded web assets (used by the full build for extra
// assets beyond the single studio.html).
func (s *Server) staticFS() fs.FS {
	sub, _ := fs.Sub(webFS, "web")
	return sub
}

var _ = (*Server).staticFS

// assetOr returns an embedded asset's bytes, or a fallback string if absent.
func (s *Server) assetOr(name, fallback string) []byte {
	if b, err := webFS.ReadFile(name); err == nil {
		return b
	}
	return []byte(fallback)
}
