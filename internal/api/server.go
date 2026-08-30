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
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/bridge"
	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/domain"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/nodeca"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/telegram"
	"github.com/forgepanel/forgepanel/internal/version"
	"github.com/forgepanel/forgepanel/internal/webhook"
	"github.com/forgepanel/forgepanel/internal/wgpeer"
)

//go:embed web/*
var webFS embed.FS

// The settings registry is built on exactly the two methods the store exposes
// for its key/value table; assert it here so a rename breaks the build.
var _ settings.KV = (*store.Store)(nil)

// knobs is typed, validated, defaulted access to the settings table: every
// reader and writer of an operator setting in this package goes through it.
//
// DERIVED from s.db rather than assigned in a constructor, deliberately. As a
// field it had to be set in every place a Server is built, and it was not — the
// half-dozen fixtures that assemble a Server around a live database by hand all
// read registry defaults instead of the rows in front of them, which is the
// same "wired in one place, forgotten in the others" failure the registry exists
// to end. A nil *Values is usable and answers every read with the registered
// default, which is what a panel with no store should do.
func (s *Server) knobs() *settings.Values {
	if s == nil || s.db == nil {
		return nil
	}
	return settings.NewValues(s.db)
}

// Server wraps the gin engine, configuration, persistence and auth.
type Server struct {
	// cdnSeen is set the first time a request arrives stamped by a CDN that
	// parses WebSocket traffic. It lives here rather than on Config because
	// Config is marshalled by value and an atomic makes it uncopyable — vet
	// says so. Learn-once: one stamped request proves a CDN is in front, and an
	// unstamped one proves nothing.
	cdnSeen atomic.Bool
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

	// The node control plane's own CA, opened lazily from DataDir.
	nodeCAOnce sync.Once
	nodeCARef  *nodeca.CA
	nodeCAErr  error

	// The reverse-tunnel bridge supervisor, opened lazily.
	bridgeOnce sync.Once
	bridgeMgr  *bridge.Manager

	// The per-client WireGuard peer manager, opened lazily.
	wgOnce sync.Once
	wgMgr  *wgpeer.Manager
	wgErr  error
	// notifier pushes operator alerts. Nil when Telegram is not configured, and
	// every method on it is a safe no-op in that state, so no call site checks.
	notifier *telegram.Notifier

	// webhooks posts the same lifecycle events to endpoints the operator runs.
	// Nil in the light constructor, and every method on it is a safe no-op in
	// that state, so no call site checks.
	webhooks *webhook.Dispatcher

	// bots owns the Telegram bot's goroutine so a settings change can restart it
	// without restarting the panel.
	bots *botControl
	// tgSend overrides how a test message is delivered. Nil means the real Bot
	// API; a test replaces it rather than dialling api.telegram.org.
	tgSend telegramTestSender

	// poolProber overrides how the scheduled rotation-pool sweep health-checks a
	// domain. Nil means a real TLS handshake, which is what production wants and
	// what a test must not do. It lives on the Server rather than in a package
	// variable so two panels in one process cannot share one.
	poolProber dns.Prober

	// The last congestion-control outcome reported, so a host that refuses the
	// sysctl does not repeat itself once a minute forever. On the Server for the
	// same reason poolProber is: two panels in one process must not share it.
	netTuneMu   sync.Mutex
	netTuneLast string

	stop context.CancelFunc

	lifecycleMu sync.Mutex
	closed      bool
	background  sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error

	// acmeHTTP is the :80 HTTP-01 helper. It is started whenever a panel domain
	// is configured — at boot and, so TLS needs no restart, the moment a domain
	// is saved from the UI. Guarded by acmeMu.
	acmeMu   sync.Mutex
	acmeHTTP *http.Server

	// edgePush debounces canonical-feed pushes to registered ForgeEdge
	// deployments (§6); see EdgePushSoon in edge.go.
	edgePush edgePushState

	// logs holds each node's recent core output and the admins watching it. A
	// zero value works, deliberately: the panel has two constructors and a hub
	// that needed constructing is a hub that gets wired into one of them.
	logs nodeLogHub

	// paasRoutes maps a URL path to the loopback port a core bound for it, when
	// the panel runs behind a platform edge that gives out one port. Rebuilt on
	// every engine reload and read by the front proxy on every request, so it is
	// guarded rather than passed. See paas.go.
	paasMu     sync.RWMutex
	paasRoutes []paasRoute

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
		if p != nil && p.Domain != "" && strings.EqualFold(host, p.Domain) {
			return true
		}
		// One-click TLS (BUG-3): also issue for any domain in the registry, so an
		// inbound whose domain is registered gets an ACME cert on demand. Still a
		// closed allowlist — an arbitrary SNI cannot trigger a Let's Encrypt order.
		if db != nil {
			if _, err := db.DomainByName(host); err == nil {
				return true
			}
		}
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg: cfg, router: gin.New(), db: db, mem: NewNodeStore(),
		signer:  auth.NewSigner([]byte(deriveSecret(cfg))),
		engine:  core.NewController(cfg.DataDir, cfg.APIPort+1),
		fdns:    core.NewForgeDNSController(fmt.Sprintf(":%d", cfg.DNSPort), cfg.DataDir),
		domains: domain.New(nil),
		certs:   cert.NewStore(filepath.Join(cfg.DataDir, "acme"), staging, allowPanelHost),
		login:   newLoginLimiter(),
		subs:    newLoginLimiter(),
		stop:    cancel,
	}
	// The routing definition is read at BUILD time rather than pushed in, so an
	// operator's edit takes effect on the very next reload without anything
	// having to remember to tell the controller about it. That "remember to
	// notify" pattern is how a stale copy of a config lingers.
	s.engine.SetRoutingSource(s.routingSpecs)

	// Apply the operator's stored core pins before anything reloads. Skipping
	// this is how the whole feature dies quietly across a restart: the API keeps
	// reporting the selected version while every adapter goes on exec'ing the
	// one this build was compiled against. Non-fatal — a panel that cannot read
	// its pins must still start, on the shipped cores, so the operator can reach
	// the UI and see why.
	if err := s.applyStoredCorePins(); err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: core pins:", err)
	}

	// Outbound webhooks. Built eagerly rather than on first use: its only caller
	// is the emit seam below, and a lazily built sink is a nil sink at exactly
	// the moment the first event fires.
	s.webhooks = webhook.NewDispatcher(s.webhookEndpoints, s.recordWebhookAttempt)

	// Restore certificates the operator imported in an earlier run. Without
	// this they lived in memory only: the upload succeeded, the panel served
	// them, and after the next restart every TLS surface silently fell back to
	// self-signed with no error to explain it.
	for _, err := range s.certs.LoadImported() {
		fmt.Fprintln(os.Stderr, "forgepanel: cert:", err)
	}
	// Bridge the certificate store to the proxy engines. ReloadSpecs previously
	// handed BuildMulti the self-signed pair unconditionally, so an inbound on a
	// domain with a valid Let's Encrypt certificate was still served a
	// self-signed one and every client had to skip verification.
	s.engine.SetCertResolver(s.certs.Materialize)

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
		cancel()
		_ = db.Close()
		return nil, err
	}
	s.router.Use(gin.Recovery(), securityHeaders())
	s.routes()
	// A platform hostname that appeared after an inbound was created leaves that
	// inbound pointing somewhere unreachable. Repair those BEFORE the cores are
	// handed the list, or this boot still serves the stale addresses and the
	// operator has to restart a second time to get a working config.
	s.ReconcilePaaSAddresses()
	// Best-effort: bring the engines up for already-persisted inbounds. A fresh
	// or offline panel simply has nothing to start yet.
	s.startBackground(s.reloadEngines)
	s.startBackground(s.syncForgeDNS)
	// The host's congestion control is not durable state: a /proc write is gone
	// after a reboot, and this is the only code that runs on every panel start.
	// Without it the BBR toggle is a one-shot that dies at the next restart of
	// the machine while the panel keeps reporting it as on.
	s.startBackground(s.applyNetTune)
	// Cron scheduler: poll traffic, enforce quotas/expiry, reset by strategy.
	s.sched = job.New(job.Config{
		DB:         db,
		ReloadHook: s.reloadEngines,
		// Ninety days of trail by default: long enough to investigate an
		// incident found weeks later, short enough that the table does not
		// become the largest thing in the database on a busy panel.
		AuditRetention: 90 * 24 * time.Hour,
		// Hourly detail for a month is enough to investigate a spike; daily is
		// billing history and is kept for two years so a year-long chart has a
		// year to show.
		RollupHourlyRetention: 31 * 24 * time.Hour,
		RollupDailyRetention:  730 * 24 * time.Hour,
		// A daily local backup, keeping a week. Read from cfg at run time so
		// changing it does not need a restart.
		BackupConfig: func() (string, string, time.Duration, int) {
			return cfg.DataDir, cfg.MasterKey, 24 * time.Hour, 7
		},
		// The fan-out, not one destination: this is the single hook the
		// scheduler holds, so a destination not named here is a destination
		// that never runs however completely it is built.
		DeliverBackup: s.deliverBackup,
		PollTraffic: func(reset bool) (map[string]store.TrafficSplit, error) {
			if s.engine == nil {
				return nil, nil
			}
			stats, err := s.engine.QueryUserStats(reset)
			if err != nil {
				return nil, err
			}
			// The engine reports uplink and downlink SEPARATELY and this used to
			// sum them here, before anything else could see the two halves. The
			// panel then had one number, so every subscription reported
			// "upload=0" and put the whole total under download — a figure every
			// client displays verbatim.
			out := make(map[string]store.TrafficSplit, len(stats))
			for email, ut := range stats {
				out[email] = store.TrafficSplit{Up: ut.Uplink, Down: ut.Downlink}
			}
			return out, nil
		},
		// Presence is what makes User.IPLimit mean anything. Nil when there is no
		// core, and the scheduler treats nil as "do not enforce" rather than
		// enforcing against a count of zero — which would release every held
		// user on a panel that happens to have no engine running.
		ActiveAddresses: func(email string) int {
			if s.engine == nil {
				return 0
			}
			return s.engine.ActiveAddresses(email)
		},
		// An account that stops working needs a findable reason. Without this the
		// user reports an outage, the panel shows them active, and nothing
		// anywhere says the panel did it on purpose.
		// Housekeeping that had no caller. EvictIdle's own doc comment said
		// "called by the scheduler" and nothing called it, so every ForgeDNS
		// session lived until the process restarted.
		Maintenance: s.runMaintenance,
		// Quota trips and expiries are the transitions a customer notices before
		// the operator does.
		Notify: func(event, subject, message string) {
			s.emit(telegram.Event(event), subject, message)
		},
		AuditIPLimit: func(action, target string, seen, limit int) {
			if s.db == nil {
				return
			}
			entry := &store.AuditLog{Actor: "system", Action: action, Target: target}
			if seen > 0 {
				entry.Diff = fmt.Sprintf("addresses: %d; limit: %d", seen, limit)
			}
			s.db.Audit(entry)
		},
	})
	s.sched.Start()
	s.bots = &botControl{base: ctx}
	s.restartBot()
	return s, nil
}

// emit is the ONE place a lifecycle event reaches a sink.
//
// There was no such place. The scheduler's Notify closure called the Telegram
// notifier directly, and so did four separate spots in maintenance.go, so a
// second sink meant finding all five — and the four in maintenance.go are
// exactly the ones a reader of the closure would never think to look for. Every
// alert now goes through here; the next sink is one function, not a hunt.
//
// Both sinks suppress a repeat of an alert that is still active, on the same
// six-hour window, so an operator running both does not see them disagree about
// how often a node that is still down is worth mentioning.
func (s *Server) emit(event telegram.Event, subject, message string) {
	s.notifier.Notify(event, subject, message)
	s.webhooks.Alert(webhook.Event{Type: string(event), Subject: subject, Message: message})
}

// emitResolve announces that an alert has cleared.
//
// Both sinks stay silent about a problem they never reported, so a healthy
// fleet does not announce a recovery per node per sweep.
func (s *Server) emitResolve(event telegram.Event, subject, message string) {
	s.notifier.Resolve(event, subject, message)
	s.webhooks.Resolve(webhook.Event{Type: string(event), Subject: subject, Message: message})
}

// Close stops background workers and dependent services before closing storage.
// It is safe to call more than once.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closed = true
		s.lifecycleMu.Unlock()
		if s.stop != nil {
			s.stop()
		}
		if s.sched != nil {
			s.sched.Stop()
		}
		s.background.Wait()
		if s.engine != nil {
			s.engine.StopAll()
		}
		if s.fdns != nil {
			s.fdns.Stop()
		}
		// Stopped BEFORE the store closes: a delivery in flight records its
		// outcome against the endpoint row, and a write into a closed database
		// is an error nobody ever reads.
		s.webhooks.Close()
		if s.db != nil {
			s.closeErr = s.db.Close()
		}
	})
	return s.closeErr
}

func (s *Server) startBackground(fn func()) {
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return
	}
	s.background.Add(1)
	s.lifecycleMu.Unlock()
	go func() {
		defer s.background.Done()
		fn()
	}()
}

func (s *Server) isClosed() bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.closed
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
	// Behind a platform edge the port this process bound is an internal detail
	// the outside world never dials: the edge listens on 443 of the platform's
	// hostname and forwards inward. Printing the bound port here would hand the
	// operator a URL to their own container's private port.
	if pa := s.cfg.PaaS(); pa.Enabled {
		if pa.Domain != "" {
			return "https://" + pa.Domain + pa.PublicPortString() + p.AdminPath
		}
		// No domain generated yet. Falling through would print the container's
		// own private address — a URL that resolves nowhere and that an operator
		// will reasonably spend an hour trying to reach. The admin path is still
		// the useful half, so give that and name what is missing.
		return "(no public domain yet — generate one on the platform) " + p.AdminPath
	}
	// The panel always serves TLS (self-signed with no domain, ACME with one).
	scheme, defPort := "https", 443
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

// studioTabURL is where an old /studio bookmark should land: the panel, whose
// Config Studio tab is the real one.
func (s *Server) studioTabURL() string {
	if p := s.cfg.AdminPath; p != "" && p != "/" {
		return p + "/"
	}
	return "/"
}

// Handler exposes the underlying http.Handler (for tests and embedding).
//
// Behind a platform edge the same handler also fronts the inbounds: they share
// the one port the platform routes to, so the panel's handler is what decides
// whether a request is for the panel or for a tunnel. paasFront is the identity
// wrapper on a normal install.
func (s *Server) Handler() http.Handler { return s.paasFront(s.router) }

// CertTLSConfig returns the panel's TLS config (imported certs + ACME fallback),
// used by main to serve the panel over HTTPS.
func (s *Server) CertTLSConfig() *tls.Config {
	cfg := s.certs.TLSConfig()
	// Ask every client for a certificate, and REQUEST rather than REQUIRE it.
	//
	// Requiring one would break the panel for browsers, which have none — the
	// same listener serves the admin UI and the node control plane. Requesting
	// it means a node's certificate arrives and is verified against the node CA
	// (ClientCAs), while a browser simply sends nothing and is handled as
	// before. The node-facing handlers are what decide whether the absence of a
	// certificate is acceptable.
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	if pool := s.nodeClientCAPool(); pool != nil {
		cfg.ClientCAs = pool
	}
	return cfg
}

// ACMEHTTPHandler returns the handler for the :80 helper: it answers ACME
// HTTP-01 challenges and redirects everything else to HTTPS.
func (s *Server) ACMEHTTPHandler() http.Handler { return s.certs.ACMEManager().HTTPHandler(nil) }

// StartACMEHelper ensures the :80 HTTP-01 helper is listening so Let's Encrypt
// can validate the panel domain. It is idempotent and safe to call at boot and
// again the instant a domain is saved from the UI, so a browser-trusted cert is
// obtained without a restart. Binding :80 needs CAP_NET_BIND_SERVICE (the
// systemd unit and the Docker root process both have it); a bind failure (port
// already in use, missing capability) is logged, never fatal.
func (s *Server) StartACMEHelper() {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	if s.acmeHTTP != nil {
		return // already running
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: ACME :80 helper not started:", err)
		return
	}
	srv := &http.Server{Handler: s.ACMEHTTPHandler(), ReadHeaderTimeout: 10 * time.Second}
	s.acmeHTTP = srv
	go func() {
		if e := srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "forgepanel: ACME :80 helper:", e)
		}
	}()
}

// StopACMEHelper shuts the :80 helper down — used when the panel domain is
// cleared, so the panel stops holding port 80.
func (s *Server) StopACMEHelper() {
	s.acmeMu.Lock()
	srv := s.acmeHTTP
	s.acmeHTTP = nil
	s.acmeMu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

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
	// healthz carries the build identity so an operator (and the release
	// pipeline's metadata check) can confirm which artifact is actually serving,
	// without shelling into the host or the container.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "version": version.Get()})
	})
	r.GET("/api/version", func(c *gin.Context) { c.JSON(200, version.Get()) })

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
			// s.authz() enforces the RBAC the panel already modelled but never
			// mounted: authentication proves who you are, this proves you may
			// perform the action. See internal/api/authz.go.
			// apiTokenAuth runs FIRST and only claims requests whose bearer value
			// is shaped like one of our tokens; everything else falls through to
			// the JWT middleware untouched.
			admin := api.Group("/admin", s.apiTokenAuth(), s.signer.Middleware(), s.authz(), s.learnPaaSDomain())
			admin.GET("/me", s.handleMe)
			admin.GET("/inbounds", s.handleListInbounds)
			// portCollisionGuard runs BEFORE the handler writes the row. Two
			// inbounds on one port do not fail politely: the engine rejects the
			// generated document as a whole, so one bad create takes EVERY other
			// inbound offline, and because the panel never applies a config the
			// core rejected the operator sees a silent no-op with the stale
			// config still running. The guard existed and was mounted only
			// inside its own test, so the tests passed while production had no
			// check at all.
			admin.POST("/inbounds", s.portCollisionGuard(), s.handleCreateInbound)
			admin.PUT("/inbounds/:id", s.portCollisionGuard(), s.handleUpdateInbound)
			admin.GET("/inbounds/:id/config", s.handleInboundConfig)
			admin.GET("/inbounds/:id/porthop", s.handlePortHop)
			// Lets the create form warn while the operator is still typing
			// rather than after they submit.
			s.registerPortRoutes(admin)
			admin.DELETE("/inbounds/:id", s.handleDeleteInbound)
			// Edit lifecycle (BUG-4): clone, toggle, undo, bulk.
			admin.POST("/inbounds/:id/clone", s.handleCloneInbound)
			admin.POST("/inbounds/:id/toggle", s.handleToggleInbound)
			admin.POST("/inbounds/:id/undo", s.handleUndoInbound)
			admin.POST("/inbounds/bulk", s.handleBulkInbounds)
			// Validation & Proof engine (§3).
			admin.GET("/inbounds/:id/hosts", s.handleListHosts)
			admin.POST("/inbounds/:id/hosts", s.handleCreateHost)
			admin.PUT("/inbounds/:id/hosts/:hostID", s.handleUpdateHost)
			admin.DELETE("/inbounds/:id/hosts/:hostID", s.handleDeleteHost)
			admin.POST("/inbounds/validate", s.handleValidateInbound)
			admin.POST("/inbounds/:id/verify", s.handleVerifyInbound)
			admin.GET("/doctor", s.handleDoctor)
			// §5 Domain & DNS automation wizard (Cloudflare-first). Mounted under
			// /api/admin/dns/…; its own DB-backed store + AES-GCM credential
			// encryption. Registration is best-effort: a store/key failure must not
			// take the rest of the admin API down.
			if s.db != nil {
				gs, storeErr := dns.NewGormStore(s.db.DB())
				enc, encErr := dns.NewAESGCMFromPassphrase(deriveSecret(s.cfg))
				switch {
				case storeErr != nil || encErr != nil:
					// Best-effort registration must still SAY it did not happen.
					// Failing silently left the DNS routes absent with no
					// indication why, so the UI's DNS section 404'd and looked
					// like a bug in the frontend.
					err := storeErr
					if err == nil {
						err = encErr
					}
					fmt.Fprintln(os.Stderr, "forgepanel: DNS automation is unavailable:", err)
				default:
					dns.RegisterRoutes(admin, dns.Deps{
						Credentials: gs, Encryptor: enc, Pools: gs, CleanIPs: gs,
						// Audit was nil, so NOT ONE DNS mutation was ever
						// recorded: adding a provider credential, repointing a
						// domain, rotating an address — the changes most likely
						// to break a deployment and most worth being able to
						// trace afterwards — happened with no trail at all,
						// while every other mutation in the panel was logged.
						// The action strings the DNS package passes already carry
						// their own "dns." prefix ("dns.credential.create"), so
						// this must NOT add another.
						Audit: func(c *gin.Context, action, target, result string) {
							if result != "" && result != "ok" {
								// Failures are recorded too. A trail that holds
								// only successes cannot answer "did someone
								// try", which is the question asked after a
								// breach.
								s.audit(c, action+".failed", target+": "+result)
								return
							}
							s.audit(c, action, target)
						},
					})
				}
			}
			// §6 ForgeEdge control plane, mounted the same way at
			// /api/admin/edge/…. The PULL feed itself is NOT here: a Worker cron
			// has no admin session, so it lives at /api/edge/feed behind its own
			// bearer token (registered below).
			s.registerEdgeRoutes(admin)
			admin.GET("/groups", s.handleListGroups)
			admin.POST("/groups", s.handleCreateGroup)
			admin.GET("/groups/:id", s.handleGetGroup)
			admin.PATCH("/groups/:id", s.handleUpdateGroup)
			admin.DELETE("/groups/:id", s.handleDeleteGroup)
			admin.GET("/users", s.handleListUsers)
			admin.POST("/users", s.handleCreateUser)
			admin.GET("/users/:id", s.handleGetUser)
			admin.PATCH("/users/:id", s.handleUpdateUser)
			admin.PUT("/users/:id/inbounds", s.handleSetUserInbounds)
			admin.POST("/users/:id/reset-credentials", s.handleResetUserCredentials)
			admin.POST("/users/:id/sub-revoked", s.handleSetSubRevoked)
			admin.GET("/users/:id/sub-requests", s.handleUserSubRequests)
			// Saved plans. handleCreateUser reads one when the request carries
			// template_id; these five only maintain the list.
			admin.GET("/user-templates", s.handleListUserTemplates)
			admin.POST("/user-templates", s.handleCreateUserTemplate)
			admin.GET("/user-templates/:id", s.handleGetUserTemplate)
			admin.PATCH("/user-templates/:id", s.handleUpdateUserTemplate)
			admin.DELETE("/user-templates/:id", s.handleDeleteUserTemplate)
			admin.POST("/users/:id/apply-template", s.handleApplyUserTemplate)
			admin.GET("/quota", s.handleQuota)
			// The audit trail. Entries carry the actor, their IP and what they
			// did across every admin, so this is owner/admin only.
			// Backup. A backup contains the database, the master key and the
			// certificates — everything needed to impersonate this panel — so
			// it is owner-only, like the other whole-panel material.
			admin.POST("/backup", s.handleCreateBackup)
			admin.POST("/backup/verify", s.handleVerifyBackup)
			admin.GET("/backup/status", s.handleBackupStatus)

			// Usage history, from the rollups written alongside billing.
			// API tokens. tenantMgmt rather than owner-only: a reseller
			// automating their own customer management is the ordinary case, and
			// a token can never exceed the authority of the account that minted
			// it (see clampRole).
			// Prometheus scrape. Under /admin so it goes through the ordinary
			// token path: an observability-scoped API token — the narrowest the
			// panel issues — is exactly what a scraper should hold, and an open
			// /metrics tells anyone who finds it how large the deployment is and
			// when its nodes are struggling.
			admin.GET("/bridges/backends", s.handleListBridgeBackends)
			admin.GET("/bridges", s.handleListBridges)
			admin.POST("/bridges", s.handleCreateBridge)
			admin.GET("/bridges/:id/bundle", s.handleBridgeBundle)
			admin.POST("/bridges/:id/restart", s.handleRestartBridge)
			admin.DELETE("/bridges/:id", s.handleDeleteBridge)
			admin.GET("/metrics", s.handleMetrics)

			admin.GET("/tokens", s.handleListAPITokens)
			admin.POST("/tokens", s.handleCreateAPIToken)
			admin.DELETE("/tokens/:id", s.handleRevokeAPIToken)

			// Config profiles: one protocol definition deployed to N nodes.
			// Foreign-panel import: preview writes nothing, apply is atomic.
			admin.POST("/migrate/preview", s.handleMigratePreview)
			admin.POST("/migrate/apply", s.handleMigrateApply)

			admin.GET("/profiles", s.handleListProfiles)
			admin.POST("/profiles", s.handleSaveProfile)
			admin.PUT("/profiles/:id", s.handleSaveProfile)
			admin.DELETE("/profiles/:id", s.handleDeleteProfile)
			admin.POST("/profiles/bindings", s.handleSaveBinding)
			admin.PUT("/profiles/bindings/:id", s.handleSaveBinding)
			admin.DELETE("/profiles/bindings/:id", s.handleDeleteBinding)

			admin.GET("/online", s.handleOnlineUsers)

			// Routing: named outbounds and the ordered rules that select between
			// them. Owner/admin only — a rule can send any user's traffic
			// anywhere, or stop it entirely.
			admin.GET("/routing/outbounds", s.handleListOutbounds)
			admin.POST("/routing/outbounds", s.handleSaveOutbound)
			admin.PUT("/routing/outbounds/:id", s.handleSaveOutbound)
			admin.DELETE("/routing/outbounds/:id", s.handleDeleteOutbound)

			// Cloudflare WARP, provisioned as one of those outbounds. Separate
			// routes rather than a protocol option on the generic outbound
			// editor because it has a lifecycle the others do not: a device is
			// registered with Cloudflare, a license may be attached to it, and
			// the endpoint rotates without the account changing.
			// What this deployment can do, so the UI can drop what the platform
			// owns instead of showing controls that cannot work.
			admin.GET("/deployment", s.handleDeployment)
			// REALITY dest probing: measured, not guessed.
			admin.GET("/reality/dest-probe", s.handleRealityDestProbe)
			admin.GET("/reality/dest-suggest", s.handleRealityDestSuggest)
			admin.GET("/routing/warp", s.handleWarpStatus)
			admin.POST("/routing/warp", s.handleWarpProvision)
			admin.POST("/routing/warp/rotate", s.handleWarpRotate)
			admin.DELETE("/routing/warp", s.handleWarpDelete)
			admin.GET("/routing/rules", s.handleListRoutingRules)
			admin.POST("/routing/rules", s.handleSaveRoutingRule)
			admin.PUT("/routing/rules/:id", s.handleSaveRoutingRule)
			admin.DELETE("/routing/rules/:id", s.handleDeleteRoutingRule)
			admin.POST("/routing/rules/reorder", s.handleReorderRoutingRules)
			// Failover groups: several outbounds behind one tag, health-probed,
			// so a rule keeps working when the exit it names stops answering.
			admin.GET("/routing/groups", s.handleListOutboundGroups)
			admin.POST("/routing/groups", s.handleSaveOutboundGroup)
			admin.PUT("/routing/groups/:id", s.handleSaveOutboundGroup)
			admin.DELETE("/routing/groups/:id", s.handleDeleteOutboundGroup)
			admin.GET("/routing/presets", s.handleListRoutingPresets)
			admin.POST("/routing/presets/:name", s.handleApplyRoutingPreset)
			admin.GET("/traffic/series", s.handleTrafficSeries)
			admin.GET("/traffic/top", s.handleTopConsumers)
			admin.GET("/audit", s.handleListAudit)
			admin.GET("/audit/actions", s.handleAuditActions)
			// Admin/reseller provisioning. Owner-only: see internal/api/authz.go.
			admin.GET("/admins", s.handleListAdmins)
			admin.POST("/admins", s.handleCreateAdmin)
			admin.PATCH("/admins/:id", s.handleUpdateAdmin)
			admin.DELETE("/admins/:id", s.handleDeleteAdmin)
			admin.DELETE("/users/:id", s.handleDeleteUser)
			// Backing state for the panel's status indicator: per-subsystem
			// health with human-readable text, replacing the unexplained dot.
			admin.GET("/health/detail", s.handleHealthDetail)
			admin.GET("/stats", s.handleStats)
			admin.GET("/overview", s.handleOverview)
			admin.GET("/engines", s.handleEngines)
			// Operator-selectable core versions (FP-ADAPT-014). A cores.go with
			// no admin. line here is the whole defect class this row exists in.
			admin.GET("/cores", s.handleListCores)
			admin.POST("/cores/:engine/pin", s.handlePinCore)
			admin.POST("/cores/:engine/rollback", s.handleRollbackCore)
			// Brook and AmneziaWG are not supervised subprocesses, so they do
			// not appear in /engines. Their status functions existed with no
			// route at all, which is why an operator running either of them saw
			// an engines list that did not mention them.
			admin.GET("/engines/aux", s.handleAuxEngineStatus)
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
			// Domains registry (BUG-3): CRUD + no-domain guidance + one-click paths.
			admin.GET("/domains", s.handleListDomains)
			admin.POST("/domains", s.handleCreateDomain)
			admin.PUT("/domains/:id", s.handleUpdateDomain)
			admin.DELETE("/domains/:id", s.handleDeleteDomain)
			admin.GET("/domains-status", s.handleDomainStatus)
			admin.POST("/inbounds/reality-quickstart", s.handleRealityQuickstart)
			admin.POST("/inbounds/paas-quickstart", s.handlePaaSQuickstart)
			admin.POST("/wizard/preset", s.handlePresetWizard)
			// Ask every prerequisite up front, so a failing setup is one round of
			// fixes rather than one per attempt. Writes nothing.
			admin.POST("/wizard/preset/preflight", s.handlePresetPreflight)
			admin.POST("/inbounds/:id/tls", s.handleInboundOneClickTLS)
			admin.POST("/certs/import", s.handleCertImport)
			admin.POST("/certs/issue", s.handleCertIssueDNS01)
			admin.GET("/certs", s.handleCertList)
			admin.GET("/nodes", s.handleListNodes)
			admin.POST("/nodes/enroll", s.handleEnrollNode)
			// Take a node out of service, and put it back. Enforced at the
			// heartbeat, not painted on the list — see handleSetNodeState.
			admin.PATCH("/nodes/:id", s.handleSetNodeState)
			// The node's own core output, live. Authenticated by the query token
			// the WebSocket handshake carries, because a browser cannot set an
			// Authorization header on `new WebSocket()`; see auth.bearer.
			admin.GET("/nodes/:id/logs", s.handleNodeLogsStream)
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
			// The bot token is a bearer credential for the bot; owner-only, like
			// every other panel-level secret. /api/admin/settings already
			// resolves to ownerOnly in the authz table.
			admin.GET("/settings/telegram", s.handleGetTelegramSettings)
			admin.POST("/settings/telegram", s.handleSetTelegramSettings)
			admin.POST("/settings/telegram/test", s.handleTestTelegram)
			// Webhook secrets sign deliveries a receiver acts on, so they are
			// panel-level credentials like the bot token and land under the
			// same owner-only /api/admin/settings prefix.
			admin.GET("/settings/webhooks", s.handleListWebhooks)
			admin.POST("/settings/webhooks", s.handleCreateWebhook)
			admin.PUT("/settings/webhooks/:id", s.handleUpdateWebhook)
			admin.DELETE("/settings/webhooks/:id", s.handleDeleteWebhook)
			admin.POST("/settings/webhooks/:id/test", s.handleTestWebhook)
			// The secret key is a bearer credential for a bucket holding the
			// panel's whole state — the database, the master key and every
			// certificate — so it belongs under the same owner-only
			// /api/admin/settings prefix as the bot token.
			admin.GET("/settings/backup/s3", s.handleGetBackupS3Settings)
			admin.POST("/settings/backup/s3", s.handleSetBackupS3Settings)
			admin.POST("/settings/backup/s3/test", s.handleTestBackupS3)
			admin.GET("/settings/egress", s.handleGetEgressSettings)
			admin.POST("/settings/egress", s.handleSetEgressSettings)
			admin.POST("/settings/egress/test", s.handleTestEgress)
			// What this panel can be told, described by the panel. Without it the
			// UI has to carry its own copy of every enum and default.
			admin.GET("/settings/registry", s.handleSettingsRegistry)
			// And what this panel can be ASKED, described by the panel: the
			// endpoint surface itself, generated from this router at request
			// time. It must be built per request, not here — routes() registers
			// top to bottom, so a document snapshotted at this line would omit
			// every route below it.
			admin.GET("/openapi.json", s.handleOpenAPI)
			admin.GET("/settings/subscription", s.handleGetSubSettings)
			admin.POST("/settings/subscription", s.handleSetSubSettings)
			admin.GET("/settings/nettune", s.handleGetNetTune)
			admin.POST("/settings/nettune", s.handleSetNetTune)
			admin.GET("/geoip", s.handleGeoIP)
			admin.GET("/panel-address", s.handlePanelAddress)
			admin.POST("/panel-address", s.handlePanelAddressUpdate)
			admin.GET("/panel-address/dns-check", s.handlePanelDNSCheck)
			admin.GET("/panel-address/port-check", s.handlePanelPortCheck)
			admin.POST("/panel-address/cert/renew", s.handlePanelCertRenew)
			// Panel self-update. Read and STAGE only: applying stays with the
			// installer because ProtectSystem=full makes /usr/local/bin
			// read-only to this process (packaging/systemd/forgepanel.service).
			admin.GET("/update", s.handleUpdateCheck)
			admin.POST("/update/channel", s.handleUpdateChannel)
			admin.POST("/update/stage", s.handleUpdateStage)
		}
	}

	// Subscription endpoint (spec §9): format auto-detect by UA + explicit
	// suffix. DB-backed when a store is attached, else the in-memory demo store.
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)

	// ForgeEdge PULL feed (§6): the Worker's cron fetches this with the token
	// minted at /api/admin/edge/feed-token. Token-authenticated rather than
	// session-authenticated, because the caller is a Worker, not a browser.
	if s.db != nil {
		r.GET("/api/edge/feed", s.handleEdgeFeed)
	}

	// Node agent endpoints (token-authenticated, spec §10).
	if s.db != nil {
		r.POST("/api/node/bootstrap", s.handleNodeBootstrap)
		r.POST("/api/node/renew", s.handleNodeRenew)
		r.POST("/api/node/register", s.handleNodeRegister)
		r.POST("/api/node/heartbeat", s.handleNodeHeartbeat)
		r.GET("/node-install.sh", s.handleNodeInstallScript)
		// Alias: the Node Cluster UI hands out /api/node/install.sh, so serve the
		// enrollment script there too (the bare /node-install.sh stays as well).
		r.GET("/api/node/install.sh", s.handleNodeInstallScript)
		// The agent binary itself. The enrollment script downloads it from here
		// rather than a release URL so the agent always matches the panel that
		// will drive it — the two speak a private heartbeat and config schema.
		r.GET("/api/node/agent", s.handleNodeAgent)
		r.GET("/api/node/agent/sha256", s.handleNodeAgentDigest)
	}

	// The panel at root and at the randomized admin path. ONE shell, the panel's
	// own — web/index.html.
	//
	// This read used to name web/admin.html, the shell of a second, reduced panel
	// that lived at /admin, and that is the line the whole clean-up turns on.
	// adapter-static emits one shell per prerendered route, so deleting that route
	// stops admin.html being generated — and assetOr discards the read error and
	// returns its fallback, which was the Config Studio's shell, itself about to
	// disappear for the same reason. The panel would have come up serving the stub
	// "The Config Studio asset was not embedded in this build" at /, at the secret
	// path, and on every client-side route, with no build error, no failing test
	// and no log line. A blackout that compiles.
	//
	// The fallback is now the panel's own no-asset message rather than another
	// page, so a bundle built without the frontend says so instead of silently
	// serving something else.
	adminPage := s.assetOr("web/index.html", panelAssetMissing)
	serveAdmin := func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", adminPage) }
	r.GET("/", serveAdmin)
	// /studio was a mock page — it built a config client-side and never called
	// the preview endpoint. The real Config Studio is a tab inside the panel, so
	// an old bookmark is sent there rather than to a page that no longer exists.
	r.GET("/studio", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, s.studioTabURL())
	})
	if s.cfg.AdminPath != "" && s.cfg.AdminPath != "/" {
		// Serve the panel at "<path>/" and redirect the bare "<path>" to it. The
		// SvelteKit shell derives its base from `new URL(".", location)`; opened at
		// "/panel/<secret>" (no trailing slash) that base collapses to "/panel", so
		// the router looks for a route named after the secret segment and mounts
		// nothing — a blank page. With the trailing slash the base is the full
		// secret path and the route is "/", so the app mounts and its relative
		// "./_app/…" assets resolve under the secret path (served by serveSPA).
		r.GET(s.cfg.AdminPath, func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, s.cfg.AdminPath+"/")
		})
		r.GET(s.cfg.AdminPath+"/", serveAdmin)
	}
	// ForgeDNS admin page — clickable tunnel management, no terminal (spec §5).
	if s.db != nil {
		fdnsPage := s.assetOr("web/forgedns.html", "")
		r.GET("/forgedns", func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", fdnsPage) })
	}

	// Serve the SvelteKit build's static assets (/_app/immutable/…, favicon, …)
	// and fall back to the SPA entry for client-side routes. Without this the
	// panel's HTML loaded but every /_app/*.js and *.css returned 404, so the UI
	// was completely dead — the single most important thing the panel does.
	r.NoRoute(s.serveSPA(adminPage))
}

// serveSPA returns the catch-all handler for the embedded SvelteKit build: a
// real file under web/ is served with its correct content type; an /api/* miss
// stays a JSON 404; anything else is a client-side route and gets the SPA entry.
func (s *Server) serveSPA(entry []byte) gin.HandlerFunc {
	sub, _ := fs.Sub(webFS, "web")
	return func(c *gin.Context) {
		p := strings.TrimPrefix(path.Clean(c.Request.URL.Path), "/")
		if strings.HasPrefix(p, "api/") {
			fail(c, http.StatusNotFound, "not found")
			return
		}
		// SvelteKit references its content-hashed bundle relatively ("./_app/…"),
		// so when the panel is opened under /panel/<secret>/ the browser requests
		// /panel/<secret>/_app/…. Those files live at web/_app/… in the embed FS;
		// serve them by their "_app/…" suffix regardless of the leading path, or
		// the secret-path prefix turns every script into the SPA shell and the
		// browser rejects it as a bad module — a blank panel.
		if i := strings.Index(p, "_app/"); i >= 0 {
			if b, err := fs.ReadFile(sub, p[i:]); err == nil {
				c.Data(http.StatusOK, contentTypeFor(p), b)
				return
			}
		}
		if p != "" {
			if b, err := fs.ReadFile(sub, p); err == nil {
				c.Data(http.StatusOK, contentTypeFor(p), b)
				return
			}
		}
		// Client-side route (e.g. /admin, /users): serve the SPA entry so the
		// router can take over.
		c.Data(http.StatusOK, "text/html; charset=utf-8", entry)
	}
}

// contentTypeFor maps a static asset's extension to its MIME type. The immutable
// SvelteKit bundle is mostly .js and .css; getting these right matters because a
// browser refuses to execute a script served as text/plain.
func contentTypeFor(p string) string {
	switch {
	case strings.HasSuffix(p, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(p, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".png"):
		return "image/png"
	case strings.HasSuffix(p, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(p, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// --- /api/protocols -------------------------------------------------------

type protoMeta struct {
	Proto      string   `json:"proto"`
	Label      string   `json:"label"`
	Transports []string `json:"transports"`
	Securities []string `json:"securities"`
	Engine     string   `json:"engine"`
	// ServesInbound is false for a protocol the panel can only DIAL, never
	// listen on. Without it the UI offered SSH as an inbound protocol that no
	// core can serve, and the resulting inbound sat in the database serving
	// nobody.
	ServesInbound bool `json:"serves_inbound"`
	// ServesHere is false for a protocol this DEPLOYMENT cannot serve, as
	// opposed to one the panel cannot serve anywhere. Behind a platform edge
	// that is most of the catalogue, and a form that offers the full list there
	// is offering choices that end in an inbound carrying nothing.
	ServesHere bool `json:"serves_here"`
	// HereNote says why, when ServesHere is false.
	HereNote string `json:"here_note,omitempty"`
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
		m := protoMeta{Proto: string(p), Label: labels[p], Engine: render.EngineFor(p),
			// Published so the UI does not offer a protocol the panel cannot
			// serve. SSH is dialable as an egress hop and cannot be an inbound:
			// sing-box has an SSH outbound and no SSH inbound.
			ServesInbound: render.ServesInbound(p)}
		if p.UsesTransport() {
			m.Transports = transportsAll
			m.Securities = securitiesAll
		} else if p.IsQUICBased() {
			m.Securities = []string{string(model.SecTLS)}
		}
		// Behind a platform edge, narrow the catalogue to what can actually be
		// served here — and narrow the TRANSPORT list too, not just the
		// protocol list. VLESS is servable, and VLESS over tcp is not; a form
		// that offers the protocol but every transport still leads the operator
		// straight into an inbound that cannot work.
		m.ServesHere, m.HereNote = s.paasProtocolSupport(p)
		if m.ServesHere && len(m.Transports) > 0 {
			m.Transports = s.paasNarrowTransports(p, m.Transports)
			m.Securities = s.paasNarrowSecurities(m.Securities)
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
		// Named because they were MEASURED to fail, not because they look
		// unlikely. www.microsoft.com serves an 8126-byte certificate chain and
		// REALITY cannot relay a borrowed handshake that large: the client
		// authenticates correctly and the tunnel then carries nothing, with
		// every field of the config looking right. See internal/realityprobe.
		//
		// This stays a cheap static hint; /api/admin/reality/dest-probe is the
		// authority and actually connects. The previous version of this list
		// blocked www.amazon.com, which works fine.
		measuredBad := []string{"microsoft.com", "www.microsoft.com"}
		for _, bad := range measuredBad {
			if strings.Contains(dest, bad) {
				f = append(f, PreviewFinding{"warn", "REALITY dest '" + dest + "' has a certificate chain too large for REALITY to relay, so the tunnel will authenticate and then carry nothing. Use www.cloudflare.com, www.apple.com, gateway.icloud.com, addons.mozilla.org, www.amazon.com or dl.google.com — or probe your own with /api/admin/reality/dest-probe."})
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
		fail(c, 400, "unknown keygen kind: "+req.Kind)
	}
}

// respond answers with v, or with err.
//
// It used to answer EVERY error 400 with a bare string. That flattened a typed
// failure — a *dns.Error that knows it is a missing zone and knows which token
// permission would have found it — into "Bad Request" with the remediation
// deleted. The status now comes from the error itself; 400 is only the fallback
// for an error that carries no classification of its own.
func respond(c *gin.Context, v any, err error) {
	if err != nil {
		apierr.FailStatus(c, http.StatusBadRequest, err)
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
		failErr(c, 400, err)
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
