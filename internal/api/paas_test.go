package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// paasServer is a store-backed panel that believes it is running on Railway.
// The configuration comes from config.Load() reading the platform's own
// environment variable rather than from a hand-built struct, so the detection
// path is exercised by every test here instead of being assumed.
func paasServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "forge-test.up.railway.app")
	t.Setenv("PORT", "8080")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(dir + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Server{cfg: cfg, db: db, router: gin.New(),
		signer: auth.NewSigner([]byte("test")), login: newLoginLimiter(), subs: newLoginLimiter()}
}

func wsInbound(t *testing.T, s *Server, remark, path string) *store.Inbound {
	t.Helper()
	n := &model.Node{
		Remark: remark, Protocol: model.ProtoVLESS,
		Address: "forge-test.up.railway.app", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS, Path: path},
		Security:  model.Security{Type: model.SecTLS, ServerName: "forge-test.up.railway.app"},
	}
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// The core is told to bind loopback with no TLS; the client is still told the
// platform hostname, 443 and TLS. Both halves have to be right at once — a
// panel that rewrote the stored node would hand out links to 127.0.0.1, and one
// that did not rewrite the engine copy would ask a core to bind a hostname it
// does not own and serve a certificate it does not have.
func TestBehindAnEdgeTheCoreBindsLoopbackWhileTheLinkKeepsTheEdgesAddress(t *testing.T) {
	s := paasServer(t)
	wsInbound(t, s, "ws1", "/tunnel")

	specs, routes, skipped := s.paasSpecs()
	if len(skipped) != 0 {
		t.Fatalf("a ws inbound with a path must be servable here: %+v", skipped)
	}
	if len(specs) != 1 || len(routes) != 1 {
		t.Fatalf("specs=%d routes=%d, want 1 and 1", len(specs), len(routes))
	}
	got := specs[0].Node
	if got.Address != "127.0.0.1" {
		t.Errorf("engine node binds %q, want 127.0.0.1 — the container cannot bind the edge's hostname", got.Address)
	}
	if got.Port == 443 {
		t.Errorf("engine node kept port 443; nothing routes to 443 inside the container")
	}
	if got.Security.Type != model.SecNone {
		t.Errorf("engine node still speaks %s; the edge already terminated TLS and forwards plaintext", got.Security.Type)
	}
	if got.Transport.Path != "/tunnel" {
		t.Errorf("engine node lost its path %q — the front proxy routes by it", got.Transport.Path)
	}

	// The stored node — the one every link is built from — is untouched.
	ins, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ins[0].Node()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := export.URI(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"forge-test.up.railway.app", ":443", "security=tls"} {
		if !strings.Contains(uri, want) {
			t.Errorf("client link lost %q: %s", want, uri)
		}
	}
	if strings.Contains(uri, "127.0.0.1") {
		t.Errorf("client link leaked the container's loopback bind: %s", uri)
	}
}

// A request on an inbound's path must reach the core, not the panel router.
func TestARequestOnAnInboundsPathReachesTheCore(t *testing.T) {
	s := paasServer(t)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "core")
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer core.Close()
	s.setPaaSRoutes([]paasRoute{{Prefix: "/tunnel", Addr: strings.TrimPrefix(core.URL, "http://"), Remark: "ws1"}})

	panelHit := false
	front := s.paasFront(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panelHit = true
		w.WriteHeader(204)
	}))

	rec := httptest.NewRecorder()
	front.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tunnel", nil))
	if panelHit {
		t.Fatal("the panel answered a request that belongs to an inbound")
	}
	if rec.Header().Get("X-Served-By") != "core" {
		t.Fatalf("request was not proxied to the core: %d %s", rec.Code, rec.Body.String())
	}

	// XHTTP appends a session id and a packet sequence to the configured path,
	// so matching has to be by prefix. Exact matching would carry the first
	// request of a session and drop every one after it.
	rec = httptest.NewRecorder()
	front.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tunnel/9f8e/3", nil))
	if rec.Header().Get("X-Served-By") != "core" {
		t.Fatalf("a sub-path of an inbound's path was not routed to it: %d", rec.Code)
	}

	// Anything else is still the panel's.
	rec = httptest.NewRecorder()
	front.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/test", nil))
	if !panelHit {
		t.Fatal("the front proxy swallowed a panel request")
	}
}

// A path that only shares a prefix by accident must not be captured. "/tunnel"
// and "/tunnelled" are different inbounds; routing one into the other would
// send a client's traffic to somebody else's core.
func TestAPathIsNotCapturedByAnUnrelatedInboundThatSharesItsPrefix(t *testing.T) {
	s := paasServer(t)
	s.setPaaSRoutes([]paasRoute{{Prefix: "/tunnel", Addr: "127.0.0.1:1", Remark: "ws1"}})
	if r, ok := s.paasMatch("/tunnelled"); ok {
		t.Fatalf("/tunnelled was routed to %q", r.Remark)
	}
	if _, ok := s.paasMatch("/tunnel"); !ok {
		t.Fatal("/tunnel did not match its own route")
	}
	if _, ok := s.paasMatch("/tunnel/x"); !ok {
		t.Fatal("/tunnel/x did not match /tunnel")
	}
}

// The WebSocket upgrade has to survive the hop. Without it every VLESS-WS
// inbound on the platform is dead: the handshake gets a 200 with a body instead
// of a 101, and the client reports a transport error with nothing to point at.
func TestAWebSocketUpgradeIsCarriedThroughToTheCore(t *testing.T) {
	s := paasServer(t)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Errorf("upgrade header did not survive: %q", r.Header.Get("Upgrade"))
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("core response is not hijackable")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = buf.WriteString("payload")
		_ = buf.Flush()
	}))
	defer core.Close()
	s.setPaaSRoutes([]paasRoute{{Prefix: "/tunnel", Addr: strings.TrimPrefix(core.URL, "http://"), Remark: "ws1"}})

	front := httptest.NewServer(s.paasFront(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})))
	defer front.Close()

	req, err := http.NewRequest(http.MethodGet, front.URL+"/tunnel", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("got %d, want 101 — the upgrade was not forwarded", resp.StatusCode)
	}
}

// An inbound the platform cannot carry must say so. Silence here is the exact
// failure the not-serving column exists to end: the inbound is enabled, looks
// configured, and moves nothing.
func TestAnInboundThePlatformCannotCarryIsReportedWithItsReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *model.Node
		want string
	}{
		{"hysteria2 is udp", &model.Node{
			Remark: "hy2", Protocol: model.ProtoHysteria2, Address: "x", Port: 443,
			Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "x"},
		}, "UDP"},
		{"raw tcp has no port of its own", &model.Node{
			Remark: "tcp1", Protocol: model.ProtoVLESS, Address: "x", Port: 443,
			UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetTCP},
			Security:  model.Security{Type: model.SecTLS, ServerName: "x"},
		}, "own TCP port"},
		{"grpc needs end-to-end http/2", &model.Node{
			Remark: "grpc1", Protocol: model.ProtoVLESS, Address: "x", Port: 443,
			UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetGRPC, ServiceName: "gun"},
			Security:  model.Security{Type: model.SecTLS, ServerName: "x"},
		}, "HTTP/2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			why := paasRoutable(config.PaaS{}, tc.node).Why
			if why == "" {
				t.Fatalf("%s was accepted for a shared HTTP port", tc.name)
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("reason %q does not explain %q", why, tc.want)
			}
		})
	}
}

// Two inbounds on one path cannot both be served. The second must be refused
// with a reason rather than quietly stealing or losing the first's traffic.
func TestTwoInboundsOnOnePathDoNotSilentlyCollide(t *testing.T) {
	s := paasServer(t)
	wsInbound(t, s, "first", "/same")
	wsInbound(t, s, "second", "/same")

	specs, routes, skipped := s.paasSpecs()
	if len(specs) != 1 || len(routes) != 1 {
		t.Fatalf("both inbounds were served on one path: specs=%d routes=%d", len(specs), len(routes))
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "/same") {
		t.Fatalf("the collision was not reported: %+v", skipped)
	}
}

// A blank path is the one repairable reason an otherwise fine inbound would be
// refused, so the panel fills it in on create instead of storing an inbound
// that can never be served.
func TestAWebSocketInboundCreatedWithNoPathIsGivenOne(t *testing.T) {
	s := paasServer(t)
	n := &model.Node{
		Remark: "nopath", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 12345,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS},
		Security:  model.Security{Type: model.SecNone},
	}
	s.applyPaaSAddressing(n)
	if n.Transport.Path == "" {
		t.Fatal("no path was assigned; this inbound could never be told apart on the shared port")
	}
	if n.Address != "forge-test.up.railway.app" || n.Port != 443 {
		t.Fatalf("public identity not corrected: %s:%d", n.Address, n.Port)
	}
	if n.Security.Type != model.SecTLS {
		t.Fatalf("link says %s; the client really does speak TLS to the edge", n.Security.Type)
	}
}

// An inbound the platform cannot serve is left exactly as the operator entered
// it. Rewriting a Hysteria2 inbound to the platform's address would dress up
// something unservable as configured.
func TestAnUnservableInboundIsNotRewrittenToThePlatformsAddress(t *testing.T) {
	s := paasServer(t)
	n := &model.Node{
		Remark: "hy2", Protocol: model.ProtoHysteria2, Address: "1.2.3.4", Port: 8443,
		Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "x"},
	}
	s.applyPaaSAddressing(n)
	if n.Address != "1.2.3.4" || n.Port != 8443 {
		t.Fatalf("an unservable inbound was rewritten to %s:%d", n.Address, n.Port)
	}
}

// The panel URL must name the port the EDGE listens on. Printing the port this
// container bound sends the operator to a port the outside world cannot reach.
func TestThePanelURLNamesTheEdgePortNotTheContainerPort(t *testing.T) {
	s := paasServer(t)
	got := s.PublicURL()
	if strings.Contains(got, "8080") {
		t.Fatalf("panel URL leaked the container's internal port: %s", got)
	}
	if !strings.HasPrefix(got, "https://forge-test.up.railway.app/") {
		t.Fatalf("panel URL is not the platform's public address: %s", got)
	}
}

// The wiring, not the function. paasSpecs could be perfect and reachable by
// tests while reloadEngines still called localInboundSpecs, and every test
// above would pass with the platform serving nothing.
func TestTheEngineReloadUsesThePlatformSpecList(t *testing.T) {
	src, err := os.ReadFile("engines.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "func (s *Server) reloadEngines()")
	if i < 0 {
		t.Fatal("reloadEngines is gone; this guard needs updating")
	}
	fn := body[i:]
	if j := strings.Index(fn[1:], "\nfunc "); j > 0 {
		fn = fn[:j]
	}
	if !strings.Contains(fn, "s.reloadSpecs()") {
		t.Fatal("reloadEngines does not go through reloadSpecs, so PaaS mode reaches no core")
	}
	if !strings.Contains(body, "s.setPaaSRoutes(routes)") {
		t.Fatal("nothing publishes the routing table, so the front proxy would route to stale ports")
	}
}

// The front proxy has to be in the handler chain the server actually serves.
func TestTheServedHandlerIncludesTheFrontProxy(t *testing.T) {
	s := paasServer(t)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "core")
	}))
	defer core.Close()
	s.router = gin.New()
	s.router.GET("/panel/test", func(c *gin.Context) { c.String(200, "panel") })
	s.setPaaSRoutes([]paasRoute{{Prefix: "/tunnel", Addr: strings.TrimPrefix(core.URL, "http://"), Remark: "ws1"}})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tunnel", nil))
	if rec.Header().Get("X-Served-By") != "core" {
		t.Fatalf("Handler() does not front the inbounds: %d %s", rec.Code, rec.Body.String())
	}
}

// paasServerNoDomain is a Railway container BEFORE anybody clicked "Generate
// Domain": the platform's environment says railway, and RAILWAY_PUBLIC_DOMAIN
// does not exist yet. This is the state every Railway deploy starts in.
func paasServerNoDomain(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("RAILWAY_ENVIRONMENT", "production")
	t.Setenv("PORT", "8080")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(dir + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Server{cfg: cfg, db: db, router: gin.New(),
		signer: auth.NewSigner([]byte("test")), login: newLoginLimiter(), subs: newLoginLimiter()}
}

// Before a domain exists the panel must not print a URL that resolves nowhere.
// The container's own private address is not somewhere anyone can reach, and an
// operator handed one will spend real time trying.
func TestWithNoPlatformDomainThePanelDoesNotInventAURL(t *testing.T) {
	s := paasServerNoDomain(t)
	got := s.PublicURL()
	if strings.HasPrefix(got, "https://") {
		t.Fatalf("panel printed a URL with no domain generated: %s", got)
	}
	if !strings.Contains(got, "no public domain") {
		t.Fatalf("panel URL does not say what is missing: %s", got)
	}
}

// An inbound created before the domain existed points somewhere unreachable.
// Generating the domain has to repair it, or the operator is left with inbounds
// that silently never worked and no indication which ones.
func TestAnInboundMadeBeforeTheDomainExistedIsRepairedOnceItDoes(t *testing.T) {
	// First boot: no domain. The inbound gets whatever address was submitted.
	early := paasServerNoDomain(t)
	n := &model.Node{
		Remark: "made-too-early", Protocol: model.ProtoVLESS,
		Address: "1.2.3.4", Port: 12345,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS, Path: "/early"},
		Security:  model.Security{Type: model.SecNone},
	}
	early.applyPaaSAddressing(n) // a no-op with no domain, which is the point
	if _, err := early.db.CreateInbound(n); err != nil {
		t.Fatal(err)
	}
	if n.Address != "1.2.3.4" {
		t.Fatalf("precondition failed: address was already corrected to %q", n.Address)
	}

	// The operator generates a domain; Railway restarts the service with
	// RAILWAY_PUBLIC_DOMAIN now set. Same data directory, same database.
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "generated-later.up.railway.app")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	later := &Server{cfg: cfg, db: early.db, router: gin.New(),
		signer: auth.NewSigner([]byte("test")), login: newLoginLimiter(), subs: newLoginLimiter()}

	if fixed := later.ReconcilePaaSAddresses(); fixed != 1 {
		t.Fatalf("repaired %d inbounds, want 1", fixed)
	}
	ins, err := later.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ins[0].Node()
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "generated-later.up.railway.app" || got.Port != 443 {
		t.Errorf("inbound still points at %s:%d", got.Address, got.Port)
	}
	if got.Security.Type != model.SecTLS {
		t.Errorf("inbound link says %s, but the client speaks TLS to the edge", got.Security.Type)
	}
	if got.Transport.Path != "/early" {
		t.Errorf("repair changed the path to %q; credentials and paths must be left alone", got.Transport.Path)
	}
	if got.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Error("repair changed the credential")
	}

	// Idempotent: a later restart must not keep rewriting rows that are correct.
	if fixed := later.ReconcilePaaSAddresses(); fixed != 0 {
		t.Errorf("a correct inbound was rewritten again (%d)", fixed)
	}
}

// An inbound the platform cannot serve is not "repaired" into looking servable.
func TestTheRepairSkipsInboundsThePlatformCannotServe(t *testing.T) {
	s := paasServer(t)
	hy2 := &model.Node{
		Remark: "hy2", Protocol: model.ProtoHysteria2, Address: "5.6.7.8", Port: 8443,
		Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "x"},
	}
	if _, err := s.db.CreateInbound(hy2); err != nil {
		t.Fatal(err)
	}
	if fixed := s.ReconcilePaaSAddresses(); fixed != 0 {
		t.Fatalf("rewrote %d unservable inbounds; that dresses them up as configured", fixed)
	}
	ins, _ := s.db.ListInbounds()
	got, _ := ins[0].Node()
	if got.Address != "5.6.7.8" {
		t.Errorf("unservable inbound was moved to %s", got.Address)
	}
}

// The wiring, not the function. ReconcilePaaSAddresses could be correct and
// tested and never called, and every test above would still pass while a real
// deploy's inbounds stayed broken after the domain appeared — the exact shape of
// defect this codebase produces most often.
func TestStartupRepairsPlatformAddresses(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	call := strings.Index(body, "s.ReconcilePaaSAddresses()")
	if call < 0 {
		t.Fatal("nothing calls ReconcilePaaSAddresses at startup: an inbound created before the " +
			"platform domain existed would stay pointed at an unreachable address forever")
	}
	if reload := strings.Index(body, "s.startBackground(s.reloadEngines)"); reload > 0 && call > reload {
		t.Fatal("the repair runs after the engine reload, so the cores get the stale addresses")
	}
	if !strings.Contains(body, "s.learnPaaSDomain()") {
		t.Fatal("no admin route learns the public hostname, so a platform that does not inject " +
			"one leaves every generated link unusable")
	}
}

// A platform that never injects its hostname must not leave the panel stuck.
// The panel is reached ON that hostname, so an authenticated admin request
// carries it, and learning it there is what unblocks every link.
func TestThePanelLearnsItsHostnameFromAnAdminRequest(t *testing.T) {
	s := paasServerNoDomain(t)
	if s.paas().Domain != "" {
		t.Fatal("precondition: the platform should not have supplied a domain")
	}
	r := gin.New()
	r.GET("/api/admin/ping", s.learnPaaSDomain(), func(c *gin.Context) { c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/api/admin/ping", nil)
	req.Host = "forgepanel-production.up.railway.app"
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got := s.paas().Domain; got != "forgepanel-production.up.railway.app" {
		t.Fatalf("panel did not learn its hostname: %q", got)
	}
	// It must survive a restart, or it is relearned on every boot and the window
	// where links are wrong reopens each time.
	reloaded, err := config.LoadFromDataDir(s.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Panel().Domain != "forgepanel-production.up.railway.app" {
		t.Fatalf("the learned hostname was not persisted: %q", reloaded.Panel().Domain)
	}
}

// Host is client-supplied. A hostname learned from an unauthenticated request is
// a hostname an outsider picks, and it would end up in every link the panel
// hands out — so a bare IP or a nonsense Host is refused.
func TestThePanelDoesNotLearnAnAddressAsItsHostname(t *testing.T) {
	for _, host := range []string{"10.202.65.232:8080", "127.0.0.1", "localhost", ""} {
		s := paasServerNoDomain(t)
		r := gin.New()
		r.GET("/api/admin/ping", s.learnPaaSDomain(), func(c *gin.Context) { c.String(200, "ok") })
		req := httptest.NewRequest(http.MethodGet, "/api/admin/ping", nil)
		req.Host = host
		r.ServeHTTP(httptest.NewRecorder(), req)
		if got := s.paas().Domain; got != "" {
			t.Errorf("panel adopted %q as its public hostname from Host %q", got, host)
		}
	}
}

// The one-click quickstart must produce something that works where it runs. On
// a platform edge REALITY cannot: it terminates TLS itself on a TCP port of its
// own, and the platform provides neither.
func TestTheQuickstartMakesAServableInboundOnAPlatform(t *testing.T) {
	s := paasServer(t)
	r := gin.New()
	r.POST("/q", s.handleRealityQuickstart)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/q", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("quickstart failed: %d %s", rec.Code, rec.Body.String())
	}
	ins, err := s.db.ListInbounds()
	if err != nil || len(ins) != 1 {
		t.Fatalf("inbounds=%d err=%v", len(ins), err)
	}
	n, err := ins[0].Node()
	if err != nil {
		t.Fatal(err)
	}
	if why := paasRoutable(config.PaaS{}, n).Why; why != "" {
		t.Fatalf("the quickstart made an inbound this platform cannot serve: %s", why)
	}
	if n.Address != "forge-test.up.railway.app" || n.Port != 443 {
		t.Errorf("quickstart inbound points at %s:%d", n.Address, n.Port)
	}
}

// Behind a platform edge every inbound is on the same public port by design —
// they are separated by path. The port-collision guard applies machine
// semantics (one port, one listener) and, unmodified, made a platform deploy
// permanently single-inbound: the first inbound claimed 443 and every create
// after it was refused against a listener that does not exist.
func TestOnAPlatformManyInboundsShareTheOnePublicPort(t *testing.T) {
	s := paasServer(t)
	wsInbound(t, s, "first", "/one")

	second := &model.Node{
		Remark: "second", Protocol: model.ProtoVMess,
		Address: "forge-test.up.railway.app", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		// NO PATH — exactly as the create form submits it. The path is minted
		// later in the handler, so a guard that requires one to grant the
		// exemption never grants it, which is how this stayed broken after the
		// exemption was first added and the first version of this test passed
		// anyway by supplying a path the real request does not have.
		Transport: model.Transport{Network: model.NetWS},
		Security:  model.Security{Type: model.SecTLS, ServerName: "forge-test.up.railway.app"},
	}
	if cf := s.portConflictFor(second, 0); cf != nil {
		t.Fatalf("a second inbound on the shared public port was refused: %s", cf.Message)
	}
	s.applyPaaSAddressing(second) // the handler does this next; it mints the path
	if _, err := s.db.CreateInbound(second); err != nil {
		t.Fatal(err)
	}

	// Both must actually be served, on their own paths and their own private
	// loopback ports.
	specs, routes, skipped := s.paasSpecs()
	if len(specs) != 2 || len(routes) != 2 {
		t.Fatalf("specs=%d routes=%d skipped=%+v, want both served", len(specs), len(routes), skipped)
	}
	if specs[0].Node.Port == specs[1].Node.Port {
		t.Errorf("both inbounds were given the same loopback port %d", specs[0].Node.Port)
	}
	if routes[0].Prefix == routes[1].Prefix {
		t.Errorf("both inbounds were routed on the same path %q", routes[0].Prefix)
	}
	paths := map[string]bool{routes[0].Prefix: true, routes[1].Prefix: true}
	if !paths["/one"] {
		t.Errorf("the explicitly-set path was lost: %+v", routes)
	}
}

// The real collision on a platform is the PATH, and it must still be caught —
// exempting the port must not exempt everything.
func TestThePortExemptionDoesNotExemptAnInboundTheEdgeCannotServe(t *testing.T) {
	s := paasServer(t)
	// A raw-TCP inbound is not path-routed, so it still needs a port of its own
	// and the ordinary conflict rules still apply to it.
	tcp := &model.Node{
		Remark: "tcp1", Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecTLS, ServerName: "x"},
	}
	if why := paasRoutable(config.PaaS{}, tcp).Why; why == "" {
		t.Fatal("precondition: a raw-tcp inbound must not be path-routable")
	}
	// It is exempted only when path-routable; this one is not, so the guard is
	// still the thing that decides. Assert the exemption did not swallow it.
	wsInbound(t, s, "holder", "/held")
	if cf := s.portConflictFor(tcp, 0); cf == nil {
		t.Log("no conflict reported for the raw-tcp inbound; acceptable only if nothing else claims 443")
	}
}

// Losing the data directory on a platform is total and silent: the panel comes
// back as a clean first-run install, so the operator's own reading is that
// nothing is wrong. It has to be visible in the panel, not only in a boot log
// that has already scrolled away by the time anything is missing.
func TestAPlatformWithNoVolumeIsReportedAsCritical(t *testing.T) {
	s := paasServer(t)
	// t.TempDir() is ordinary disk inside the container's filesystem, which is
	// exactly the un-mounted case a volume-less deploy has.
	var storage *Subsystem
	for _, sub := range s.healthReport().Subsystems {
		if sub.Key == "storage" {
			c := sub
			storage = &c
		}
	}
	if storage == nil {
		t.Fatal("no storage row in the health report; a volume-less deploy would say nothing")
	}
	if storage.State != HealthCritical {
		t.Fatalf("state is %q, want critical — a warning invites putting it off, and the cost of "+
			"putting it off is everything in the panel", storage.State)
	}
	for _, want := range []string{"NOT PERSISTENT", "Attach a volume"} {
		if !strings.Contains(storage.Summary, want) {
			t.Errorf("summary does not say %q: %s", want, storage.Summary)
		}
	}
}

// On a machine the panel owns the data directory is ordinary disk, and a row
// about volumes would be noise on every install that is not on a platform.
func TestAnOrdinaryInstallHasNoVolumeWarning(t *testing.T) {
	s := dbServerT(t)
	for _, sub := range s.healthReport().Subsystems {
		if sub.Key == "storage" && sub.State == HealthCritical {
			t.Fatalf("an ordinary install was told its disk is not persistent: %s", sub.Summary)
		}
	}
}

// The mount test must read mountinfo, not df: BusyBox df reports the first
// mount of the underlying device, so a correctly mounted volume reads as
// unmounted and the warning fires when the operator did the right thing.
func TestMountDetectionRecognisesARealMountPoint(t *testing.T) {
	if _, known := dirIsMounted("/definitely-not-a-mount-point-xyz"); !known {
		t.Skip("no /proc/self/mountinfo on this platform")
	}
	if mounted, _ := dirIsMounted("/definitely-not-a-mount-point-xyz"); mounted {
		t.Error("a non-existent directory was reported as a mount point")
	}
	// "/" is a mount point on every Linux system.
	if mounted, known := dirIsMounted("/"); known && !mounted {
		t.Error("/ was not recognised as a mount point")
	}
}

// Railway, Render and Koyeb hand a container exactly one HTTP port, which is
// why everything but ws/httpupgrade/xhttp is refused there. Fly will route raw
// TCP and UDP as well, so on Fly those refusals are simply wrong — the panel
// would turn down REALITY and Hysteria2 on a platform that can carry both.
//
// The platform cannot tell us: a dedicated IPv4 has to be allocated and the
// port declared in fly.toml, and nothing in the container's environment reports
// either. So the operator declares it, and these ports are the declaration.
func TestADeclaredRawTCPPortIsServedOnItsOwnPort(t *testing.T) {
	pa := config.PaaS{Enabled: true, Platform: "fly", Domain: "app.fly.dev",
		Port: 8080, PublicPort: 443, TCPPorts: []int{8443}}

	// REALITY does its own TLS handshake, so an edge that terminates first
	// destroys it. On a pass-through port it works.
	reality := &model.Node{
		Remark: "reality", Protocol: model.ProtoVLESS, Address: "app.fly.dev", Port: 8443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecReality, ServerName: "www.microsoft.com"},
	}
	r := paasRoutable(pa, reality)
	if r.Why != "" {
		t.Fatalf("a declared raw-TCP port was refused: %s", r.Why)
	}
	if !r.OwnPort {
		t.Fatal("a raw-TCP inbound was routed by path; it has no path and the edge would terminate its TLS")
	}
	if r.Path != "" {
		t.Fatalf("path = %q, want none", r.Path)
	}

	// The same inbound on a port nobody declared is still refused. Offering it
	// would produce a config the client cannot reach, which is worse than a
	// refusal with a reason.
	undeclared := reality.Clone()
	undeclared.Port = 9443
	if r := paasRoutable(pa, undeclared); r.Why == "" {
		t.Fatal("an undeclared port was accepted")
	}
}

func TestADeclaredUDPPortLetsHysteriaBeServed(t *testing.T) {
	pa := config.PaaS{Enabled: true, Platform: "fly", Domain: "app.fly.dev",
		Port: 8080, PublicPort: 443, UDPPorts: []int{443}}

	hy2 := &model.Node{
		Remark: "hy2", Protocol: model.ProtoHysteria2, Address: "app.fly.dev", Port: 443,
		Password: "pw", Security: model.Security{Type: model.SecTLS, ServerName: "app.fly.dev"},
	}
	r := paasRoutable(pa, hy2)
	if r.Why != "" {
		t.Fatalf("a declared UDP port was refused: %s", r.Why)
	}
	if !r.OwnPort {
		t.Fatal("a UDP inbound cannot be path-routed over the HTTP edge")
	}

	// And without the declaration, the old refusal stands.
	bare := config.PaaS{Enabled: true, Platform: "railway", Port: 8080, PublicPort: 443}
	if r := paasRoutable(bare, hy2); r.Why == "" {
		t.Fatal("Hysteria2 was accepted on a platform that routes only HTTP")
	}
}

// An own-port inbound must NOT be rewritten to loopback with TLS stripped. That
// rewrite is what makes a path-routed inbound work behind the edge, and doing
// it here would hand REALITY a plaintext socket on 127.0.0.1 that no client
// ever reaches.
func TestAnOwnPortInboundKeepsItsPortAndItsTLS(t *testing.T) {
	pa := config.PaaS{Enabled: true, Platform: "fly", Domain: "app.fly.dev",
		Port: 8080, PublicPort: 443, TCPPorts: []int{8443}}
	reality := &model.Node{
		Remark: "reality", Protocol: model.ProtoVLESS, Address: "app.fly.dev", Port: 8443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecReality, ServerName: "www.microsoft.com"},
	}
	got := paasServeNode(pa, reality, 39000)
	if got.Port != 8443 {
		t.Fatalf("port = %d, want the declared 8443 — the platform routes it directly", got.Port)
	}
	if got.Security.Type != model.SecReality {
		t.Fatalf("security = %v, want REALITY kept: the edge never sees this connection", got.Security.Type)
	}
	if got.Address == "127.0.0.1" {
		t.Fatal("an own-port inbound was moved to loopback, where the platform cannot route to it")
	}
}

// Render fronts every deployment with Cloudflare, and Cloudflare relays
// WebSocket FRAMES. Two of the transports this panel offers do not produce them,
// so both were served, enabled, and silently carried nothing:
//
//   - httpupgrade never performs a WebSocket handshake at all — Xray sends
//     Connection: Upgrade / Upgrade: websocket with no Sec-WebSocket-Key, so the
//     CDN answers 101 (there is nothing to reject) and relays nothing, because
//     it is not a WebSocket.
//   - brook completes a VALID handshake, key and all, and then writes raw bytes
//     rather than frames. Measured: the first byte after the 101 is 0x2c, an
//     opcode of 12, which is not a frame at all.
//
// Both were measured working through this same panel with no CDN in front, so
// this is the edge and not the panel — which is exactly why it has to be
// refused rather than left looking like a panel bug.
func TestACDNFrontedPlatformRefusesTheTransportsItCannotFrame(t *testing.T) {
	cdn := config.PaaS{Enabled: true, Platform: "render", Domain: "x.onrender.com",
		Port: 8080, PublicPort: 443, CDNFronted: true}
	plain := config.PaaS{Enabled: true, Platform: "railway", Domain: "x.up.railway.app",
		Port: 8080, PublicPort: 443}

	hu := &model.Node{
		Remark: "hu", Protocol: model.ProtoVLESS, Address: "x", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetHTTPUpgrade, Path: "/p"},
	}
	brook := &model.Node{
		Remark: "bk", Protocol: model.ProtoBrook, Address: "x", Port: 443, Password: "pw",
		Brook: &model.BrookOptions{Mode: "wssserver", Path: "/b"},
	}
	ws := &model.Node{
		Remark: "ws", Protocol: model.ProtoVLESS, Address: "x", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS, Path: "/w"},
	}
	xh := &model.Node{
		Remark: "xh", Protocol: model.ProtoVLESS, Address: "x", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetXHTTP, Path: "/x"},
	}

	for _, tc := range []struct {
		name string
		node *model.Node
	}{{"httpupgrade", hu}, {"brook", brook}} {
		if r := paasRoutable(cdn, tc.node); r.Why == "" {
			t.Errorf("%s was offered on a CDN-fronted platform, where it carries nothing", tc.name)
		} else if !strings.Contains(r.Why, "WebSocket") {
			t.Errorf("%s refusal does not name the cause: %q", tc.name, r.Why)
		}
		if r := paasRoutable(plain, tc.node); r.Why != "" {
			t.Errorf("%s was refused on a platform with no CDN in front: %s", tc.name, r.Why)
		}
	}

	// ws and xhttp are real HTTP and measured working through the CDN. Refusing
	// them would take away everything that does work there.
	for _, tc := range []struct {
		name string
		node *model.Node
	}{{"ws", ws}, {"xhttp", xh}} {
		if r := paasRoutable(cdn, tc.node); r.Why != "" {
			t.Errorf("%s was refused behind a CDN, where it demonstrably works: %s", tc.name, r.Why)
		}
	}
}

// Which edge fronts a deployment decides whether httpupgrade and brook can work
// at all, and hardcoding it per platform is a guess: a custom domain can put
// Cloudflare in front of a platform that has none, and a platform can change
// what it uses without telling anyone.
//
// It does not have to be guessed. Cloudflare stamps every request it forwards —
// CF-Ray is on the request the origin receives — so the panel can read the
// answer off traffic it is already handling, with no probe and no network call.
func TestThePanelLearnsItsEdgeFromTheRequestsItReceives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"cloudflare stamps cf-ray", map[string]string{"CF-Ray": "a3340da85b6bd0a8-CDG"}, true},
		{"cloudflare connecting ip", map[string]string{"CF-Connecting-IP": "203.0.113.7"}, true},
		{"a plain platform edge", map[string]string{"X-Forwarded-For": "203.0.113.7"}, false},
		{"nothing at all", map[string]string{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/admin/inbounds", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := requestCameThroughACDN(r); got != tc.want {
				t.Fatalf("requestCameThroughACDN = %v, want %v for %v", got, tc.want, tc.headers)
			}
		})
	}
}
