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
			_, why := paasRoutable(tc.node)
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
