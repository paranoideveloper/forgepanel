package api

import (
	"encoding/json"
	"github.com/forgepanel/forgepanel/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func quickstartAll(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST("/q", s.handlePaaSQuickstart)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/q", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	return rec
}

// One call must produce the whole set, and every entry must be one this
// platform can actually serve.
func TestTheQuickstartCreatesEveryConfigThePlatformCanCarry(t *testing.T) {
	s := paasServer(t)
	rec := quickstartAll(t, s)
	if rec.Code != 201 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != len(paasQuickstartSet) {
		t.Fatalf("created %d inbounds, want %d", len(ins), len(paasQuickstartSet))
	}
	for i := range ins {
		n, err := ins[i].Node()
		if err != nil {
			t.Fatal(err)
		}
		if why := paasRoutable(config.PaaS{}, n).Why; why != "" {
			t.Errorf("%s cannot be served here: %s", ins[i].Remark, why)
		}
		if n.Address != "forge-test.up.railway.app" || n.Port != 443 {
			t.Errorf("%s points at %s:%d", ins[i].Remark, n.Address, n.Port)
		}
	}
	// Every inbound needs its own path, or the later ones are refused at reload.
	specs, routes, skipped := s.paasSpecs()
	if len(skipped) != 0 {
		t.Fatalf("some generated configs cannot be served: %+v", skipped)
	}
	if len(specs) != len(paasQuickstartSet) || len(routes) != len(paasQuickstartSet) {
		t.Fatalf("specs=%d routes=%d", len(specs), len(routes))
	}
}

// Clicking twice must not pile up duplicates, each with its own credentials, on
// a panel the operator then has to weed by hand.
func TestTheQuickstartIsIdempotent(t *testing.T) {
	s := paasServer(t)
	quickstartAll(t, s)
	first, _ := s.db.ListInbounds()
	rec := quickstartAll(t, s)
	second, _ := s.db.ListInbounds()
	if len(second) != len(first) {
		t.Fatalf("a second click created %d more inbounds", len(second)-len(first))
	}
	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Error("the second run did not report what it skipped")
	}
}

// Shadowsocks belongs in the set on all three transports, and the three differ
// only in HOW you hand one to somebody.
//
// The platform routes all three, and the core serves all three. Over WebSocket
// there is a share link, through SIP003's plugin field. Over httpupgrade and
// xhttp there is no link — no SIP003 plugin implements those modes — but the
// Xray and JSON subscriptions carry a full client config and deliver them fine.
// "No share link" is not "does not work", and the set says which is which.
func TestShadowsocksIsOfferedOnEveryTransportWithItsDeliveryNamed(t *testing.T) {
	tiers := map[model.Network]ClientTier{}
	for _, e := range paasQuickstartSet {
		if e.Protocol == model.ProtoShadowsocks {
			tiers[e.Network] = e.Tier
		}
	}
	for _, want := range []model.Network{model.NetWS, model.NetHTTPUpgrade, model.NetXHTTP} {
		if _, ok := tiers[want]; !ok {
			t.Errorf("shadowsocks over %s is missing; the platform routes it and the core serves it", want)
		}
	}
	if tiers[model.NetWS] != TierPlugin {
		t.Errorf("ss+ws is %q; it needs a client carrying v2ray-plugin", tiers[model.NetWS])
	}
	for _, n := range []model.Network{model.NetHTTPUpgrade, model.NetXHTTP} {
		if tiers[n] != TierSubscriptionOnly {
			t.Errorf("ss+%s is %q; it has no share link and is delivered by subscription", n, tiers[n])
		}
	}
}

// Each entry has to say what can dial it. Handing over nine links without that
// means finding out which ones work by watching people fail to connect.
func TestEveryGeneratedConfigSaysWhatCanDialIt(t *testing.T) {
	s := paasServer(t)
	body := quickstartAll(t, s).Body.String()
	for _, want := range []string{"client_support", "universal", "xray-only", "sing-box", "subscription"} {
		if !strings.Contains(body, want) {
			t.Errorf("the response never mentions %q", want)
		}
	}
	// XHTTP is the trap: it is the newest and most attractive transport and the
	// one sing-box cannot dial at all.
	for _, e := range paasQuickstartSet {
		// XHTTP is Xray-core only for the protocols with a share link.
		// Shadowsocks over it has no link at all, which is a stricter statement,
		// so subscription-only is the accurate label rather than a wrong one.
		if e.Network == model.NetXHTTP && e.Protocol != model.ProtoShadowsocks && e.Tier != TierXrayOnly {
			t.Errorf("%s over xhttp is labelled %q; sing-box cannot dial XHTTP", e.Protocol, e.Tier)
		}
		if e.Network == model.NetXHTTP && e.Protocol == model.ProtoShadowsocks && e.Tier != TierSubscriptionOnly {
			t.Errorf("ss over xhttp is labelled %q; it has no share link at all", e.Tier)
		}
		// WebSocket is universal for the protocols a client dials natively.
		// Shadowsocks is the exception and not because of the transport: it
		// needs an external v2ray-plugin binary whatever it rides on.
		if e.Network == model.NetWS && e.Protocol != model.ProtoShadowsocks && e.Tier != TierUniversal {
			t.Errorf("%s over ws is labelled %q; WebSocket works everywhere", e.Protocol, e.Tier)
		}
	}
}

// Off-platform it must refuse rather than create nine inbounds that all claim
// port 443 on a machine where that means one listener.
func TestTheQuickstartRefusesOffPlatform(t *testing.T) {
	s := dbServerT(t)
	rec := quickstartAll(t, s)
	if rec.Code != 409 {
		t.Fatalf("status %d, want 409: %s", rec.Code, rec.Body.String())
	}
	// The REASON matters, not just the refusal. Both guards here return 409, so
	// asserting only the status cannot tell "not on a platform" from "no
	// hostname yet" — and an operator on a normal server told the second one
	// would go looking for a domain they do not need.
	if !strings.Contains(rec.Body.String(), "platform edge") {
		t.Errorf("refused for the wrong reason: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "owns its ports") {
		t.Errorf("the refusal does not say what to do instead: %s", rec.Body.String())
	}
	if n, _ := s.db.ListInbounds(); len(n) != 0 {
		t.Fatalf("created %d inbounds off-platform", len(n))
	}
}

// With no hostname yet, every generated link would be unreachable.
func TestTheQuickstartRefusesBeforeAHostnameExists(t *testing.T) {
	s := paasServerNoDomain(t)
	rec := quickstartAll(t, s)
	if rec.Code != 409 {
		t.Fatalf("status %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "hostname") {
		t.Error("the refusal does not say what is missing")
	}
}

// On a platform, an inbound the edge can never carry must be refused at the
// door rather than stored and marked not-serving afterwards.
//
// Marking it is right on a server the operator owns, where the reason might be
// something they can go and fix. Here nothing can be fixed — the platform routes
// one HTTP port — so the row would sit there looking configured, holding a
// minted credential, carrying nothing, forever.
func TestOnAPlatformAnUnservableInboundIsRefusedNotStored(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"hysteria2", `{"remark":"h","protocol":"hysteria2","port":443,"security":{"type":"tls"}}`, "UDP"},
		{"raw tcp vless", `{"remark":"t","protocol":"vless","port":443,"transport":{"network":"tcp"},"security":{"type":"tls"}}`, "its own TCP port"},
		{"grpc", `{"remark":"g","protocol":"vless","port":443,"transport":{"network":"grpc","service_name":"gun"},"security":{"type":"tls"}}`, "HTTP/2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := paasServer(t)
			r := gin.New()
			r.POST("/in", s.handleCreateInbound)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/in", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(rec, req)
			if rec.Code != 400 {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("refusal does not explain %q: %s", tc.want, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "supported") {
				t.Errorf("refusal does not say what IS possible: %s", rec.Body.String())
			}
			if ins, _ := s.db.ListInbounds(); len(ins) != 0 {
				t.Fatalf("stored %d unservable inbounds", len(ins))
			}
		})
	}
}

// The same inbound on a server that owns its ports must still be accepted —
// the restriction is a property of the deployment, not of the panel.
func TestOffPlatformTheSameInboundIsStillAccepted(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.POST("/in", s.handleCreateInbound)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/in",
		strings.NewReader(`{"remark":"h","protocol":"hysteria2","address":"1.2.3.4","port":8443,"security":{"type":"tls","server_name":"x"}}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("a normal install refused Hysteria2: %d %s", rec.Code, rec.Body.String())
	}
}

// The form must be offered only what works here — narrowed on TRANSPORT too,
// not just protocol. VLESS is servable and VLESS-over-tcp is not, so a
// protocol-only filter still walks the operator into a dead inbound.
func TestThePlatformCatalogueOffersOnlyWhatItCanServe(t *testing.T) {
	s := paasServer(t)
	r := gin.New()
	r.GET("/p", s.handleProtocols)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/p", nil))

	var metas []protoMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &metas); err != nil {
		t.Fatal(err)
	}
	here := map[string]protoMeta{}
	for _, m := range metas {
		if m.ServesHere {
			here[m.Proto] = m
		}
	}
	for _, want := range []string{"vless", "vmess", "trojan"} {
		m, ok := here[want]
		if !ok {
			t.Errorf("%s is not offered, but it works here", want)
			continue
		}
		if len(m.Transports) != 3 {
			t.Errorf("%s offers %v; only ws/httpupgrade/xhttp can be routed here", want, m.Transports)
		}
		for _, tr := range m.Transports {
			if tr != "ws" && tr != "httpupgrade" && tr != "xhttp" {
				t.Errorf("%s offers transport %q, which cannot share the platform's port", want, tr)
			}
		}
		if len(m.Securities) != 1 || m.Securities[0] != "tls" {
			t.Errorf("%s offers securities %v; the edge terminates TLS and REALITY is contradictory here",
				want, m.Securities)
		}
	}
	// Brook is offered: it is its own engine, and its wsserver mode is a
	// WebSocket server with a path on it, which a shared HTTP port routes like
	// any other. Only its plain-server and quic modes cannot be served here.
	if _, ok := here["brook"]; !ok {
		t.Error("brook is not offered; its wsserver mode is routable on a shared port")
	}
	for _, gone := range []string{"hysteria2", "tuic", "wireguard"} {
		if m, ok := here[gone]; ok {
			t.Errorf("%s is offered but cannot be served here (%s)", gone, m.HereNote)
		}
	}
	// Shadowsocks IS servable here, but only over WebSocket — the one transport
	// an ss:// URI can describe. Offering it the full three would let an
	// operator build an inbound that runs and that no client can be told about.
	ss, ok := here["shadowsocks"]
	if !ok {
		t.Fatal("shadowsocks is not offered, but the platform routes it and the core serves it")
	}
	if len(ss.Transports) != 3 {
		t.Errorf("shadowsocks offers %v; all three are routable here, they differ only in delivery",
			ss.Transports)
	}
	// Every unavailable protocol has to say WHY, or the form is a list of
	// things greyed out for no stated reason.
	for _, m := range metas {
		if !m.ServesHere && m.HereNote == "" {
			t.Errorf("%s is unavailable with no reason given", m.Proto)
		}
	}
}

// A subscription URL is what an operator copies and sends to somebody. Behind
// an edge the panel serves plain HTTP, so deriving the scheme from the listener
// produced an http:// link to a service that is HTTPS-only.
func TestASubscriptionURLIsAlwaysHTTPS(t *testing.T) {
	s := paasServer(t)
	if got := s.subScheme(); got != "https" {
		t.Fatalf("scheme %q — the panel serves plain HTTP behind an edge, but the client's leg is TLS", got)
	}
	if got := dbServerT(t).subScheme(); got != "https" {
		t.Fatalf("off-platform scheme %q", got)
	}
}

// Saving a routing rule must not be refused because of the INBOUNDS.
//
// The validation path built its candidate from the raw inbound list while the
// reload built from the platform-rewritten one, so on a platform every routing
// edit was rejected with "unable to listen on domain address: …" — the panel
// asking the core to bind a hostname the container does not own, about inbounds
// that were running correctly the whole time. Routing was unusable there and
// the error pointed at the wrong thing.
func TestRoutingValidationUsesTheSpecsThatWillActuallyRun(t *testing.T) {
	s := paasServer(t)
	wsInbound(t, s, "ws1", "/one")

	cand := s.candidateSpecs()
	// Assert non-empty FIRST. Without the platform rewrite the bindability
	// filter drops every inbound (their address is the platform's hostname, which
	// this host does not hold), so the loop below would run zero times and pass
	// while validating nothing at all.
	if len(cand) == 0 {
		t.Fatal("no specs to validate: the platform rewrite is not being applied")
	}
	for _, sp := range cand {
		if sp.Node == nil {
			continue
		}
		if sp.Node.Address != "127.0.0.1" {
			t.Errorf("a config built for validation would ask the core to bind %q, "+
				"which this container does not own", sp.Node.Address)
		}
		if sp.Node.Security.Type != model.SecNone {
			t.Errorf("validation config still carries %s; the edge already terminated TLS",
				sp.Node.Security.Type)
		}
	}
	// The nodes handed to Config Doctor have to agree with them.
	nodes := s.candidateNodes()
	if len(nodes) == 0 {
		t.Fatal("Config Doctor would validate an empty inbound list")
	}
	for _, n := range nodes {
		if n.Address != "127.0.0.1" {
			t.Errorf("Config Doctor would validate against %q", n.Address)
		}
	}
}

// Validation and the reload must not be able to drift apart again.
func TestValidationAndReloadBuildFromTheSameList(t *testing.T) {
	s := paasServer(t)
	wsInbound(t, s, "a", "/a")
	wsInbound(t, s, "b", "/b")

	run, _ := s.reloadSpecs()
	cand := s.candidateSpecs()
	if len(run) != 2 {
		t.Fatalf("reload produced %d specs, want both inbounds", len(run))
	}
	if len(run) != len(cand) {
		t.Fatalf("reload builds %d specs, validation builds %d", len(run), len(cand))
	}
	for i := range run {
		if run[i].Node.Address != cand[i].Node.Address || run[i].Node.Port != cand[i].Node.Port {
			t.Errorf("spec %d differs: run=%s:%d validate=%s:%d", i,
				run[i].Node.Address, run[i].Node.Port, cand[i].Node.Address, cand[i].Node.Port)
		}
	}
	src, err := os.ReadFile("routing.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "s.enabledInboundSpecs()") {
		t.Error("routing validation went back to the raw inbound list")
	}
}

// Shadowsocks on a transport no ss:// link can describe must still be CREATABLE.
//
// It was refused at first, on the reasoning that an inbound nobody can be told
// about is worse than one that does not run. That confused the link with the
// config: the inbound runs, the core serves it, and the Xray and JSON
// subscriptions carry the transport in full. Refusing it removed a working
// option to avoid a missing URI.
func TestShadowsocksIsCreatableOnEveryRoutableTransport(t *testing.T) {
	for _, net := range []string{"ws", "httpupgrade", "xhttp"} {
		t.Run(net, func(t *testing.T) {
			s := paasServer(t)
			r := gin.New()
			r.POST("/in", s.handleCreateInbound)
			rec := httptest.NewRecorder()
			body := `{"remark":"ss-` + net + `","protocol":"shadowsocks","port":443,"transport":{"network":"` + net + `"},"security":{"type":"none"}}`
			req := httptest.NewRequest(http.MethodPost, "/in", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(rec, req)
			if rec.Code != 201 {
				t.Fatalf("shadowsocks over %s was refused: %d %s", net, rec.Code, rec.Body.String())
			}
			// And it must actually be served, not merely stored.
			_, _, skipped := s.paasSpecs()
			if len(skipped) != 0 {
				t.Fatalf("created but not served: %+v", skipped)
			}
		})
	}
}
