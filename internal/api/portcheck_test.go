package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// portRouter wires the collision guard the way the server does: as PER-ROUTE
// middleware on the node-accepting routes only. Group-level would also wrap
// /ports/check, whose whole job is to REPORT a conflict rather than refuse.
func portRouter(s *Server) *gin.Engine {
	r := gin.New()
	g := r.Group("/api/admin")
	g.POST("/inbounds", s.portCollisionGuard(), s.handleCreateInbound)
	g.PUT("/inbounds/:id", s.portCollisionGuard(), s.handleUpdateInbound)
	s.registerPortRoutes(g)
	return r
}

// stubListeners fixes the host socket table for the duration of one test. Every
// test in this file calls it: the real machine's listeners drift under us, and
// a check that only worked when port 443 happened to be free would be a test of
// the CI box, not of the code.
func stubListeners(t *testing.T, ls ...firewall.Listener) {
	t.Helper()
	old := hostListeners
	hostListeners = func() []firewall.Listener { return ls }
	t.Cleanup(func() { hostListeners = old })
}

func mustCreate(t *testing.T, r *gin.Engine, body string) uint {
	t.Helper()
	rec := dreq(t, r, "POST", "/api/admin/inbounds", body)
	if rec.Code != 201 {
		t.Fatalf("create should have succeeded: got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

func vlessBody(port int, remark string) string {
	return `{"protocol":"vless","port":` + strconv.Itoa(port) + `,"remark":"` + remark +
		`","transport":{"network":"tcp"},"security":{"type":"reality"}}`
}

func hy2Body(port int, remark string) string {
	return `{"protocol":"hysteria2","port":` + strconv.Itoa(port) + `,"remark":"` + remark +
		`","security":{"type":"tls"}}`
}

// decodeConflict pulls the machine-readable conflict out of a 409 body.
func decodeConflict(t *testing.T, body []byte) PortConflict {
	t.Helper()
	var out struct {
		Code     string       `json:"code"`
		Conflict PortConflict `json:"conflict"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Code != "port_conflict" {
		t.Fatalf("want code port_conflict, got %q (%s)", out.Code, body)
	}
	return out.Conflict
}

// TestPortCollisionSameProtocolRejected is the defect itself: before this check
// the second create was accepted and the resulting engine document — every
// inbound in it — became unloadable.
func TestPortCollisionSameProtocolRejected(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	first := mustCreate(t, r, vlessBody(24443, "alpha"))

	rec := dreq(t, r, "POST", "/api/admin/inbounds", vlessBody(24443, "beta"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second inbound on tcp/24443 must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	cf := decodeConflict(t, rec.Body.Bytes())
	if cf.Kind != "inbound" || cf.InboundID != first {
		t.Fatalf("conflict must name the other inbound, got %+v", cf)
	}
	if !strings.Contains(cf.HeldBy, "alpha") {
		t.Errorf("operator needs the conflicting inbound's name, got %q", cf.HeldBy)
	}
	if cf.Suggested <= 24443 {
		t.Errorf("a free alternative port must be suggested, got %d", cf.Suggested)
	}
	// The suggestion has to be usable, not decorative.
	mustCreate(t, r, vlessBody(cf.Suggested, "gamma"))
}

// TestPortCollisionUDPAndTCPCoexist: hysteria2 is QUIC/UDP, so it does not
// collide with a TCP inbound on the same number. Rejecting this pair would make
// the check worse than nothing — 443 is exactly the port operators want twice.
func TestPortCollisionUDPAndTCPCoexist(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, vlessBody(24444, "tcp-side"))
	mustCreate(t, r, hy2Body(24444, "udp-side"))
}

// TestPortCollisionSameUDPFamilyRejected: two QUIC inbounds DO collide.
func TestPortCollisionSameUDPFamilyRejected(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, hy2Body(24445, "hy2"))

	body := `{"protocol":"tuic","port":24445,"remark":"tuic","security":{"type":"tls"}}`
	rec := dreq(t, r, "POST", "/api/admin/inbounds", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("tuic and hysteria2 both bind udp/24445, got %d: %s", rec.Code, rec.Body.String())
	}
	if cf := decodeConflict(t, rec.Body.Bytes()); cf.Proto != "udp" {
		t.Fatalf("conflict must be reported on udp, got %+v", cf)
	}
}

// TestPortCollisionIgnoresSelfOnUpdate: an edit that keeps the port must not be
// refused because the inbound already owns it.
func TestPortCollisionIgnoresSelfOnUpdate(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	id := mustCreate(t, r, vlessBody(24446, "self"))

	rec := dreq(t, r, "PUT", "/api/admin/inbounds/"+strconv.FormatUint(uint64(id), 10),
		`{"protocol":"vless","port":24446,"remark":"self-renamed","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	if rec.Code != 200 {
		t.Fatalf("an inbound must not conflict with itself: got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPortCollisionMovingOntoAnotherInboundRejected covers the update path.
func TestPortCollisionMovingOntoAnotherInboundRejected(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, vlessBody(24447, "squatter"))
	id := mustCreate(t, r, vlessBody(24448, "mover"))

	rec := dreq(t, r, "PUT", "/api/admin/inbounds/"+strconv.FormatUint(uint64(id), 10)+"?confirm=true",
		vlessBody(24447, "mover"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("moving onto a taken port must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPortCollisionForeignProcess: a non-panel listener is detected, named, and
// left strictly alone — and a TCP one does not block a UDP inbound.
func TestPortCollisionForeignProcess(t *testing.T) {
	stubListeners(t, firewall.Listener{
		Proto: "tcp", Address: "0.0.0.0", Port: 24449, PID: 812, Process: "nginx",
	})
	s := dbServerT(t)
	r := portRouter(s)

	rec := dreq(t, r, "POST", "/api/admin/inbounds", vlessBody(24449, "clash"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("a live foreign listener on tcp/24449 must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	cf := decodeConflict(t, rec.Body.Bytes())
	if cf.Kind != "system" || cf.PID != 812 || !strings.Contains(cf.HeldBy, "nginx") {
		t.Fatalf("foreign holder must be named: %+v", cf)
	}
	if !strings.Contains(cf.Message, "will not stop it") {
		t.Errorf("the panel must say it leaves foreign processes alone: %q", cf.Message)
	}

	// Same number, different transport: nginx on tcp/24449 says nothing about
	// udp/24449, and refusing here would be a fabricated conflict.
	mustCreate(t, r, hy2Body(24449, "udp-ok"))
}

// TestPortCollisionUnnamedForeignProcess: /proc denies the panel the owner's
// name unless it is privileged. A missing name must not downgrade a correct
// detection into a false "port is free".
func TestPortCollisionUnnamedForeignProcess(t *testing.T) {
	stubListeners(t, firewall.Listener{Proto: "tcp", Address: "::", Port: 24450})
	s := dbServerT(t)
	r := portRouter(s)

	rec := dreq(t, r, "POST", "/api/admin/inbounds", vlessBody(24450, "x"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("an unattributable listener still holds the port, got %d: %s", rec.Code, rec.Body.String())
	}
	if cf := decodeConflict(t, rec.Body.Bytes()); cf.PID != 0 || !strings.Contains(cf.HeldBy, "did not start") {
		t.Fatalf("unnamed holder must be described honestly: %+v", cf)
	}
}

// TestPortCollisionOwnEngineListenerIsNotForeign: on an update that keeps the
// port, the engine's own live socket is visible in /proc. Treating it as a
// foreign holder would make every such edit impossible.
func TestPortCollisionOwnEngineListenerIsNotForeign(t *testing.T) {
	s := dbServerT(t)
	stubListeners(t)
	r := portRouter(s)
	id := mustCreate(t, r, vlessBody(24451, "live"))

	stubListeners(t, firewall.Listener{Proto: "tcp", Address: "::", Port: 24451, PID: 99, Process: "xray"})
	rec := dreq(t, r, "PUT", "/api/admin/inbounds/"+strconv.FormatUint(uint64(id), 10),
		vlessBody(24451, "live"))
	if rec.Code != 200 {
		t.Fatalf("our own engine socket must not block the inbound that owns it: %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPortCollisionHopRangeReserved: Hysteria2 port hopping answers on a whole
// UDP span, so an inbound landing inside it is a real collision even though the
// port numbers differ.
func TestPortCollisionHopRangeReserved(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, `{"protocol":"hysteria2","port":24452,"remark":"hopper","security":{"type":"tls"},`+
		`"hysteria2":{"port_hopping":"30000-30100"}}`)

	rec := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"tuic","port":30050,"remark":"inside","security":{"type":"tls"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("udp/30050 sits inside the hop range, got %d: %s", rec.Code, rec.Body.String())
	}
	// A TCP inbound in the same span is fine: hopping is UDP DNAT only.
	mustCreate(t, r, vlessBody(30051, "tcp-inside-range"))
}

// TestPortCollisionMalformedHopRangeReservesNothing: the renderer skips a
// malformed range, so it protects nothing and must not block a port either.
func TestPortCollisionMalformedHopRangeReservesNothing(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, `{"protocol":"hysteria2","port":24453,"remark":"bad-hop","security":{"type":"tls"},`+
		`"hysteria2":{"port_hopping":"not-a-range"}}`)
	mustCreate(t, r, `{"protocol":"tuic","port":24454,"remark":"unaffected","security":{"type":"tls"}}`)
}

// TestInboundClaimsTransportOverridesL4: mKCP and QUIC transports ride UDP even
// under a protocol that is otherwise TCP.
func TestInboundClaimsTransportOverridesL4(t *testing.T) {
	for _, net := range []model.Network{model.NetMKCP, model.NetQUIC} {
		n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: net}}
		cs := inboundClaims(n, "", 0)
		if len(cs) != 1 || cs[0].l4 != l4UDP {
			t.Fatalf("vless over %s binds udp only, got %+v", net, cs)
		}
	}
}

// TestInboundClaimsForgeDNSSharesOneListener: ForgeDNS zones are multiplexed
// onto the controller's single socket, so they claim no port of their own —
// otherwise every zone after the first would be refused for "using port 53".
func TestInboundClaimsForgeDNSSharesOneListener(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoForgeDNS, Port: 53,
		ForgeDNS: &model.ForgeDNSOptions{Zone: "t.example.com", Adapter: "stormdns"}}
	if cs := inboundClaims(n, "", 0); len(cs) != 0 {
		t.Fatalf("a forgedns zone binds nothing of its own, got %+v", cs)
	}
}

// TestPanelPortIsReserved: taking the panel's own port locks the operator out.
func TestPanelPortIsReserved(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	s.cfg.PanelPort = 24455
	r := portRouter(s)

	rec := dreq(t, r, "POST", "/api/admin/inbounds", vlessBody(24455, "lockout"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("the panel port must be reserved, got %d: %s", rec.Code, rec.Body.String())
	}
	if cf := decodeConflict(t, rec.Body.Bytes()); cf.Kind != "panel" {
		t.Fatalf("want kind panel, got %+v", cf)
	}
	// UDP on the same number is free: the panel serves HTTP over TCP.
	mustCreate(t, r, hy2Body(24455, "udp-beside-panel"))
}

// TestPortCheckRouteReportsWithoutRefusing: the create form asks this while the
// operator types, so a taken port is a 200 carrying the detail, not an error.
func TestPortCheckRouteReportsWithoutRefusing(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, vlessBody(24456, "taken"))

	rec := dreq(t, r, "POST", "/api/admin/ports/check", vlessBody(24456, "probe"))
	if rec.Code != 200 {
		t.Fatalf("the checker is a query, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Available bool         `json:"available"`
		Binds     []string     `json:"binds"`
		Conflict  PortConflict `json:"conflict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Available || out.Conflict.Suggested == 0 {
		t.Fatalf("taken port must report unavailable with an alternative: %s", rec.Body.String())
	}
	if len(out.Binds) != 1 || out.Binds[0] != l4TCP {
		t.Errorf("vless/tcp binds tcp only, got %v", out.Binds)
	}

	rec = dreq(t, r, "POST", "/api/admin/ports/check", vlessBody(24457, "probe"))
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available {
		t.Fatalf("free port must report available: %s", rec.Body.String())
	}
}

// TestListeningPortsRouteReportsOnly proves the endpoint is pure reporting.
func TestListeningPortsRouteReportsOnly(t *testing.T) {
	stubListeners(t,
		firewall.Listener{Proto: "tcp", Address: "0.0.0.0", Port: 22, PID: 7, Process: "sshd"},
		firewall.Listener{Proto: "udp", Address: "::", Port: 51820, Process: "wg"},
	)
	s := dbServerT(t)
	r := portRouter(s)

	rec := dreq(t, r, "GET", "/api/admin/ports/listening?port=22", "")
	if rec.Code != 200 {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Count     int                 `json:"count"`
		Listeners []firewall.Listener `json:"listeners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Listeners[0].Process != "sshd" {
		t.Fatalf("port filter should return only sshd: %s", rec.Body.String())
	}
}

// TestSuggestPortSkipsEveryHolder: a suggestion must be free on ALL transports
// the inbound needs, or it just moves the failure.
func TestSuggestPortSkipsEveryHolder(t *testing.T) {
	busy := func(port int, l4 string) bool {
		switch {
		case port == 30000: // taken on tcp only
			return l4 == l4TCP
		case port == 30001: // taken on udp only
			return l4 == l4UDP
		}
		return false
	}
	if got := suggestPort(30000, []string{l4TCP, l4UDP}, busy); got != 30002 {
		t.Fatalf("want the first port free on both families (30002), got %d", got)
	}
	if got := suggestPort(30000, []string{l4UDP}, busy); got != 30000 {
		t.Fatalf("udp/30000 is free, got %d", got)
	}
	if got := suggestPort(80, []string{l4TCP}, func(int, string) bool { return false }); got != 1024 {
		t.Fatalf("suggestions must stay out of the privileged range, got %d", got)
	}
}

// TestPortCollisionNormalisesRequestBody: the guard reads the RAW body, before
// the handler's pipeline has canonicalised anything. An uppercase protocol or a
// legacy transport alias must still be understood, or a collision slips through
// in exactly the spelling a hand-written API call tends to use.
func TestPortCollisionNormalisesRequestBody(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, vlessBody(24458, "lower"))

	rec := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"VLESS","port":24458,"remark":"upper","transport":{"network":"TCP"},"security":{"type":"reality"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("uppercase protocol must still collide, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPortCollisionTransportAliasRidesUDP: "mkcp" is the legacy spelling of the
// kcp network, and kcp is UDP — so this VLESS inbound really does fight the
// hysteria2 one, even though VLESS is a TCP protocol on paper.
func TestPortCollisionTransportAliasRidesUDP(t *testing.T) {
	stubListeners(t)
	s := dbServerT(t)
	r := portRouter(s)
	mustCreate(t, r, hy2Body(24459, "quic-side"))

	rec := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":24459,"remark":"kcp","transport":{"network":"mkcp"},"security":{"type":"none"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("vless-over-mkcp binds udp/24459, got %d: %s", rec.Code, rec.Body.String())
	}
	if cf := decodeConflict(t, rec.Body.Bytes()); cf.Proto != l4UDP {
		t.Fatalf("conflict must be on udp, got %+v", cf)
	}
	// The same inbound over plain TCP does not collide.
	mustCreate(t, r, vlessBody(24459, "tcp-side"))
}

// The guard existed, was correct, was thoroughly tested — and was mounted only
// inside this test file. Production had no port-collision check at all, and
// nothing could tell: every test passed because each one wired the middleware
// itself.
//
// This asserts against the REAL router, so the check is that the server mounts
// it, not that a test can.
func TestPortCollisionGuardIsMountedOnTheRealServer(t *testing.T) {
	stubListeners(t) // host table empty: this is about inbound-vs-inbound
	s, _, token := createComprehensiveTestServer(t)

	body := map[string]any{
		"protocol": "vless", "remark": "first", "address": "0.0.0.0", "port": 24601,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
	}
	if code, resp := realPost(t, s, "/api/admin/inbounds", token, body); code != 201 {
		t.Fatalf("first create should succeed, got %d: %s", code, resp)
	}

	body["remark"] = "second"
	code, resp := realPost(t, s, "/api/admin/inbounds", token, body)
	if code != http.StatusConflict {
		t.Fatalf("a second inbound on the same port must be refused with 409, got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "port_conflict") {
		t.Fatalf("the 409 should carry the port_conflict code so the UI can act on it: %s", resp)
	}
}

// The pre-flight query route must be mounted too, or the create form cannot warn
// before the operator submits.
func TestPortCheckRouteIsMountedOnTheRealServer(t *testing.T) {
	stubListeners(t)
	s, _, token := createComprehensiveTestServer(t)
	code, resp := realPost(t, s, "/api/admin/ports/check", token, map[string]any{
		"protocol": "vless", "address": "0.0.0.0", "port": 24602,
	})
	if code != 200 {
		t.Fatalf("/ports/check should answer 200, got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "available") {
		t.Fatalf("the answer should report availability: %s", resp)
	}
}

// realPost drives the SERVER's own handler chain, not a router assembled by the
// test. That distinction is the whole point of the two tests above.
func realPost(t *testing.T, s *Server, path, token string, body map[string]any) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}
