package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/store"
)

// doPOST posts a raw JSON body. The shared adminReq takes a map, which cannot
// express the JSON these handlers accept (string lists, nested objects) without
// building it twice — once as a map here and once as the struct the API binds.
func doPOST(t *testing.T, s *Server, path, token, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// Routing over HTTP. The dangerous parts are: a rule that matches everything, a
// rule pointing at an outbound that does not exist, deleting an outbound rules
// still use, and a reorder that silently leaves a rule somewhere nobody chose.
// Each of them ends the same way — the core refuses the whole config and every
// inbound on the box goes down — so each is refused before it is stored.

func mkOutbound(t *testing.T, s *Server, token, tag, proto string) {
	t.Helper()
	body := fmt.Sprintf(`{"tag":%q,"protocol":%q,"enabled":true}`, tag, proto)
	code, resp := doPOST(t, s, "/api/admin/routing/outbounds", token, body)
	if code != 200 {
		t.Fatalf("creating outbound %s: %d %s", tag, code, resp)
	}
}

func TestOutboundCRUD(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "relay", "socks")

	code, body := doGET(t, s, "/api/admin/routing/outbounds", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res struct {
		Outbounds []store.Outbound `json:"outbounds"`
		Builtin   []string         `json:"builtin"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Outbounds) != 1 || res.Outbounds[0].Tag != "relay" {
		t.Fatalf("outbounds = %+v", res.Outbounds)
	}
	// The built-ins are published so the UI does not hardcode names.
	if len(res.Builtin) != 2 {
		t.Errorf("builtin = %v, want direct and block", res.Builtin)
	}
}

func TestOutboundCannotShadowABuiltIn(t *testing.T) {
	s, token := adminAPI(t)
	for _, tag := range []string{"direct", "block", "api"} {
		code, body := doPOST(t, s, "/api/admin/routing/outbounds", token,
			fmt.Sprintf(`{"tag":%q,"protocol":"freedom","enabled":true}`, tag))
		// A config with two outbounds of one name lets the core pick either, so
		// traffic an operator sent to "block" could leave the machine.
		if code == 200 {
			t.Fatalf("an outbound shadowing the built-in %q was accepted: %s", tag, body)
		}
	}
}

func TestOutboundCannotShadowARelayChain(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/routing/outbounds", token,
		`{"tag":"egress-0-0","protocol":"freedom","enabled":true}`)
	// The egress renderer generates tags in that space. A collision would
	// silently reroute an inbound's relay chain to the operator's outbound.
	if code == 200 {
		t.Fatalf("an outbound in the reserved egress tag space was accepted: %s", body)
	}
}

func TestRuleWithNoMatchersIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"catch-all","outbound_tag":"block","enabled":true}`)
	// Saved above a carefully ordered list it silently swallows all of it, and
	// the operator sees a panel where routing "stopped working".
	if code == 200 {
		t.Fatalf("a rule with no matchers was accepted: %s", body)
	}
}

func TestRulePointingAtNothingIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"ghost","domain":["a.com"],"outbound_tag":"nowhere","enabled":true}`)
	// The core refuses the ENTIRE config for this, so one bad rule takes every
	// inbound down. Catching it here rejects the rule instead of the panel.
	if code == 200 {
		t.Fatalf("a rule pointing at an undefined outbound was accepted: %s", body)
	}
}

func TestRuleCanTargetABuiltIn(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"ads","domain":["geosite:category-ads-all"],"outbound_tag":"block","enabled":true}`)
	if code != 200 {
		t.Fatalf("blocking ads is the most ordinary rule there is: %d %s", code, body)
	}
}

func TestDeletingAnOutboundInUseIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "relay", "socks")
	code, body := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"via-relay","domain":["x.com"],"outbound_tag":"relay","enabled":true}`)
	if code != 200 {
		t.Fatalf("creating the rule: %d %s", code, body)
	}

	var list struct {
		Outbounds []store.Outbound `json:"outbounds"`
	}
	_, lb := doGET(t, s, "/api/admin/routing/outbounds", token)
	if err := json.Unmarshal([]byte(lb), &list); err != nil {
		t.Fatal(err)
	}
	code, body = doDELETE(t, s, fmt.Sprintf("/api/admin/routing/outbounds/%d", list.Outbounds[0].ID), token)
	// Deleting it anyway leaves a rule pointing at a tag the config no longer
	// defines; the core rejects the whole config and every inbound goes down —
	// one delete causing a total outage.
	if code == 204 || code == 200 {
		t.Fatalf("deleted an outbound a rule still uses: %d %s", code, body)
	}
	if code != 409 {
		t.Errorf("status = %d, want 409 Conflict", code)
	}
}

func TestReorderMustListEveryRule(t *testing.T) {
	s, token := adminAPI(t)
	for i, name := range []string{"a", "b", "c"} {
		code, body := doPOST(t, s, "/api/admin/routing/rules", token,
			fmt.Sprintf(`{"name":%q,"domain":["%d.com"],"outbound_tag":"block","enabled":true,"sort_order":%d}`, name, i, i))
		if code != 200 {
			t.Fatalf("creating rule %s: %d %s", name, code, body)
		}
	}
	var res struct {
		Rules []store.RoutingRule `json:"rules"`
	}
	_, body := doGET(t, s, "/api/admin/routing/rules", token)
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(res.Rules))
	}

	// A partial list leaves the omitted rules at whatever position they held,
	// producing an order nobody designed — live, on a first-match table.
	partial := fmt.Sprintf(`{"ids":[%d,%d]}`, res.Rules[2].ID, res.Rules[0].ID)
	if code, b := doPOST(t, s, "/api/admin/routing/rules/reorder", token, partial); code == 200 {
		t.Fatalf("a partial reorder was accepted: %s", b)
	}

	// A duplicate would give one rule two positions.
	dup := fmt.Sprintf(`{"ids":[%d,%d,%d]}`, res.Rules[0].ID, res.Rules[0].ID, res.Rules[1].ID)
	if code, b := doPOST(t, s, "/api/admin/routing/rules/reorder", token, dup); code == 200 {
		t.Fatalf("a reorder listing a rule twice was accepted: %s", b)
	}

	full := fmt.Sprintf(`{"ids":[%d,%d,%d]}`, res.Rules[2].ID, res.Rules[1].ID, res.Rules[0].ID)
	if code, b := doPOST(t, s, "/api/admin/routing/rules/reorder", token, full); code != 200 {
		t.Fatalf("a complete reorder was refused: %d %s", code, b)
	}
	_, body = doGET(t, s, "/api/admin/routing/rules", token)
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Rules[0].Name != "c" || res.Rules[2].Name != "a" {
		t.Fatalf("order after reorder = %s, %s, %s", res.Rules[0].Name, res.Rules[1].Name, res.Rules[2].Name)
	}
}

func TestRoutingPrecedenceIsPublished(t *testing.T) {
	s, token := adminAPI(t)
	_, body := doGET(t, s, "/api/admin/routing/rules", token)
	var res struct {
		Precedence []string `json:"precedence"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	// A routing table whose order has to be discovered by experiment is one
	// people get wrong, and getting THIS one wrong can pull traffic out of a
	// relay chain and expose the server's real address.
	if len(res.Precedence) < 3 {
		t.Fatalf("precedence = %v; it must be stated, not inferred", res.Precedence)
	}
}

func TestRoutingIsNotAResellersToWrite(t *testing.T) {
	s, _ := adminAPI(t)
	reseller := &store.Admin{Username: "rs", PasswordHash: "x", Role: store.RoleReseller}
	if err := s.db.CreateAdmin(reseller); err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.signer.Issue(reseller.ID, reseller.Username, string(store.RoleReseller))
	if err != nil {
		t.Fatal(err)
	}
	// A rule applies across every tenant and can send any user's traffic
	// anywhere, or stop it entirely. It is not one tenant's to write.
	for _, path := range []string{"/api/admin/routing/rules", "/api/admin/routing/outbounds"} {
		if code, _ := doGET(t, s, path, tok); code != 403 {
			t.Errorf("GET %s as a reseller returned %d, want 403", path, code)
		}
	}
	if code, _ := doPOST(t, s, "/api/admin/routing/rules", tok,
		`{"name":"x","domain":["a.com"],"outbound_tag":"block","enabled":true}`); code != 403 {
		t.Errorf("a reseller could write a routing rule (%d)", code)
	}
}

func TestSavedRoutingReachesTheGeneratedConfig(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "hole", "blackhole")
	code, body := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"ads","domain":["geosite:category-ads-all"],"outbound_tag":"hole","enabled":true}`)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}

	// The whole point: stored routing must actually be what the core is given.
	// A panel that stores rules and generates a config without them is the
	// silent-failure shape this codebase keeps finding.
	outs, rules, _ := s.routingSpecs()
	if len(outs) != 1 || outs[0].Tag != "hole" {
		t.Fatalf("outbound specs = %+v", outs)
	}
	if len(rules) != 1 || rules[0].OutboundTag != "hole" {
		t.Fatalf("rule specs = %+v", rules)
	}
}

func TestDisabledRoutingIsNotRendered(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "hole", "blackhole")
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"off","domain":["a.com"],"outbound_tag":"hole","enabled":false}`); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	_, rules, _ := s.routingSpecs()
	// "Enabled" has to mean something. A disabled rule that still routes traffic
	// is worse than no toggle at all, because the operator believes it is off.
	if len(rules) != 0 {
		t.Fatalf("a disabled rule was rendered: %+v", rules)
	}
}

// --- presets ---------------------------------------------------------------

func TestPresetsIncludeTheSecurityOne(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/admin/routing/presets", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res struct {
		Presets []struct {
			Name  string `json:"name"`
			Title string `json:"title"`
			Why   string `json:"why"`
			Rules []struct {
				IP []string `json:"ip"`
			} `json:"rules"`
		} `json:"presets"`
		GeodataReady bool `json:"geodata_ready"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}

	var priv *struct {
		Name  string `json:"name"`
		Title string `json:"title"`
		Why   string `json:"why"`
		Rules []struct {
			IP []string `json:"ip"`
		} `json:"rules"`
	}
	for i := range res.Presets {
		if res.Presets[i].Name == "block-private" {
			priv = &res.Presets[i]
		}
	}
	if priv == nil {
		t.Fatal("there is no block-private preset")
	}
	// The link-local range is the one that matters: 169.254.169.254 serves cloud
	// instance credentials to anything on the box that asks, and a proxy will
	// ask on a user's behalf because that is its job.
	found := false
	for _, r := range priv.Rules {
		for _, ip := range r.IP {
			if ip == "169.254.0.0/16" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the private-network preset does not block 169.254.0.0/16; " +
			"cloud instance metadata is reachable through the proxy")
	}
	// A preset whose consequences are not stated gets applied and then blamed.
	if priv.Why == "" || priv.Title == "" {
		t.Error("the preset does not explain what it is for")
	}
}

func TestApplyingAPresetIsIdempotent(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/routing/presets/block-private", token, `{}`)
	if code != 200 {
		t.Fatalf("first apply: %d %s", code, body)
	}
	var first struct {
		Applied int      `json:"applied"`
		Skipped []string `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(body), &first); err != nil {
		t.Fatal(err)
	}
	if first.Applied == 0 {
		t.Fatal("the preset added nothing")
	}

	code, body = doPOST(t, s, "/api/admin/routing/presets/block-private", token, `{}`)
	if code != 200 {
		t.Fatalf("second apply: %d %s", code, body)
	}
	var second struct {
		Applied int      `json:"applied"`
		Skipped []string `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(body), &second); err != nil {
		t.Fatal(err)
	}
	// A duplicated rule can never match, because the identical one above it
	// already did. It is pure confusion in a table read top to bottom.
	if second.Applied != 0 || len(second.Skipped) != first.Applied {
		t.Fatalf("re-applying duplicated rules: applied=%d skipped=%v", second.Applied, second.Skipped)
	}
}

func TestApplyingAPresetKeepsExistingRules(t *testing.T) {
	s, token := adminAPI(t)
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"mine","domain":["hand.written"],"outbound_tag":"block","enabled":true}`); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	if code, b := doPOST(t, s, "/api/admin/routing/presets/block-ads", token, `{}`); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}

	var res struct {
		Rules []store.RoutingRule `json:"rules"`
	}
	_, body := doGET(t, s, "/api/admin/routing/rules", token)
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	// Wiping the table in response to one click on a convenience feature would
	// destroy rules an operator spent real time on.
	found := false
	for _, r := range res.Rules {
		if r.Name == "mine" {
			found = true
		}
	}
	if !found {
		t.Fatal("applying a preset removed a hand-written rule")
	}
	if len(res.Rules) < 2 {
		t.Fatalf("rules = %d, want the hand-written one plus the preset's", len(res.Rules))
	}
}

func TestUnknownPresetIs404(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := doPOST(t, s, "/api/admin/routing/presets/nonsense", token, `{}`); code != 404 {
		t.Errorf("unknown preset returned %d, want 404", code)
	}
}

// --- failover groups --------------------------------------------------------

func mkGroup(t *testing.T, s *Server, token, body string) (int, string) {
	t.Helper()
	return doPOST(t, s, "/api/admin/routing/groups", token, body)
}

// The wiring assertion. A GroupSpec, a RenderBalancers and a groups table can
// all be written, unit-tested and shipped while the panel's routing source stays
// a two-tuple of outbounds and rules — at which point the operator configures
// failover, the UI shows it, and not one generated config contains a balancer.
func TestFailoverGroupReachesTheGeneratedConfig(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "relay-a", "blackhole")
	mkOutbound(t, s, token, "relay-b", "blackhole")
	if code, b := mkGroup(t, s, token,
		`{"tag":"failover","members":["relay-a","relay-b"],"strategy":"leastPing","enabled":true}`); code != 200 {
		t.Fatalf("creating the group: %d %s", code, b)
	}
	if code, b := doPOST(t, s, "/api/admin/routing/rules", token,
		`{"name":"web","domain":["example.com"],"outbound_tag":"failover","enabled":true}`); code != 200 {
		t.Fatalf("a rule could not target the group: %d %s", code, b)
	}

	outs, rules, groups := s.routingSpecs()
	if len(groups) != 1 || groups[0].Tag != "failover" {
		t.Fatalf("group specs = %+v", groups)
	}
	bundle, err := engine.BuildMultiWithRouting(s.candidateSpecs(), 0, "", "", outs, rules, groups)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routing struct {
			Balancers []struct {
				Tag string `json:"tag"`
			} `json:"balancers"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(bundle.Xray, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Routing.Balancers) != 1 || doc.Routing.Balancers[0].Tag != "failover" {
		t.Fatalf("the saved group is in no generated config: %s", bundle.Xray)
	}
}

// A member the config no longer defines makes the core refuse the WHOLE
// document, so one delete takes every inbound on the box down.
func TestAnOutboundInsideAGroupCannotBeDeleted(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "relay-a", "blackhole")
	mkOutbound(t, s, token, "relay-b", "blackhole")
	if code, b := mkGroup(t, s, token,
		`{"tag":"failover","members":["relay-a","relay-b"],"enabled":true}`); code != 200 {
		t.Fatalf("creating the group: %d %s", code, b)
	}
	obs, err := s.db.ListOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	var id uint
	for _, o := range obs {
		if o.Tag == "relay-a" {
			id = o.ID
		}
	}
	code, body := doDELETE(t, s, fmt.Sprintf("/api/admin/routing/outbounds/%d", id), token)
	if code != http.StatusConflict {
		t.Fatalf("deleting a group member returned %d, want 409: %s", code, body)
	}
	if !strings.Contains(body, "failover") {
		t.Errorf("the refusal does not name the group holding it: %s", body)
	}
}

func TestAGroupNamingAnUnknownMemberIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	mkOutbound(t, s, token, "relay-a", "blackhole")
	code, body := mkGroup(t, s, token,
		`{"tag":"failover","members":["relay-a","ghost"],"enabled":true}`)
	if code == 200 {
		t.Fatalf("a group selecting an outbound nothing defines was stored: %s", body)
	}
	if list, err := s.db.ListOutboundGroups(); err != nil || len(list) != 0 {
		t.Fatalf("the rejected group was stored anyway: %+v (%v)", list, err)
	}
}
