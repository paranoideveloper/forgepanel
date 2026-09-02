package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// chainNode is an inbound that relays out through an upstream hop.
func chainNode(remark string, port int, egress string) *model.Node {
	n := &model.Node{
		Protocol: model.ProtoVLESS,
		Address:  "0.0.0.0",
		Port:     port,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Remark:   remark,
		Egress:   chainOf(egress),
	}
	n.Normalize()
	return n
}

const upstreamVLESS = "vless://11111111-2222-4333-8444-555555555555@203.0.113.50:443?" +
	"security=reality&sni=www.cloudflare.com&fp=chrome&pbk=xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU&sid=0123abcd&type=tcp#hop"

const upstreamSS = "ss://YWVzLTI1Ni1nY206aHVudGVyMg@203.0.113.60:8388#hop2"

func xrayObj(t *testing.T, b *Bundle) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(b.Xray, &cfg); err != nil {
		t.Fatalf("xray config is not JSON: %v", err)
	}
	return cfg
}

func tagsOf(t *testing.T, cfg map[string]any, key string) []string {
	t.Helper()
	arr, _ := cfg[key].([]any)
	var out []string
	for _, e := range arr {
		m, _ := e.(map[string]any)
		if s, ok := m["tag"].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// An inbound with an egress must gain an upstream outbound and a routing rule
// that sends only that inbound through it.
func TestEgressAddsUpstreamOutboundAndRule(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{{Node: chainNode("chained", 20401, upstreamVLESS)}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 0 {
		t.Fatalf("inbound was skipped: %+v", b.Skipped)
	}
	cfg := xrayObj(t, b)

	outs := tagsOf(t, cfg, "outbounds")
	found := false
	for _, tag := range outs {
		if strings.HasPrefix(tag, "egress-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no egress outbound was emitted; outbounds = %v", outs)
	}

	routing, _ := cfg["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	if len(rules) < 2 {
		t.Fatalf("expected the api rule plus an egress rule, got %d", len(rules))
	}
	// The api rule must stay first or the local gRPC listener loses its route.
	first, _ := rules[0].(map[string]any)
	if got, _ := first["outboundTag"].(string); got != "api" {
		t.Fatalf("first routing rule must be the api rule, got %q", got)
	}
	last, _ := rules[len(rules)-1].(map[string]any)
	if tag, _ := last["outboundTag"].(string); !strings.HasPrefix(tag, "egress-") {
		t.Fatalf("egress rule points at %q", tag)
	}
	in, _ := last["inboundTag"].([]any)
	if len(in) != 1 {
		t.Fatalf("egress rule should name exactly one inbound, got %v", in)
	}
}

// An inbound with no egress must be completely unaffected: no extra outbound,
// no extra rule. This is the regression that matters, because every existing
// deployment is this case.
func TestNoEgressLeavesTheConfigUnchanged(t *testing.T) {
	plain := chainNode("plain", 20402, "")
	b, err := BuildMulti([]InboundSpec{{Node: plain}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	cfg := xrayObj(t, b)
	for _, tag := range tagsOf(t, cfg, "outbounds") {
		if strings.HasPrefix(tag, "egress-") {
			t.Fatalf("an inbound with no egress produced an egress outbound (%s)", tag)
		}
	}
	routing, _ := cfg["routing"].(map[string]any)
	if rules, _ := routing["rules"].([]any); len(rules) != 1 {
		t.Fatalf("expected only the api rule, got %d", len(rules))
	}
}

// Two inbounds pointing at the SAME upstream must share one outbound. Dialling
// the same hop twice doubles the connections to it for no benefit.
func TestSharedUpstreamIsDialledOnce(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: chainNode("a", 20403, upstreamVLESS)},
		{Node: chainNode("b", 20404, upstreamVLESS)},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	cfg := xrayObj(t, b)
	n := 0
	for _, tag := range tagsOf(t, cfg, "outbounds") {
		if strings.HasPrefix(tag, "egress-") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("two inbounds sharing an upstream produced %d egress outbounds, want 1", n)
	}
	routing, _ := cfg["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	if len(rules) != 3 { // api + one rule per inbound
		t.Fatalf("expected 3 rules (api + 2 inbounds), got %d", len(rules))
	}
}

// Different upstreams get their own outbound, so an operator can run several
// chains side by side.
func TestDistinctUpstreamsGetDistinctOutbounds(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: chainNode("a", 20405, upstreamVLESS)},
		{Node: chainNode("b", 20406, upstreamSS)},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	cfg := xrayObj(t, b)
	seen := map[string]bool{}
	for _, tag := range tagsOf(t, cfg, "outbounds") {
		if strings.HasPrefix(tag, "egress-") {
			seen[tag] = true
		}
	}
	if len(seen) != 2 {
		t.Fatalf("two distinct upstreams produced %d outbounds, want 2", len(seen))
	}
}

// A broken upstream must SKIP the inbound, never fall through to a direct exit.
// Silently egressing directly would leak traffic straight out of the machine the
// operator explicitly told to relay it — the one outcome a chain exists to
// prevent.
func TestBrokenUpstreamSkipsTheInboundRatherThanExitingDirectly(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: chainNode("bad", 20407, "not-a-uri://nonsense")},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 1 {
		t.Fatalf("expected the inbound to be skipped, got %+v", b.Skipped)
	}
	if !strings.Contains(b.Skipped[0].Reason, "egress") {
		t.Fatalf("skip reason should name the egress, got %q", b.Skipped[0].Reason)
	}
	cfg := xrayObj(t, b)
	ins, _ := cfg["inbounds"].([]any)
	if len(ins) != 1 { // api only
		t.Fatalf("the unusable inbound must not be served; inbounds = %d", len(ins))
	}
}

// --- sing-box chains -------------------------------------------------------
//
// Egress was originally honoured on the Xray branch ONLY. A chain set on a
// sing-box inbound (Hysteria2, TUIC, AnyTLS, ShadowTLS) was accepted by the
// API, stored, rendered in the UI and then dropped on the floor by the builder:
// the inbound exited directly with nothing logged. These tests pin the fix.

// chainOf builds a chain from one URI, treating "" as no chain at all.
func chainOf(uri string) model.EgressChain {
	if strings.TrimSpace(uri) == "" {
		return nil
	}
	return model.EgressChain{uri}
}

func sbChainNode(proto model.Protocol, remark string, port int, egress string) *model.Node {
	n := &model.Node{
		Protocol: proto,
		Address:  "0.0.0.0",
		Port:     port,
		Remark:   remark,
		Egress:   chainOf(egress),
		Password: "hunter2hunter2",
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Security: model.Security{Type: "tls", ServerName: "example.com"},
	}
	n.Normalize()
	return n
}

func singboxObj(t *testing.T, b *Bundle) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(b.Singbox, &cfg); err != nil {
		t.Fatalf("sing-box config is not JSON: %v", err)
	}
	return cfg
}

// The regression that mattered: a chained sing-box inbound must actually route
// through the hop, not exit directly.
func TestSingboxEgressRoutesThroughTheHop(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: sbChainNode(model.ProtoHysteria2, "hy2", 20501, upstreamVLESS)},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 0 {
		t.Fatalf("inbound was skipped: %+v", b.Skipped)
	}
	cfg := singboxObj(t, b)

	outs := tagsOf(t, cfg, "outbounds")
	var egressTagName string
	for _, tag := range outs {
		if strings.HasPrefix(tag, "egress-") {
			egressTagName = tag
		}
	}
	if egressTagName == "" {
		t.Fatalf("no egress outbound in the sing-box config; outbounds = %v", outs)
	}

	route, ok := cfg["route"].(map[string]any)
	if !ok {
		t.Fatalf("a chained sing-box inbound produced no route block, so the hop is unreachable")
	}
	if final, _ := route["final"].(string); final != "direct" {
		t.Fatalf(`route.final must stay "direct" so unchained inbounds are unaffected, got %q`, final)
	}
	rules, _ := route["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected one egress rule, got %d", len(rules))
	}
	r, _ := rules[0].(map[string]any)
	if got, _ := r["outbound"].(string); got != egressTagName {
		t.Fatalf("rule points at %q, want %q", got, egressTagName)
	}
	in, _ := r["inbound"].([]any)
	if len(in) == 0 {
		t.Fatalf("rule names no inbound, so it can never match")
	}
}

// An unchained sing-box inbound must produce no route block at all — every
// existing deployment is this case.
func TestSingboxWithoutEgressIsUnchanged(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: sbChainNode(model.ProtoHysteria2, "plain", 20502, "")},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	cfg := singboxObj(t, b)
	if _, present := cfg["route"]; present {
		t.Fatalf("an inbound with no egress produced a route block")
	}
	for _, tag := range tagsOf(t, cfg, "outbounds") {
		if strings.HasPrefix(tag, "egress-") {
			t.Fatalf("an inbound with no egress produced an egress outbound (%s)", tag)
		}
	}
}

// A broken hop must skip the sing-box inbound, exactly as it does for Xray.
// Falling through to direct is the one outcome a chain exists to prevent.
func TestSingboxBrokenUpstreamSkipsRatherThanExitingDirectly(t *testing.T) {
	b, err := BuildMulti([]InboundSpec{
		{Node: sbChainNode(model.ProtoTUIC, "bad", 20503, "not-a-uri://nonsense")},
	}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 1 {
		t.Fatalf("expected the inbound to be skipped, got %+v", b.Skipped)
	}
	if !strings.Contains(b.Skipped[0].Reason, "egress") {
		t.Fatalf("skip reason should name the egress, got %q", b.Skipped[0].Reason)
	}
	cfg := singboxObj(t, b)
	if ins, _ := cfg["inbounds"].([]any); len(ins) != 0 {
		t.Fatalf("the unusable inbound must not be served; inbounds = %d", len(ins))
	}
}

// A WireGuard endpoint has nowhere to attach a per-inbound detour. Silently
// ignoring the chain would leak precisely the traffic it exists to hide, so the
// builder refuses and says why.
func TestWireGuardEndpointRefusesAnEgressInsteadOfIgnoringIt(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoWireGuard,
		Address:  "0.0.0.0",
		Port:     20504,
		Remark:   "wg",
		Egress:   model.EgressChain{upstreamVLESS},
	}
	n.Normalize()
	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 1 {
		t.Fatalf("expected the endpoint to be skipped, got %+v", b.Skipped)
	}
	if !strings.Contains(b.Skipped[0].Reason, "egress") {
		t.Fatalf("skip reason should name the egress, got %q", b.Skipped[0].Reason)
	}
}
