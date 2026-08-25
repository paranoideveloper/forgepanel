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
		Egress:   egress,
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
