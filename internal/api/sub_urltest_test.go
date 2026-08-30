package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
)

// The auto-select group.
//
// Without it a subscription's default is whichever node happened to be rendered
// first, which is not the one that is up — and most people never open the group
// list to change it. Both flavours therefore lead with a latency-tested group
// and make it the default.

func twoNodes() []*model.Node {
	return []*model.Node{
		{Protocol: model.ProtoVMess, Address: "a.example.com", Port: 443, Remark: "A",
			UUID: "11111111-1111-1111-1111-111111111111"},
		{Protocol: model.ProtoVMess, Address: "b.example.com", Port: 443, Remark: "B",
			UUID: "22222222-2222-2222-2222-222222222222"},
	}
}

func TestClashLeadsWithALatencyTestedGroup(t *testing.T) {
	y, err := export.ClashYAML(twoNodes())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(y, "type: url-test") {
		t.Fatalf("no url-test group:\n%s", y)
	}
	if !strings.Contains(y, export.ClashAutoSelect) {
		t.Error("the auto group is not named")
	}
	// Tolerance matters: without it the group flaps between two nodes a few
	// milliseconds apart, and every switch drops the connections on the old one.
	if !strings.Contains(y, "tolerance:") {
		t.Error("no tolerance, so the group will flap between near-equal nodes")
	}
	if !strings.Contains(y, "interval:") || !strings.Contains(y, "url:") {
		t.Error("a url-test group with no url or interval never tests anything")
	}

	// The auto group must be listed inside the selector, and first, or the
	// client still defaults to a specific node.
	sel := y[strings.Index(y, export.ClashProxySelector):]
	autoAt, aAt := strings.Index(sel, export.ClashAutoSelect), strings.Index(sel, "- A")
	if autoAt < 0 {
		t.Fatal("the selector does not list the auto group")
	}
	if aAt >= 0 && autoAt > aAt {
		t.Error("the auto group is not the selector's first member")
	}
}

func TestSingboxLeadsWithALatencyTestedGroup(t *testing.T) {
	raw := singboxSubscription(twoNodes(), routing.Options{}, routing.Fragment{})
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var auto, selector map[string]any
	for _, o := range doc.Outbounds {
		switch o["type"] {
		case "urltest":
			auto = o
		case "selector":
			selector = o
		}
	}
	if auto == nil {
		t.Fatalf("no urltest outbound:\n%s", raw)
	}
	if selector == nil {
		t.Fatal("no selector outbound")
	}
	// sing-box wants a DURATION STRING here. A bare integer is rejected at parse
	// time and takes the whole subscription with it, which is why this asserts
	// the type and not just the presence.
	if _, ok := auto["interval"].(string); !ok {
		t.Errorf("interval is %T, want a duration string like \"60s\" — sing-box rejects a number", auto["interval"])
	}
	if selector["default"] != sbAutoTag {
		t.Errorf("selector default = %v, want %q so an untouched client uses the fastest node",
			selector["default"], sbAutoTag)
	}
}

// A urltest over one outbound measures it and then picks it. Emitting the group
// anyway adds a layer, a timer and a periodic request that buy nothing.
func TestASingleNodeGetsNoAutoGroup(t *testing.T) {
	one := twoNodes()[:1]

	y, err := export.ClashYAML(one)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(y, "type: url-test") {
		t.Error("clash emitted an auto group for a single node")
	}

	raw := singboxSubscription(one, routing.Options{}, routing.Fragment{})
	if strings.Contains(string(raw), `"urltest"`) {
		t.Error("sing-box emitted an auto group for a single node")
	}
}

// sing-box refuses a config with two outbounds sharing a tag, so a node whose
// own tag is "auto" would take the entire subscription down.
func TestANodeCannotClaimTheAutoTag(t *testing.T) {
	nodes := twoNodes()
	nodes[0].Tag = sbAutoTag
	nodes[1].Tag = sbAutoTag

	raw := singboxSubscription(nodes, routing.Options{}, routing.Fragment{})
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, o := range doc.Outbounds {
		tag, _ := o["tag"].(string)
		seen[tag]++
	}
	for tag, n := range seen {
		if n > 1 {
			t.Errorf("tag %q appears %d times; sing-box refuses the whole config", tag, n)
		}
	}
	if seen[sbAutoTag] != 1 {
		t.Errorf("the auto tag appears %d times, want exactly the group's own", seen[sbAutoTag])
	}
}

func TestTheAutoIntervalHasSaneDefaults(t *testing.T) {
	if export.DefaultURLTestInterval < 10 || export.DefaultURLTestInterval > 3600 {
		t.Errorf("interval %d is outside anything reasonable", export.DefaultURLTestInterval)
	}
	if export.DefaultURLTolerance <= 0 {
		t.Error("a zero tolerance makes the group flap")
	}
	a := export.AutoSelect{}
	y, err := export.ClashYAMLAuto(twoNodes(), a)
	if err != nil {
		t.Fatal(err)
	}
	// The zero value must not produce interval: 0 — a url-test group that tests
	// continuously is a request flood from every client at once.
	if strings.Contains(y, "interval: 0") {
		t.Error("the zero AutoSelect rendered interval 0, which tests without pause")
	}
}
