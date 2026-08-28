package api

import (
	"os"
	"strings"
	"testing"
)

// A core cannot bind another machine's IP, and it refuses a config as a WHOLE.
// So one inbound bound to an enrolled node's address stopped the PANEL's own
// xray from starting at all, and every inbound the panel served itself went with
// it:
//
//	failed to listen TCP on 25443 > listen tcp 94.183.174.37:25443:
//	bind: cannot assign requested address
//
// Measured on a live panel with two nodes: 270 restart attempts, xray never up,
// every locally-created inbound dead, and the UI showing all of them enabled.
// The node side has always had enabledInboundSpecsForNodeAddress; the panel side
// had no filter and took the whole list.
func TestThePanelDoesNotTryToServeANodesInbounds(t *testing.T) {
	s, token := adminAPI(t)

	if code, b := realPost(t, s, "/api/admin/nodes/enroll", token,
		map[string]any{"name": "remote", "address": "94.183.174.37"}); code != 201 {
		t.Fatalf("enrol: %d %s", code, b)
	}
	// One inbound on the node, one here. The local one is what must survive.
	for _, in := range []map[string]any{
		{"protocol": "vless", "address": "94.183.174.37", "port": 25443, "remark": "on-the-node",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"}, "enabled": true},
		{"protocol": "vless", "address": "0.0.0.0", "port": 28000, "remark": "on-the-panel",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"}, "enabled": true},
	} {
		if code, b := realPost(t, s, "/api/admin/inbounds", token, in); code != 201 && code != 200 {
			t.Fatalf("create %v: %d %s", in["remark"], code, b)
		}
	}

	local := s.localInboundSpecs()
	var remarks []string
	for _, sp := range local {
		if sp.Node != nil {
			remarks = append(remarks, sp.Node.Remark)
			if sp.Node.Address == "94.183.174.37" {
				t.Errorf("the panel is trying to serve %q, which is bound to a node's address — "+
					"xray cannot bind it and refuses the whole config", sp.Node.Remark)
			}
		}
	}
	// The local one must still be there: filtering must not throw away the
	// inbounds the panel is actually responsible for.
	found := false
	for _, r := range remarks {
		if r == "on-the-panel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the panel's own inbound was filtered out too; it serves %v", remarks)
	}

	// And the node still gets its own.
	onNode := s.enabledInboundSpecsForNodeAddress("94.183.174.37")
	var nodeRemarks []string
	for _, sp := range onNode {
		if sp.Node != nil {
			nodeRemarks = append(nodeRemarks, sp.Node.Remark)
		}
	}
	if len(nodeRemarks) == 0 {
		t.Error("the node was left with nothing to serve")
	}
}

// With no nodes enrolled — the ordinary single-box panel — nothing is filtered.
func TestASingleBoxPanelServesEverything(t *testing.T) {
	s, token := adminAPI(t)
	if code, b := realPost(t, s, "/api/admin/inbounds", token, map[string]any{
		"protocol": "vless", "address": "0.0.0.0", "port": 28001, "remark": "solo",
		"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"},
		"enabled": true,
	}); code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	if got := len(s.localInboundSpecs()); got != 1 {
		t.Fatalf("a panel with no nodes serves %d inbound(s), want 1", got)
	}
}

// The WIRING, not the function. The test above calls localInboundSpecs directly
// and passes even with the reload still calling the unfiltered
// enabledInboundSpecs — which is the whole defect. This reads the call site.
//
// A source-level check because the alternative is standing up a real core in a
// unit test; the thing that can silently regress is which of two very similarly
// named functions the reload calls.
func TestTheReloadPathUsesTheFilteredSpecList(t *testing.T) {
	src, err := os.ReadFile("engines.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "bundle, _ := s.engine.ReloadSpecs(specs)")
	if i < 0 {
		t.Fatal("could not find the reload call — this guard needs updating, not deleting")
	}
	// The assignment to specs immediately above the reload.
	start := strings.LastIndex(body[:i], "specs := ")
	if start < 0 {
		t.Fatal("could not find where specs is built")
	}
	line := body[start:i]
	if !strings.Contains(line, "s.localInboundSpecs()") {
		t.Errorf("the panel's reload builds specs with %q — if that is the unfiltered list, one "+
			"inbound bound to a node's address stops the panel's own core from starting at all",
			strings.TrimSpace(line))
	}
}
