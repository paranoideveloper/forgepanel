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

	local, _ := s.localInboundSpecs()
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
	if got, _ := s.localInboundSpecs(); len(got) != 1 {
		t.Fatalf("a panel with no nodes serves %d inbound(s), want 1", len(got))
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
	i := strings.Index(body, "s.engine.ReloadSpecs(specs)")
	if i < 0 {
		t.Fatal("could not find the reload call — this guard needs updating, not deleting")
	}
	// The assignment to specs immediately above the reload.
	start := strings.LastIndex(body[:i], "specs")
	start = strings.LastIndex(body[:start], "\n")
	if start < 0 {
		t.Fatal("could not find where specs is built")
	}
	line := strings.TrimSpace(body[start:i])
	if !strings.Contains(line, "s.reloadSpecs()") {
		t.Errorf("the panel's reload builds specs with %q — if that is the unfiltered list, one "+
			"inbound bound to a node's address stops the panel's own core from starting at all", line)
	}

	// The chain is an indirection, so following it is part of the guard: it must
	// still end at the FILTERED list and never at the raw enabled one. Checking
	// only the call site above would let the filter be removed one function
	// further down with this test still green.
	j := strings.Index(body, "func (s *Server) specsForBuild()")
	if j < 0 {
		t.Fatal("specsForBuild is gone; this guard needs updating, not deleting")
	}
	fn := body[j:]
	if k := strings.Index(fn[1:], "\nfunc "); k > 0 {
		fn = fn[:k]
	}
	if !strings.Contains(fn, "s.localInboundSpecs()") {
		t.Error("specsForBuild no longer returns the filtered list for a normal install")
	}
	if strings.Contains(fn, "s.enabledInboundSpecs()") {
		t.Error("specsForBuild hands the cores the unfiltered list")
	}
	// And reloadSpecs must go through it rather than building its own list.
	k := strings.Index(body, "func (s *Server) reloadSpecs()")
	if k < 0 {
		t.Fatal("reloadSpecs is gone; this guard needs updating")
	}
	rf := body[k:]
	if m := strings.Index(rf[1:], "\nfunc "); m > 0 {
		rf = rf[:m]
	}
	if !strings.Contains(rf, "s.specsForBuild()") {
		t.Error("reloadSpecs builds its own spec list instead of the shared one, so validation " +
			"and the running config can drift apart again")
	}
}

// The case the node-address filter missed, and that took the panel down a second
// time: an operator pastes a subscription into the importer and gets a hundred
// inbounds addressed to OTHER PEOPLE'S servers. Those are not nodes and are not
// here, so a filter that only knows about enrolled nodes lets every one of them
// through — and the core dies on the first address it cannot bind, taking every
// locally-created inbound with it.
//
// Measured on a live panel: 110 imported configs, xray crashed, 41 restarts,
// nothing the operator had created working. Their report was, for the second
// time, "why does nothing I create on the panel work".
func TestImportedForeignConfigsAreNotServedLocally(t *testing.T) {
	s, token := adminAPI(t)

	for _, in := range []map[string]any{
		// What the importer produces from a scraped subscription.
		{"protocol": "vless", "address": "13.113.18.50", "port": 36582, "remark": "collector-300",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "none"}, "enabled": true},
		{"protocol": "vless", "address": "usejh2.neobo-tooth.ru", "port": 2083, "remark": "collector-043",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "none"}, "enabled": true},
		// The operator's own, on this machine.
		{"protocol": "vless", "address": "0.0.0.0", "port": 28000, "remark": "mine",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"}, "enabled": true},
	} {
		if code, b := realPost(t, s, "/api/admin/inbounds", token, in); code != 201 && code != 200 {
			t.Fatalf("create %v: %d %s", in["remark"], code, b)
		}
	}

	var served []string
	localSpecs, _ := s.localInboundSpecs()
	for _, sp := range localSpecs {
		if sp.Node != nil {
			served = append(served, sp.Node.Remark)
		}
	}
	for _, foreign := range []string{"collector-300", "collector-043"} {
		for _, got := range served {
			if got == foreign {
				t.Errorf("the panel is trying to serve %q, which lives on someone else's machine — "+
					"the core cannot bind it and refuses the whole config", foreign)
			}
		}
	}
	found := false
	for _, got := range served {
		if got == "mine" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the operator's own inbound was filtered out; the panel serves %v", served)
	}
}

// The bindability rule itself. Getting this wrong in the permissive direction
// kills the core; in the strict direction it silently stops serving.
func TestBoundHereAcceptsOnlyWhatThisHostCanBind(t *testing.T) {
	local := map[string]bool{"203.0.113.5": true}
	for _, c := range []struct {
		addr string
		want bool
		why  string
	}{
		{"", true, "no address is the default and means this machine"},
		{"0.0.0.0", true, "wildcard"},
		{"::", true, "v6 wildcard"},
		{"127.0.0.1", true, "loopback"},
		{"203.0.113.5", true, "an address this host holds"},
		{"198.51.100.9", false, "someone else's machine"},
		{"13.113.18.50", false, "an imported foreign config"},
		{"no-such-host.invalid", false, "a name that cannot resolve is one the core cannot bind"},
	} {
		if got := boundHere(c.addr, local); got != c.want {
			t.Errorf("boundHere(%q) = %v, want %v — %s", c.addr, got, c.want, c.why)
		}
	}
}

// Filtering an unbindable inbound is right. Doing it SILENTLY is the bug.
//
// An inbound whose address this host cannot bind is dropped from the generated
// config — correctly, because the core would refuse the whole config over it.
// But nothing recorded why: the panel reported the inbound enabled, reachable,
// and not-serving-for-no-reason, with nothing in the engine log and nothing
// listening. That is the exact "configured, enabled, carries nothing" failure
// the not-serving-reason mechanism exists to end, and it cost real debugging
// time on a live panel before it was traced back to this line.
func TestAnUnbindableInboundIsReportedRatherThanVanishing(t *testing.T) {
	s, token := adminAPI(t)
	for _, in := range []map[string]any{
		{"protocol": "vless", "address": "0.0.0.0", "port": 28010, "remark": "ours",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"}, "enabled": true},
		// A hostname this machine does not own. It resolves — the shape an
		// operator actually produces when they paste a CDN or relay hostname
		// into the address field, which is how this was found.
		{"protocol": "vless", "address": "example.com", "port": 28011, "remark": "not-ours",
			"transport": map[string]any{"network": "tcp"}, "security": map[string]any{"type": "reality"}, "enabled": true},
	} {
		if code, b := realPost(t, s, "/api/admin/inbounds", token, in); code != 201 && code != 200 {
			t.Fatalf("create %v: %d %s", in["remark"], code, b)
		}
	}

	specs, skipped := s.reloadSpecs()

	var served []string
	for _, sp := range specs {
		if sp.Node != nil {
			served = append(served, sp.Node.Remark)
		}
	}
	for _, r := range served {
		if r == "not-ours" {
			t.Fatal("an inbound on an address this host cannot bind was handed to the core; " +
				"xray refuses the whole config over one bad bind, taking every other inbound down")
		}
	}
	if len(served) == 0 {
		t.Fatal("the panel's own inbound went with it")
	}

	// The load-bearing assertion: it was REPORTED, not just removed.
	var reason string
	for _, sk := range skipped {
		if sk.Remark == "not-ours" {
			reason = sk.Reason
		}
	}
	if reason == "" {
		t.Fatal("the inbound was dropped with no reason recorded — the panel shows it " +
			"enabled and serving nothing, which is indistinguishable from a bug in the core")
	}
	// And the reason has to name the cause, or it sends the operator looking in
	// the wrong place.
	if !strings.Contains(reason, "example.com") {
		t.Errorf("reason %q does not name the address that cannot be bound", reason)
	}
}
