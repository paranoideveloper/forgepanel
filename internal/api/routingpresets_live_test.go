package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Every shipped preset, checked by the REAL core.
//
// This test exists because it caught a real defect while it was being written:
// the BitTorrent preset referenced `geosite:category-bittorrent`, which does not
// exist in geosite.dat — nor do `bittorrent`, `torrent`, `category-torrent` or
// `p2p`, all checked. Applying that preset would have made the core refuse the
// ENTIRE config, taking every inbound on the box down, for a policy described to
// the operator as a one-click convenience.
//
// A geosite name is not something that can be verified by reading code or
// documentation. Only the database says.
func TestEveryPresetIsAcceptedByTheRealCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	// One real inbound, so the generated config is a config the core will parse
	// rather than an empty document that trivially passes.
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 8443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "preset-check",
	}
	n.Normalize()
	specs := []engine.InboundSpec{{Node: n, Clients: []engine.ClientCred{
		{UUID: "11111111-1111-1111-1111-111111111111", Email: job.UserEmail(1)}}}}

	dir := t.TempDir()
	for _, p := range routingPresets() {
		rules := make([]engine.RuleSpec, 0, len(p.Rules))
		for _, r := range p.Rules {
			rules = append(rules, engine.RuleSpec{
				Name: r.Name, Domain: r.Domain, IP: r.IP, Port: r.Port,
				Network: r.Network, Protocol: r.Protocol,
				InboundTags: r.InboundTags, OutboundTag: r.OutboundTag,
			})
		}
		b, err := engine.BuildMultiWithRouting(specs, 10085, "", "", nil, rules, nil)
		if err != nil {
			t.Fatalf("preset %q did not render: %v", p.Name, err)
		}
		path := filepath.Join(dir, p.Name+".json")
		if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput()
		if err != nil {
			t.Errorf("preset %q is REJECTED by the core; applying it would take every inbound down:\n%s",
				p.Name, out)
		}
	}
}

// TestRoutingPresetsAreWellFormed checks the parts that need no core: every preset must have
// a name, a stated reason, and at least one rule with a condition.
func TestRoutingPresetsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range routingPresets() {
		if p.Name == "" || p.Title == "" || p.Why == "" {
			t.Errorf("preset %+v does not say what it is or why", p)
		}
		if seen[p.Name] {
			t.Errorf("two presets are named %q", p.Name)
		}
		seen[p.Name] = true
		if len(p.Rules) == 0 {
			t.Errorf("preset %q has no rules", p.Name)
		}
		for _, r := range p.Rules {
			if r.Name == "" {
				t.Errorf("preset %q has an unnamed rule", p.Name)
			}
			// Rule names must be unique across ALL presets: the apply path is
			// idempotent by NAME, so two presets sharing one would make applying
			// the second silently skip a rule the operator asked for.
			if !r.Enabled {
				t.Errorf("preset %q ships a disabled rule %q, which does nothing", p.Name, r.Name)
			}
			if len(r.Domain) == 0 && len(r.IP) == 0 && r.Port == "" &&
				len(r.Protocol) == 0 && len(r.InboundTags) == 0 {
				t.Errorf("preset %q rule %q has no conditions and would match all traffic", p.Name, r.Name)
			}
			if r.OutboundTag == "" {
				t.Errorf("preset %q rule %q has no outbound", p.Name, r.Name)
			}
		}
	}
	if _, err := json.Marshal(routingPresets()); err != nil {
		t.Fatalf("presets do not serialise: %v", err)
	}
}

func TestPresetRuleNamesAreGloballyUnique(t *testing.T) {
	owner := map[string]string{}
	for _, p := range routingPresets() {
		for _, r := range p.Rules {
			if prev, dup := owner[r.Name]; dup {
				// Applying is idempotent by rule NAME. Two presets sharing one
				// would make the second silently skip a rule the operator asked
				// for, and the panel would report success.
				t.Errorf("rule name %q is used by both %q and %q", r.Name, prev, p.Name)
			}
			owner[r.Name] = p.Name
		}
	}
}
