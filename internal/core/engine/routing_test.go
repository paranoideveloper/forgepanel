package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func TestRenderOutboundsCarriesTheCoresOwnFields(t *testing.T) {
	got, err := RenderOutbounds([]OutboundSpec{{
		Tag: "wg-exit", Protocol: "wireguard",
		Settings:       json.RawMessage(`{"secretKey":"k","peers":[{"publicKey":"p","endpoint":"1.2.3.4:51820"}]}`),
		StreamSettings: json.RawMessage(`{"sockopt":{"mark":255}}`),
		SendThrough:    "10.0.0.5",
	}})
	if err != nil {
		t.Fatal(err)
	}
	o := got[0].(jobj)
	if o["tag"] != "wg-exit" || o["protocol"] != "wireguard" {
		t.Fatalf("outbound = %+v", o)
	}
	// Settings are stored verbatim rather than modelled, so they have to arrive
	// as a JSON OBJECT — quoting them into a string produces a config the core
	// rejects.
	if _, ok := o["settings"].(map[string]any); !ok {
		t.Fatalf("settings = %T, want an object", o["settings"])
	}
	if o["sendThrough"] != "10.0.0.5" {
		t.Errorf("sendThrough = %v", o["sendThrough"])
	}
}

func TestDuplicateOutboundTagsAreRefused(t *testing.T) {
	_, err := RenderOutbounds([]OutboundSpec{
		{Tag: "x", Protocol: "freedom"},
		{Tag: "x", Protocol: "blackhole"},
	})
	// Two outbounds of one name make the core's choice arbitrary, so traffic an
	// operator sent to a blackhole could leave the machine instead.
	if err == nil {
		t.Fatal("duplicate outbound tags were accepted")
	}
}

func TestMalformedOutboundSettingsFailLoudly(t *testing.T) {
	_, err := RenderOutbounds([]OutboundSpec{{Tag: "bad", Protocol: "socks",
		Settings: json.RawMessage(`{not json`)}})
	if err == nil {
		t.Fatal("malformed settings were accepted")
	}
	// Skipping it silently would leave every rule that targets it pointing at
	// nothing, and the core then refuses the ENTIRE config — the operator sees
	// every inbound go down with no indication which outbound caused it.
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error does not name the outbound: %v", err)
	}
}

func TestRulesTranslateEveryMatcher(t *testing.T) {
	known := map[string]bool{"direct": true, "block": true, "proxy": true}
	got, err := RenderRules([]RuleSpec{{
		Name: "everything", Domain: []string{"geosite:ads"}, IP: []string{"geoip:ir"},
		Port: "80,443", Network: "tcp", Protocol: []string{"tls"},
		InboundTags: []string{"in-1"}, UserEmails: []string{"u.7"}, OutboundTag: "block",
	}}, known)
	if err != nil {
		t.Fatal(err)
	}
	r := got[0].(jobj)
	for k, want := range map[string]any{"type": "field", "outboundTag": "block", "port": "80,443", "network": "tcp"} {
		if r[k] != want {
			t.Errorf("%s = %v, want %v", k, r[k], want)
		}
	}
	for _, k := range []string{"domain", "ip", "protocol", "inboundTag", "user"} {
		if r[k] == nil {
			t.Errorf("matcher %q was dropped; a rule that silently loses a condition matches more than the operator asked for", k)
		}
	}
}

func TestRuleWithNoConditionsIsRefused(t *testing.T) {
	_, err := RenderRules([]RuleSpec{{Name: "catch-all", OutboundTag: "block"}},
		map[string]bool{"block": true})
	// Placed above a carefully ordered list, a condition-less rule silently
	// swallows all of it and routing appears to have "stopped working".
	if err == nil {
		t.Fatal("a rule with no conditions was accepted; it would match all traffic")
	}
}

func TestRuleTargetingAnUndefinedOutboundIsRefused(t *testing.T) {
	_, err := RenderRules([]RuleSpec{{Name: "r", Domain: []string{"a.com"}, OutboundTag: "ghost"}},
		map[string]bool{"direct": true})
	if err == nil {
		t.Fatal("a rule pointing at an undefined outbound was accepted")
	}
	// The core refuses the whole config for this, taking every inbound down. The
	// error has to name the rule and the tag or the operator cannot find it.
	if !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "r") {
		t.Errorf("error names neither the rule nor the tag: %v", err)
	}
}

// --- ordering, which is a safety property ----------------------------------

func routingOf(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var doc struct {
		Routing struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Routing.Rules
}

func chainedSpec() InboundSpec {
	n := &model.Node{
		Protocol: model.ProtoVLESS,
		Address:  "0.0.0.0",
		Port:     443,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Remark:   "chained",
		Egress:   model.EgressChain{"socks://127.0.0.1:1080"},
	}
	n.Normalize()
	return InboundSpec{Node: n, Clients: []ClientCred{
		{UUID: "11111111-1111-1111-1111-111111111111", Email: "u.1"}}}
}

func TestOperatorRulesComeAfterEgress(t *testing.T) {
	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		nil,
		[]RuleSpec{{Name: "direct-leak", Domain: []string{"example.com"}, OutboundTag: "direct"}})
	if err != nil {
		t.Fatal(err)
	}
	rules := routingOf(t, b.Xray)
	if len(rules) < 3 {
		t.Fatalf("rules = %+v, want api + egress + operator", rules)
	}
	if rules[0]["outboundTag"] != "api" {
		t.Fatalf("first rule is %v, want the api rule", rules[0]["outboundTag"])
	}
	// THE POINT: an inbound with a relay chain was explicitly told to send
	// everything through it. If this operator rule were evaluated first, an
	// ordinary "send example.com direct" would pull that domain out of the
	// chain and expose the server's real address for it — a deanonymisation
	// caused by a rule that looks harmless. The reverse cost (a block rule not
	// applying to chained traffic) is visible and harmless.
	// The egress rule is identified by its generated outbound tag rather than by
	// the inbound's name, which Normalize assigns.
	egressIdx, opIdx := -1, -1
	for i, r := range rules {
		if tag, _ := r["outboundTag"].(string); strings.HasPrefix(tag, "egress-") {
			egressIdx = i
		}
		if r["domain"] != nil {
			opIdx = i
		}
	}
	if egressIdx < 0 || opIdx < 0 {
		t.Fatalf("did not find both rules: egress=%d operator=%d in %+v", egressIdx, opIdx, rules)
	}
	if egressIdx > opIdx {
		t.Fatal("an operator rule is evaluated BEFORE a relay chain; a 'send this domain direct' rule would leak traffic out of the chain")
	}
}

func TestDirectStaysTheFirstOutbound(t *testing.T) {
	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		[]OutboundSpec{{Tag: "mine", Protocol: "freedom"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(b.Xray, &doc); err != nil {
		t.Fatal(err)
	}
	// Xray uses the FIRST outbound for anything no rule matched. Demoting
	// "direct" would silently change where unmatched traffic goes on every
	// existing installation.
	if doc.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("first outbound = %v, want direct", doc.Outbounds[0]["tag"])
	}
	found := false
	for _, o := range doc.Outbounds {
		if o["tag"] == "mine" {
			found = true
		}
	}
	if !found {
		t.Fatal("the operator's outbound is not in the config")
	}
}

func TestNoRulesRendersExactlyWhatItAlwaysDid(t *testing.T) {
	with, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	without, err := BuildMulti([]InboundSpec{chainedSpec()}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// A panel with no routing configured must generate a byte-identical config.
	// Anything else is a silent behaviour change shipped to every existing
	// installation as part of adding a feature they are not using.
	if string(with.Xray) != string(without.Xray) {
		t.Fatal("adding the routing feature changed the config of a panel that has no routing configured")
	}
}

// TestRoutingConfigIsAcceptedByTheRealCore is the one that matters: the schema
// belongs to Xray, and a hand-rolled opinion about it is worth nothing.
func TestRoutingConfigIsAcceptedByTheRealCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		[]OutboundSpec{
			{Tag: "relay", Protocol: "socks",
				Settings: json.RawMessage(`{"servers":[{"address":"127.0.0.1","port":1080}]}`)},
			{Tag: "hole", Protocol: "blackhole"},
		},
		[]RuleSpec{
			{Name: "ads", Domain: []string{"geosite:category-ads-all"}, OutboundTag: "hole"},
			{Name: "ir-direct", IP: []string{"geoip:ir"}, OutboundTag: "direct"},
			{Name: "one-user", UserEmails: []string{"u.1"}, OutboundTag: "relay"},
			{Name: "ports", Port: "80,443", Network: "tcp", Protocol: []string{"tls"}, OutboundTag: "relay"},
		})
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("the real core rejected the generated routing config: %v\n%s\n--- config ---\n%s", err, out, b.Xray)
	}
}
