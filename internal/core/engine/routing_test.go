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
	}}, known, nil)
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
		map[string]bool{"block": true}, nil)
	// Placed above a carefully ordered list, a condition-less rule silently
	// swallows all of it and routing appears to have "stopped working".
	if err == nil {
		t.Fatal("a rule with no conditions was accepted; it would match all traffic")
	}
}

func TestRuleTargetingAnUndefinedOutboundIsRefused(t *testing.T) {
	_, err := RenderRules([]RuleSpec{{Name: "r", Domain: []string{"a.com"}, OutboundTag: "ghost"}},
		map[string]bool{"direct": true}, nil)
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
		[]RuleSpec{{Name: "direct-leak", Domain: []string{"example.com"}, OutboundTag: "direct"}}, nil)
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
		[]OutboundSpec{{Tag: "mine", Protocol: "freedom"}}, nil, nil)
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
	with, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "", nil, nil, nil)
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
			{Tag: "backup", Protocol: "socks",
				Settings: json.RawMessage(`{"servers":[{"address":"127.0.0.2","port":1080}]}`)},
			{Tag: "hole", Protocol: "blackhole"},
		},
		[]RuleSpec{
			{Name: "ads", Domain: []string{"geosite:category-ads-all"}, OutboundTag: "hole"},
			{Name: "ir-direct", IP: []string{"geoip:ir"}, OutboundTag: "direct"},
			{Name: "one-user", UserEmails: []string{"u.1"}, OutboundTag: "relay"},
			{Name: "ports", Port: "80,443", Network: "tcp", Protocol: []string{"tls"}, OutboundTag: "relay"},
			// The balancer path, which is the only one a panel-side assertion
			// cannot judge: "balancerTag" vs "outboundTag", the shape of
			// burstObservatory and whether fallbackTag exists at all are Xray's
			// opinions, and getting any of them wrong rejects the whole config.
			{Name: "web", Domain: []string{"domain:example.com"}, OutboundTag: "failover"},
		},
		[]GroupSpec{{
			Tag: "failover", Members: []string{"relay", "backup"},
			Strategy: "leastPing", ProbeURL: "https://www.gstatic.com/generate_204",
			ProbeInterval: "60s", FallbackTag: "hole",
		}})
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

// --- failover groups --------------------------------------------------------

// A group is a BALANCER, and every part of it is load-bearing. A balancer with
// no observatory never learns a member is down, so it "fails over" to a relay
// that stopped answering an hour ago. A balancer with no fallback leaves the
// core to choose when every member is down. And a rule that points at a balancer
// with "outboundTag" is not refused by anything — measured on Xray 26.2.6 the
// config validates and the core starts, then every connection that rule matches
// is dropped with one "non existing outTag" line in the log. The operator's
// failover feature becomes the outage it was bought to prevent, quietly.
func TestFailoverGroupRendersABalancerWithObservatoryAndFallback(t *testing.T) {
	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		[]OutboundSpec{
			{Tag: "relay-a", Protocol: "socks",
				Settings: json.RawMessage(`{"servers":[{"address":"127.0.0.1","port":1080}]}`)},
			{Tag: "relay-b", Protocol: "socks",
				Settings: json.RawMessage(`{"servers":[{"address":"127.0.0.2","port":1080}]}`)},
		},
		[]RuleSpec{{Name: "web", Domain: []string{"example.com"}, OutboundTag: "failover"}},
		[]GroupSpec{{
			Tag: "failover", Members: []string{"relay-a", "relay-b"},
			Strategy: "leastPing", ProbeURL: "https://www.gstatic.com/generate_204",
			ProbeInterval: "60s", FallbackTag: "block",
		}})
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Routing struct {
			Rules     []map[string]any `json:"rules"`
			Balancers []struct {
				Tag         string   `json:"tag"`
				Selector    []string `json:"selector"`
				FallbackTag string   `json:"fallbackTag"`
				Strategy    struct {
					Type string `json:"type"`
				} `json:"strategy"`
			} `json:"balancers"`
		} `json:"routing"`
		BurstObservatory struct {
			SubjectSelector []string `json:"subjectSelector"`
			PingConfig      struct {
				Destination string `json:"destination"`
				Interval    string `json:"interval"`
			} `json:"pingConfig"`
		} `json:"burstObservatory"`
	}
	if err := json.Unmarshal(b.Xray, &doc); err != nil {
		t.Fatal(err)
	}

	if len(doc.Routing.Balancers) != 1 {
		t.Fatalf("balancers = %+v, want exactly one", doc.Routing.Balancers)
	}
	bal := doc.Routing.Balancers[0]
	if bal.Tag != "failover" || strings.Join(bal.Selector, ",") != "relay-a,relay-b" {
		t.Errorf("balancer = %+v", bal)
	}
	if bal.Strategy.Type != "leastPing" {
		t.Errorf("strategy = %q; a balancer with no strategy round-robins onto dead members", bal.Strategy.Type)
	}
	// Measured on Xray 26.2.6: with every member unreachable and NO fallbackTag,
	// the connection goes out DIRECT — the server's real address, past the
	// relays. The fallback is what turns a failed group into a drop instead of
	// a leak, so losing it from the render is not cosmetic.
	if bal.FallbackTag != "block" {
		t.Errorf("fallbackTag = %q, want block", bal.FallbackTag)
	}

	// The observatory is what makes it a FAILOVER group rather than a load
	// balancer: without it every member looks alive forever.
	if strings.Join(doc.BurstObservatory.SubjectSelector, ",") != "relay-a,relay-b" {
		t.Errorf("burstObservatory.subjectSelector = %v; the members are never probed",
			doc.BurstObservatory.SubjectSelector)
	}
	if doc.BurstObservatory.PingConfig.Destination != "https://www.gstatic.com/generate_204" {
		t.Errorf("pingConfig.destination = %q", doc.BurstObservatory.PingConfig.Destination)
	}
	if doc.BurstObservatory.PingConfig.Interval != "60s" {
		t.Errorf("pingConfig.interval = %q", doc.BurstObservatory.PingConfig.Interval)
	}

	var opRule map[string]any
	for _, r := range doc.Routing.Rules {
		if r["domain"] != nil {
			opRule = r
		}
	}
	if opRule == nil {
		t.Fatalf("the operator rule is missing: %+v", doc.Routing.Rules)
	}
	if opRule["balancerTag"] != "failover" {
		t.Errorf("rule targets balancerTag=%v, want failover", opRule["balancerTag"])
	}
	// Both keys at once is not "belt and braces". Xray takes outboundTag when
	// both are present, so the rule targets a tag no outbound defines and the
	// connections are dropped exactly as if balancerTag had never been written.
	if _, has := opRule["outboundTag"]; has {
		t.Errorf("the rule also carries outboundTag; Xray refuses that and rejects the whole config: %+v", opRule)
	}
}

// The leak this feature could ship with. Measured on Xray 26.2.6: a balancer
// whose members are all unreachable and which carries NO fallbackTag sends the
// connection out direct — the server's own address, past every relay. An
// operator who never filled the field in would be leaking at exactly the moment
// their exits failed, so the renderer refuses to produce that balancer at all.
func TestAGroupWithNoFallbackStillBlocksWhenEveryMemberIsDown(t *testing.T) {
	got, _, err := RenderBalancers([]GroupSpec{{Tag: "g", Members: []string{"relay-a"}}},
		map[string]bool{"block": true, "relay-a": true})
	if err != nil {
		t.Fatal(err)
	}
	if tag := got[0].(jobj)["fallbackTag"]; tag != "block" {
		t.Fatalf("fallbackTag = %v; with none, an all-members-down group exits direct", tag)
	}
}

func TestAGroupMemberThatNoOutboundDefinesIsRefused(t *testing.T) {
	_, _, err := RenderBalancers([]GroupSpec{{Tag: "g", Members: []string{"relay-a", "ghost"}}},
		map[string]bool{"direct": true, "block": true, "relay-a": true})
	if err == nil {
		t.Fatal("a group selecting an undefined outbound was accepted")
	}
	// Xray's selector is a PREFIX match, so a typo'd member does not fail loudly
	// in the core. Measured on 26.2.6: a balancer whose selector matches no
	// outbound sends its traffic out DIRECT, from the server's own address, with
	// fallbackTag ignored — a leak that validates and logs nothing.
	if !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "g") {
		t.Errorf("error names neither the group nor the member: %v", err)
	}
}

func TestTwoGroupsCannotAskForDifferentProbes(t *testing.T) {
	known := map[string]bool{"a": true, "b": true, "block": true}
	_, _, err := RenderBalancers([]GroupSpec{
		{Tag: "g1", Members: []string{"a"}, ProbeURL: "https://one.example/generate_204", ProbeInterval: "60s"},
		{Tag: "g2", Members: []string{"b"}, ProbeURL: "https://two.example/generate_204", ProbeInterval: "60s"},
	}, known)
	// Xray has ONE burstObservatory for the whole config. Honouring the first
	// group's probe and silently discarding the second's would leave an operator
	// watching a probe URL that is not the one their group is graded on.
	if err == nil {
		t.Fatal("two groups with conflicting probe settings were accepted; only one can be honoured")
	}
}

// A group is an XRAY construct. The sing-box half of the bundle has no operator
// outbounds at all (their settings are Xray's own JSON), so emitting a sing-box
// urltest over their tags would name outbounds that config does not define —
// sing-box refuses the whole document and every hysteria2, TUIC, AnyTLS and
// ShadowTLS inbound on the box stops serving.
func TestAGroupDoesNotLeakIntoTheSingboxConfig(t *testing.T) {
	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		[]OutboundSpec{{Tag: "relay-a", Protocol: "blackhole"}},
		[]RuleSpec{{Name: "web", Domain: []string{"example.com"}, OutboundTag: "failover"}},
		[]GroupSpec{{Tag: "failover", Members: []string{"relay-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"urltest", "failover", "relay-a"} {
		if strings.Contains(string(b.Singbox), bad) {
			t.Errorf("the sing-box config names %q, which it defines no outbound for: %s", bad, b.Singbox)
		}
	}
}
