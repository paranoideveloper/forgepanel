package routing

import (
	"net/url"
	"strings"
	"testing"
)

func TestPresetAndEnabled(t *testing.T) {
	if Preset("off").Enabled() {
		t.Fatal("off preset should be disabled")
	}
	if !Preset("iran").BypassIran {
		t.Fatal("iran preset should bypass Iran")
	}
	full := Preset("full")
	if !(full.BypassIran && full.DirectLAN && full.BlockAds && full.BlockMalware && full.BlockPorn && full.BlockQUIC) {
		t.Fatalf("full preset missing toggles: %+v", full)
	}
	// Unknown name falls back to the Iran default, not empty.
	if !Preset("banana").Enabled() {
		t.Fatal("unknown preset should fall back to enabled default")
	}
}

func TestFromQueryOverrides(t *testing.T) {
	q := url.Values{}
	q.Set("routing", "off")
	q.Set("block_ads", "1")
	q.Set("bypass_iran", "true")
	o := FromQuery(q, "iran")
	if !o.BlockAds || !o.BypassIran {
		t.Fatalf("overrides not applied: %+v", o)
	}
	if o.BlockPorn {
		t.Fatalf("off base should not enable porn block: %+v", o)
	}
	// Default is used when nothing is set.
	if !FromQuery(url.Values{}, "iran").BypassIran {
		t.Fatal("empty query should use default preset")
	}
}

func TestSingboxRulesDownloadThroughProxy(t *testing.T) {
	rules, sets := Preset("full").Singbox("proxy", "direct")
	if len(rules) == 0 || len(sets) == 0 {
		t.Fatalf("expected rules and rule-sets, got %d/%d", len(rules), len(sets))
	}
	for _, rs := range sets {
		m := rs.(map[string]any)
		if m["download_detour"] != "proxy" {
			t.Fatalf("rule-set must download through the proxy: %+v", m)
		}
		if u, _ := m["url"].(string); !strings.HasSuffix(u, ".srs") {
			t.Fatalf("rule-set url should be a .srs binary set: %v", u)
		}
	}
}

func TestXrayRulesUseBuiltinGeo(t *testing.T) {
	rules := Preset("iran").Xray("direct", "block")
	var sawIR bool
	for _, r := range rules {
		m := r.(map[string]any)
		if ips, ok := m["ip"].([]string); ok {
			for _, ip := range ips {
				if ip == "geoip:ir" {
					sawIR = true
				}
			}
		}
	}
	if !sawIR {
		t.Fatal("iran preset xray rules should send geoip:ir direct")
	}
	if Preset("iran").XrayDomainStrategy() != "IPIfNonMatch" {
		t.Fatal("geoip rules need IPIfNonMatch")
	}
}

func TestClashRulesAndProviders(t *testing.T) {
	rules, providers := Preset("full").Clash("PROXY")
	if len(rules) == 0 || len(providers) == 0 {
		t.Fatalf("expected clash rules and providers, got %d/%d", len(rules), len(providers))
	}
	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "RULE-SET,ir-domains,DIRECT") {
		t.Fatalf("missing Iran direct rule-set: %v", rules)
	}
	if _, ok := providers["ads"]; !ok {
		t.Fatalf("missing ads provider: %v", providers)
	}
}

// TestFragmentPresetsAreDistinctAndDefaultToTodaysBehaviour pins the severity
// presets. Three names for one setting would be a dropdown that changes nothing,
// and moving the middle preset off today's numbers would silently re-tune every
// subscription already in the field.
func TestFragmentPresetsAreDistinctAndDefaultToTodaysBehaviour(t *testing.T) {
	if FragmentPreset("light").Length == FragmentPreset("aggressive").Length {
		t.Fatal("light and aggressive fragment to the same length; the levels are cosmetic")
	}
	// The shipped default is medium, byte for byte what FragmentFromQuery used
	// to hardcode.
	want := Fragment{Level: "medium", Packets: "tlshello", Length: "100-200", Interval: "10-20"}
	if got := FragmentPreset("medium"); got != want {
		t.Fatalf("medium moved off the shipped default: got %+v want %+v", got, want)
	}
	if FragmentPreset("bogus") != FragmentPreset("medium") {
		t.Fatalf("an unknown level must fall back to medium, got %+v", FragmentPreset("bogus"))
	}
	if (FragmentPreset("off") != Fragment{}) {
		t.Fatalf("off must be the zero Fragment, got %+v", FragmentPreset("off"))
	}
	// Nothing validated the query overrides before, so ?fragment_length=abc
	// reached the emitted JSON verbatim and the core refused the whole config.
	if err := (Fragment{Packets: "tlshello", Length: "abc", Interval: "10-20"}).Validate(); err == nil {
		t.Fatal("a non-numeric length was accepted")
	}
	if err := (Fragment{Packets: "wat", Length: "100-200", Interval: "10-20"}).Validate(); err == nil {
		t.Fatal("an unknown packets selector was accepted")
	}
	if err := (Fragment{Packets: "tlshello", Length: "200-100", Interval: "10-20"}).Validate(); err == nil {
		t.Fatal("an inverted length range was accepted")
	}
	if err := FragmentPreset("aggressive").Validate(); err != nil {
		t.Fatalf("the aggressive preset does not pass its own validator: %v", err)
	}
	// An empty core list means "every capable core", which is what every
	// Fragment literal built without one relies on.
	if !(Fragment{}).CoreEnabled("xray") || !(Fragment{}).CoreEnabled("sing-box") {
		t.Fatal("a Fragment with no core list must apply to every core")
	}
	if (Fragment{Cores: "xray"}).CoreEnabled("sing-box") {
		t.Fatal("sing-box is not in the list and was enabled anyway")
	}
	if !(Fragment{Cores: "xray, singbox"}).CoreEnabled("sing-box") {
		t.Fatal("singbox must be accepted as a spelling of sing-box")
	}
}

// TestFragmentFromQueryRejectsUnusableOverrides: a per-request override that the
// core would refuse must fall back to the default rather than produce a config
// that cannot start.
func TestFragmentFromQueryRejectsUnusableOverrides(t *testing.T) {
	def := FragmentPreset("medium")
	q := url.Values{}
	q.Set("fragment", "1")
	q.Set("fragment_length", "abc")
	f := FragmentFromQuery(q, def)
	if !f.Enabled {
		t.Fatal("?fragment=1 should turn it on")
	}
	if f.Length != def.Length {
		t.Fatalf("a garbage length should fall back to the default, got %q", f.Length)
	}
	// A level names a preset; an absent ?fragment= leaves the operator default.
	q2 := url.Values{}
	q2.Set("fragment_level", "aggressive")
	g := FragmentFromQuery(q2, Fragment{Enabled: true, Level: "medium", Packets: "tlshello", Length: "100-200", Interval: "10-20", Cores: "xray"})
	if !g.Enabled || g.Level != "aggressive" {
		t.Fatalf("fragment_level did not apply: %+v", g)
	}
	if g.Cores != "xray" {
		t.Fatalf("a per-request level must not widen the core set: %+v", g)
	}
}

// TestFragmentLevelOffTurnsItOffRatherThanEmptyingIt: "off" is one of the names
// FragmentPreset answers, and it answers with the zero Fragment. Carrying the
// operator's Enabled onto that would leave fragmentation switched ON with no
// packets, length or interval — an Xray freedom outbound with three empty
// strings in it, which the core refuses.
func TestFragmentLevelOffTurnsItOffRatherThanEmptyingIt(t *testing.T) {
	def := FragmentPreset("aggressive")
	def.Enabled = true
	q := url.Values{}
	q.Set("fragment_level", "off")
	f := FragmentFromQuery(q, def)
	if f.Enabled {
		t.Fatalf("?fragment_level=off left fragmentation on: %+v", f)
	}
	if f.Packets == "" || f.Length == "" || f.Interval == "" {
		t.Fatalf("the values were emptied instead of the switch being flipped: %+v", f)
	}
}
