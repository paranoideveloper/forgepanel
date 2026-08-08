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
