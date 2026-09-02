package api

import (
	"encoding/json"
	"testing"
)

// The subscription settings endpoint wrote whatever it was handed. A preset it
// had never heard of was persisted, echoed back in the 200, shown in the UI's
// <select> as a blank option — and then quietly ignored by routing.Preset, which
// falls back to the Iran rules for any name it does not know. The panel reported
// one routing policy and served another, with nothing anywhere saying so.
func TestSubSettingsRejectAnUnknownRoutingPreset(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"routing_preset": "nonsense"})
	if code != 400 {
		t.Fatalf("an unknown preset was accepted with %d: %s", code, body)
	}
	if raw := s.db.GetSetting("sub_routing_preset"); raw != "" {
		t.Fatalf("sub_routing_preset = %q; a rejected value was persisted anyway", raw)
	}
	if got := s.subRoutingPreset(); got != "iran" {
		t.Errorf("the default preset is now %q; a rejected write disturbed it", got)
	}
	// The refusal has to name the key, or an operator sees "invalid" with no clue
	// which of the eleven fields on that card is the bad one.
	var refusal struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(body), &refusal); err != nil {
		t.Fatalf("the refusal is not JSON: %v", err)
	}
	if refusal.Fields["sub_routing_preset"] == "" {
		t.Errorf("the refusal names no field, so the UI cannot mark the bad input: %s", body)
	}
}

// A whole batch is refused or applied, never half of it: a save that names one
// good key and one bad one must leave the good one untouched too, otherwise the
// card the operator is looking at ends up in a state they never asked for.
func TestASubSettingsBatchWithOneBadKeyWritesNothing(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/settings/subscription", token,
		map[string]any{"name_template": "{FLAG} {NAME}", "front_domain": "not a domain"})
	if code != 400 {
		t.Fatalf("an invalid front domain was accepted with %d: %s", code, body)
	}
	if tmpl := s.subNameTemplate(); tmpl != "" {
		t.Errorf("name_template = %q; the valid half of a refused batch was written anyway", tmpl)
	}
}

// The registry has to be REACHABLE. A validated, typed, well-tested settings
// table that no HTTP route serves is not a discoverable settings surface, it is
// a package with tests.
func TestSettingsRegistryRouteListsEveryKnob(t *testing.T) {
	s, token := adminAPI(t)

	code, body := doGET(t, s, "/api/admin/settings/registry", token)
	if code != 200 {
		t.Fatalf("no settings registry route: %d %s", code, body)
	}
	var doc struct {
		Settings []struct {
			Key     string   `json:"key"`
			Type    string   `json:"type"`
			Scope   string   `json:"scope"`
			Default any      `json:"default"`
			Choices []string `json:"choices"`
			Secret  bool     `json:"secret"`
			Value   any      `json:"value"`
			Help    string   `json:"help"`
		} `json:"settings"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("registry is not JSON: %v\n%s", err, body)
	}
	byKey := map[string]int{}
	for i, d := range doc.Settings {
		byKey[d.Key] = i
	}

	i, ok := byKey["sub_routing_preset"]
	if !ok {
		t.Fatalf("sub_routing_preset is not in the registry: %s", body)
	}
	preset := doc.Settings[i]
	if preset.Type != "enum" {
		t.Errorf("sub_routing_preset type = %q, want enum", preset.Type)
	}
	if preset.Default != "iran" {
		t.Errorf("sub_routing_preset default = %v, want iran", preset.Default)
	}
	want := []string{"iran", "full", "block", "off"}
	if len(preset.Choices) != len(want) {
		t.Fatalf("sub_routing_preset choices = %v, want %v", preset.Choices, want)
	}
	for n, c := range want {
		if preset.Choices[n] != c {
			t.Fatalf("sub_routing_preset choices = %v, want %v", preset.Choices, want)
		}
	}
	if preset.Help == "" {
		t.Error("sub_routing_preset carries no help text, so the surface explains nothing")
	}

	i, ok = byKey["sub_expand_sni"]
	if !ok {
		t.Fatalf("sub_expand_sni is not in the registry: %s", body)
	}
	if doc.Settings[i].Type != "bool" || doc.Settings[i].Default != true {
		t.Errorf("sub_expand_sni = {type:%q default:%v}, want {bool true} — it is ON by default",
			doc.Settings[i].Type, doc.Settings[i].Default)
	}

	i, ok = byKey["telegram_bot_token"]
	if !ok {
		t.Fatalf("telegram_bot_token is not in the registry: %s", body)
	}
	if !doc.Settings[i].Secret {
		t.Error("telegram_bot_token is not marked secret")
	}
	if v := doc.Settings[i].Value; v != nil && v != "" {
		t.Errorf("telegram_bot_token value = %v; a secret must never be echoed", v)
	}

	// Panel-owned keys are not an operator surface: the pull token is a bearer
	// credential the Worker uses, and the pending TOTP secrets are mid-enrolment
	// state. Listing them would invite editing them.
	for _, hidden := range []string{"edge_feed_pull_token", "pending_totp_"} {
		if _, present := byKey[hidden]; present {
			t.Errorf("%q is panel-owned and must not be offered as an editable setting", hidden)
		}
	}
}

// Every key the subscription card writes has to be one the registry knows.
//
// Values refuses an unregistered key, so a handler that writes "sub_expand_sn1"
// now fails the save instead of storing a row nothing reads. This drives the
// whole card in one request — the shape the UI actually sends — so that refusal
// is a test failure rather than something an operator discovers.
func TestEverySubscriptionSettingSurvivesOneSave(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/settings/subscription", token, map[string]any{
		"routing_preset": "full",
		"fragment":       true,
		"name_template":  "{FLAG} {NAME}",
		"pattern":        "both",
		"front_domain":   "aparat.com",
		"front_mode":     "cdn",
		"expand_sni":     false,
		"front_clean_ip": true,
		"clean_ips":      "104.16.0.1, speed.cloudflare.com",
	})
	if code != 200 {
		t.Fatalf("a full save of the card returned %d: %s", code, body)
	}
	if got := s.subRoutingPreset(); got != "full" {
		t.Errorf("routing preset = %q", got)
	}
	if !s.subFragmentDefault() {
		t.Error("fragment did not stick")
	}
	if got := s.subNameTemplate(); got != "{FLAG} {NAME}" {
		t.Errorf("name template = %q", got)
	}
	if got := patternSettingString(s.subPatternDefault()); got != "both" {
		t.Errorf("pattern = %q", got)
	}
	if got := s.subFrontDomain(); got != "aparat.com" {
		t.Errorf("front domain = %q", got)
	}
	if got := string(s.subFrontMode()); got != "cdn" {
		t.Errorf("front mode = %q", got)
	}
	if s.subExpandSNI() {
		t.Error("expand_sni did not stick")
	}
	if !s.subFrontCleanIP() {
		t.Error("front_clean_ip did not stick")
	}
	if ips := s.subCleanIPs(); len(ips) != 2 || ips[1] != "speed.cloudflare.com" {
		t.Errorf("clean IPs = %v", ips)
	}
}

// The lists the settings dialog renders its dropdowns from come from the same
// table the validator rejects against. They were two hardcoded copies, and only
// one of them was enforced.
func TestTheSubscriptionCardOffersExactlyWhatTheRegistryAccepts(t *testing.T) {
	s, token := adminAPI(t)

	code, body := doGET(t, s, "/api/admin/settings/subscription", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	var offered struct {
		Presets      []string `json:"presets"`
		PatternModes []string `json:"pattern_modes"`
		FrontModes   []string `json:"front_modes"`
	}
	if err := json.Unmarshal([]byte(body), &offered); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field string
		key   string
		list  []string
	}{
		{"presets", "sub_routing_preset", offered.Presets},
		{"pattern_modes", "sub_pattern_default", offered.PatternModes},
		{"front_modes", "sub_front_mode", offered.FrontModes},
	} {
		if len(tc.list) == 0 {
			t.Fatalf("%s is empty, so the dialog has no options to show", tc.field)
		}
		for _, v := range tc.list {
			if err := s.knobs().Set(tc.key, v); err != nil {
				t.Errorf("the dialog offers %s=%q but the panel refuses it: %v", tc.field, v, err)
			}
		}
	}
}
