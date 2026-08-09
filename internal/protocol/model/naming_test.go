package model

import "testing"

func TestCountryFlag(t *testing.T) {
	cases := map[string]string{
		"DE": "🇩🇪", "de": "🇩🇪", "US": "🇺🇸", "IR": "🇮🇷", "NL": "🇳🇱",
		"": "", "D": "", "DEU": "", "D1": "", "12": "",
	}
	for in, want := range cases {
		if got := CountryFlag(in); got != want {
			t.Errorf("CountryFlag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandNameTemplate(t *testing.T) {
	f := NameFields{Name: "Berlin", Country: "DE", Flag: "🇩🇪", Protocol: "vless",
		Net: "ws", TLS: "reality", Port: "443", Host: "a.example", User: "alice", Num: "2", Date: "2026-08-09"}

	if got := ExpandNameTemplate("{FLAG} {NAME}", f); got != "🇩🇪 Berlin" {
		t.Errorf("basic = %q", got)
	}
	if got := ExpandNameTemplate("{FLAG} {COUNTRY} · {NAME} · {PROTOCOL}/{NET} · {DATE}", f); got != "🇩🇪 DE · Berlin · vless/ws · 2026-08-09" {
		t.Errorf("rich = %q", got)
	}
	// An empty flag must not leave a leading gap or double space.
	empty := NameFields{Name: "Node", Flag: "", Country: ""}
	if got := ExpandNameTemplate("{FLAG} {NAME}", empty); got != "Node" {
		t.Errorf("empty flag = %q, want %q", got, "Node")
	}
	// Unknown tokens are preserved verbatim (a visible typo, not silently eaten).
	if got := ExpandNameTemplate("{NAME} {BOGUS}", f); got != "Berlin {BOGUS}" {
		t.Errorf("unknown token = %q", got)
	}
}

func TestNameFieldsFromNode(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "203.0.113.9", Port: 8443, Country: "nl",
		Transport: Transport{Network: "grpc"}, Security: Security{Type: SecReality}}
	f := NameFieldsFromNode(n, "Amsterdam", "bob", 3, "2026-08-09")
	if f.Flag != "🇳🇱" || f.Country != "NL" || f.Net != "grpc" || f.TLS != "reality" ||
		f.Port != "8443" || f.Num != "3" || f.Name != "Amsterdam" || f.Host != "203.0.113.9" {
		t.Fatalf("fields wrong: %+v", f)
	}
}
