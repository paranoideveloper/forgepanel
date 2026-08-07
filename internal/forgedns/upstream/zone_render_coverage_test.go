package upstream

import (
	"strings"
	"testing"
)

// covZoneCfg is a minimal valid zone for the default adapter.
func covZoneCfg() ZoneConfig {
	return ZoneConfig{
		Zone:       "v.example.com",
		Adapter:    DefaultAdapter,
		EncryptKey: "0123456789abcdef",
	}
}

func covDesc(t *testing.T) Descriptor {
	t.Helper()
	d, err := Lookup(DefaultAdapter)
	if err != nil {
		t.Fatalf("default adapter is not registered: %v", err)
	}
	return d
}

// TestZoneValidatePortRangeStopsBothRenderers covers the UDP_PORT range check and
// proves that a zone rejected by Validate cannot reach either renderer or the
// bundle builder — the three call sites that must not emit a config the upstream
// binary would refuse at start.
func TestZoneValidatePortRangeStopsBothRenderers(t *testing.T) {
	d := covDesc(t)

	for _, port := range []int{-1, -32768, 65536, 70000} {
		z := covZoneCfg()
		z.BindPort = port
		z.Normalize(d)

		err := z.Validate()
		if err == nil {
			t.Fatalf("UDP_PORT %d must be rejected", port)
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("UDP_PORT %d: unexpected error %v", port, err)
		}
		if got, rerr := RenderServer(d, z); rerr == nil {
			t.Fatalf("RenderServer emitted a config for UDP_PORT %d:\n%s", port, got)
		}
		if got, rerr := RenderClient(d, z, ClientOptions{}); rerr == nil {
			t.Fatalf("RenderClient emitted a config for UDP_PORT %d:\n%s", port, got)
		}
		if _, berr := BuildBundle(d, z, BundleOptions{}); berr == nil {
			t.Fatalf("BuildBundle succeeded for UDP_PORT %d", port)
		}
	}

	// Both ends of the legal range are accepted, so the check is a range and not
	// a blanket rejection.
	for _, port := range []int{1, 53, 65535} {
		z := covZoneCfg()
		z.BindPort = port
		z.Normalize(d)
		if err := z.Validate(); err != nil {
			t.Fatalf("UDP_PORT %d should be legal: %v", port, err)
		}
		out, err := RenderServer(d, z)
		if err != nil {
			t.Fatalf("UDP_PORT %d: %v", port, err)
		}
		if !strings.Contains(out, "UDP_PORT = ") {
			t.Fatalf("rendered server config has no UDP_PORT:\n%s", out)
		}
	}
}

// TestImportProtocolTypeTCPSelectsTCPMode covers the TCP branch of Managed.ApplyTo
// and the unverified-key warning importTOML raises for a key this fork's own
// sample never showed.
func TestImportProtocolTypeTCPSelectsTCPMode(t *testing.T) {
	src := strings.Join([]string{
		`DOMAIN = ["v.example.com"]`,
		`PROTOCOL_TYPE = "TCP"`,
		`FORWARD_IP = "127.0.0.1"`,
		`FORWARD_PORT = 9050`,
	}, "\n") + "\n"

	im, _, err := ImportServerTOML(src)
	if err != nil {
		t.Fatal(err)
	}
	var z ZoneConfig
	im.ApplyTo(&z)
	if z.Mode != ModeTCP {
		t.Fatalf("PROTOCOL_TYPE=TCP must select %q, got %q", ModeTCP, z.Mode)
	}
	if z.ForwardIP != "127.0.0.1" || z.ForwardPort != 9050 {
		t.Fatalf("forward target not projected: %s:%d", z.ForwardIP, z.ForwardPort)
	}
	if z.Zone != "v.example.com" {
		t.Fatalf("zone not projected: %q", z.Zone)
	}

	// FORWARD_* are marked unverified for the default (CottenDNS) fork, so the
	// import must say so rather than silently accepting them.
	var warned bool
	for _, w := range im.Warnings {
		if strings.Contains(w, "FORWARD_IP") && strings.Contains(w, "shipped sample") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected an unverified-key warning for FORWARD_IP, got %v", im.Warnings)
	}

	// The complementary branch. PROTOCOL_TYPE has an exhaustive choice set, so
	// only "SOCKS5" survives import; the lower-case spellings are fed straight to
	// ApplyTo to show the match is exact and case-sensitive rather than lenient.
	socks, _, err := ImportServerTOML("PROTOCOL_TYPE = \"SOCKS5\"\n")
	if err != nil {
		t.Fatal(err)
	}
	var sz ZoneConfig
	socks.ApplyTo(&sz)
	if sz.Mode != ModeSocks5 {
		t.Fatalf("PROTOCOL_TYPE=SOCKS5 selected %q", sz.Mode)
	}
	for _, spelling := range []string{"socks5", "tcp", "Tcp", "anything"} {
		im := Managed{Scope: ScopeServer, Values: Document{"PROTOCOL_TYPE": spelling}}
		var got ZoneConfig
		im.ApplyTo(&got)
		if got.Mode != ModeSocks5 {
			t.Fatalf("PROTOCOL_TYPE=%q selected %q; only the exact string \"TCP\" means TCP", spelling, got.Mode)
		}
	}

	// A lower-case spelling is rejected at import time rather than coerced.
	if _, _, err := ImportServerTOML("PROTOCOL_TYPE = \"socks5\"\n"); err == nil {
		t.Fatal("PROTOCOL_TYPE is case-sensitive and \"socks5\" must not import")
	}
}

// TestRenderDocumentRejectsUnrenderableValue covers renderDocument's error return
// for a value with no TOML spelling — the guard that stops a corrupt document
// being written to a supervised zone's config file.
func TestRenderDocumentRejectsUnrenderableValue(t *testing.T) {
	type opaque struct{ X int }

	for _, v := range []any{opaque{1}, make(chan int), func() {}, nil} {
		_, err := renderDocument("", []string{"K"}, Document{"K": v})
		if err == nil {
			t.Fatalf("value %T has no TOML spelling and must be rejected", v)
		}
		if !strings.Contains(err.Error(), "K") {
			t.Fatalf("error should name the offending key, got %v", err)
		}
	}

	// A document that renders cleanly still does, so the guard is not blanket.
	out, err := renderDocument("# header", []string{"S", "N", "B", "L"},
		Document{"S": "str", "N": int64(7), "B": true, "L": []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# header\n", `S = "str"`, "N = 7", "B = true", `L = ["a", "b"]`} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered document is missing %q:\n%s", want, out)
		}
	}
}
