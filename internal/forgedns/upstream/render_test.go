package upstream

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// zone builds a minimally valid zone for an adapter.
func zone(adapter string, domains ...string) ZoneConfig {
	z := ZoneConfig{Zone: "v.example.com", Adapter: adapter, EncryptKey: "deadbeef"}
	if len(domains) > 0 {
		z.Zone = domains[0]
		z.Domains = domains[1:]
	}
	return z
}

// decode renders a server config and parses it as real TOML, so the test proves
// the output is a valid config file and not merely a string with the right
// substrings in it.
func decode(t *testing.T, adapter string, z ZoneConfig) map[string]any {
	t.Helper()
	d, err := Lookup(adapter)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", adapter, err)
	}
	out, err := RenderServer(d, z)
	if err != nil {
		t.Fatalf("RenderServer(%s): %v", adapter, err)
	}
	var m map[string]any
	if err := toml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("rendered %s config is not valid TOML: %v\n---\n%s", adapter, err, out)
	}
	return m
}

// TestServerStampsConfigVersion is the guard for §4b: these binaries reject a
// file whose CONFIG_VERSION they do not know, so each adapter must stamp its own.
func TestServerStampsConfigVersion(t *testing.T) {
	want := map[string]string{
		AdapterStormDNS:  "10",
		AdapterMasterDNS: "12",
		AdapterCottenDNS: "14",
	}
	for adapter, version := range want {
		m := decode(t, adapter, zone(adapter))
		if got := m["CONFIG_VERSION"]; got != version {
			t.Errorf("%s: CONFIG_VERSION = %v, want %q", adapter, got, version)
		}
	}
}

// TestServerDomainArray covers the user's question: DOMAIN is an array, and a
// CottenDNS instance carries many tunnel domains at once (§3).
func TestServerDomainArray(t *testing.T) {
	for _, adapter := range Names() {
		m := decode(t, adapter, zone(adapter))
		got, ok := m["DOMAIN"].([]any)
		if !ok {
			t.Fatalf("%s: DOMAIN is %T, want an array", adapter, m["DOMAIN"])
		}
		if len(got) != 1 || got[0] != "v.example.com" {
			t.Errorf("%s: DOMAIN = %v, want [v.example.com]", adapter, got)
		}
	}

	multi := zone(AdapterCottenDNS, "a.example.com", "b.example.com", "c.example.net")
	m := decode(t, AdapterCottenDNS, multi)
	got, _ := m["DOMAIN"].([]any)
	if len(got) != 3 || got[0] != "a.example.com" || got[2] != "c.example.net" {
		t.Fatalf("multi-domain DOMAIN = %v, want all three with the primary first", got)
	}
}

// TestDomainDedupeAndNormalise: the primary zone must not be duplicated when it
// also appears in the extra-domains column, and case/trailing dots normalise.
func TestDomainDedupeAndNormalise(t *testing.T) {
	z := zone(AdapterCottenDNS)
	z.Zone = "V.Example.com."
	z.Domains = []string{"v.example.com", "B.example.com"}
	m := decode(t, AdapterCottenDNS, z)
	got, _ := m["DOMAIN"].([]any)
	if len(got) != 2 || got[0] != "v.example.com" || got[1] != "b.example.com" {
		t.Fatalf("DOMAIN = %v, want [v.example.com b.example.com]", got)
	}
}

// TestCottenOnlyKeys enforces the §4b rule: only emit keys the adapter version
// knows. The listener/auto-detect/A-record knobs are CottenDNS-only.
func TestCottenOnlyKeys(t *testing.T) {
	cotten := zone(AdapterCottenDNS)
	cotten.TCPListener, cotten.DoTListener, cotten.AutoDetect, cotten.ARecordDelivery = true, true, true, true
	m := decode(t, AdapterCottenDNS, cotten)
	for k, want := range map[string]any{
		"TCP_LISTENER_ENABLED":   true,
		"DOT_LISTENER_ENABLED":   true,
		"DOH_LISTENER_ENABLED":   false,
		"ENCRYPTION_AUTO_DETECT": true,
		"A_RECORD_DATA_DELIVERY": true,
	} {
		if m[k] != want {
			t.Errorf("cottendns %s = %v, want %v", k, m[k], want)
		}
	}

	// Same settings on the lean adapters must not leak those keys through.
	for _, adapter := range []string{AdapterStormDNS, AdapterMasterDNS} {
		z := zone(adapter)
		z.TCPListener, z.DoTListener, z.AutoDetect, z.ARecordDelivery = true, true, true, true
		m := decode(t, adapter, z)
		for _, k := range []string{"TCP_LISTENER_ENABLED", "DOT_LISTENER_ENABLED",
			"DOH_LISTENER_ENABLED", "ENCRYPTION_AUTO_DETECT", "A_RECORD_DATA_DELIVERY"} {
			if _, ok := m[k]; ok {
				t.Errorf("%s must not emit %s (CONFIG_VERSION does not know it)", adapter, k)
			}
		}
	}
}

// TestServerCommonKeys checks the shared dialect and the panel's key authority.
func TestServerCommonKeys(t *testing.T) {
	z := zone(AdapterStormDNS)
	z.BindHost, z.BindPort, z.Cipher = "10.0.0.5", 5353, 5
	m := decode(t, AdapterStormDNS, z)
	if m["UDP_HOST"] != "10.0.0.5" || m["UDP_PORT"] != int64(5353) {
		t.Errorf("bind = %v:%v, want 10.0.0.5:5353", m["UDP_HOST"], m["UDP_PORT"])
	}
	if m["PROTOCOL_TYPE"] != "SOCKS5" {
		t.Errorf("PROTOCOL_TYPE = %v, want SOCKS5", m["PROTOCOL_TYPE"])
	}
	if m["DATA_ENCRYPTION_METHOD"] != int64(5) {
		t.Errorf("DATA_ENCRYPTION_METHOD = %v, want 5", m["DATA_ENCRYPTION_METHOD"])
	}
	// The panel is the key authority: the server reads a key FILE, and the raw
	// key must never appear in the server config.
	if m["ENCRYPTION_KEY_FILE"] != EncryptKeyFile {
		t.Errorf("ENCRYPTION_KEY_FILE = %v, want %q", m["ENCRYPTION_KEY_FILE"], EncryptKeyFile)
	}
	if _, ok := m["ENCRYPTION_KEY"]; ok {
		t.Error("server config must reference the key file, not inline the key")
	}
}

// TestDefaultCipherPerAdapter: an unset cipher falls back to what the upstream
// itself ships with (§1–§3).
func TestDefaultCipherPerAdapter(t *testing.T) {
	for adapter, want := range map[string]int64{
		AdapterStormDNS: 1, AdapterMasterDNS: 1, AdapterCottenDNS: 3,
	} {
		m := decode(t, adapter, zone(adapter))
		if m["DATA_ENCRYPTION_METHOD"] != want {
			t.Errorf("%s default cipher = %v, want %d", adapter, m["DATA_ENCRYPTION_METHOD"], want)
		}
	}
}

func TestTCPModeRendersForwardTarget(t *testing.T) {
	z := zone(AdapterMasterDNS)
	z.Mode, z.ForwardIP, z.ForwardPort = ModeTCP, "10.1.2.3", 8388
	m := decode(t, AdapterMasterDNS, z)
	if m["PROTOCOL_TYPE"] != "TCP" || m["FORWARD_IP"] != "10.1.2.3" || m["FORWARD_PORT"] != int64(8388) {
		t.Fatalf("TCP mode rendered as %v / %v:%v", m["PROTOCOL_TYPE"], m["FORWARD_IP"], m["FORWARD_PORT"])
	}
}

func TestValidateRejectsBadZones(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	cases := map[string]func(z *ZoneConfig){
		"cipher out of range": func(z *ZoneConfig) { z.Cipher = 9 },
		"no domain":           func(z *ZoneConfig) { z.Zone = "" },
		"bad domain":          func(z *ZoneConfig) { z.Zone = "not a domain!" },
		"tcp without target":  func(z *ZoneConfig) { z.Mode = ModeTCP },
		"no key":              func(z *ZoneConfig) { z.EncryptKey = "" },
		"bad query type":      func(z *ZoneConfig) { z.QueryTypes = []string{"TXT", "NOPE"} },
	}
	for name, mutate := range cases {
		z := zone(AdapterCottenDNS)
		mutate(&z)
		z.Normalize(d)
		if err := z.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// TestClientConfig covers §4d: the client file IS the credential, so it carries
// the key inline, and every client listens SOCKS5 on 127.0.0.1:18000.
func TestClientConfig(t *testing.T) {
	for _, adapter := range Names() {
		d, _ := Lookup(adapter)
		z := zone(adapter)
		z.EncryptKey = "0123456789abcdef"
		out, err := RenderClient(d, z, ClientOptions{})
		if err != nil {
			t.Fatalf("RenderClient(%s): %v", adapter, err)
		}
		var m map[string]any
		if err := toml.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("%s client config is not valid TOML: %v\n%s", adapter, err, out)
		}
		if m["ENCRYPTION_KEY"] != "0123456789abcdef" {
			t.Errorf("%s: client ENCRYPTION_KEY = %v", adapter, m["ENCRYPTION_KEY"])
		}
		if m["LISTEN_PORT"] != int64(DefaultClientPort) || m["LISTEN_IP"] != DefaultClientListenIP {
			t.Errorf("%s: client listens on %v:%v", adapter, m["LISTEN_IP"], m["LISTEN_PORT"])
		}
		if doms, _ := m["DOMAINS"].([]any); len(doms) != 1 {
			t.Errorf("%s: client DOMAINS = %v, want one entry", adapter, m["DOMAINS"])
		}
		// QUERY_TYPES is a CottenDNS client knob only (§3).
		_, hasQT := m["QUERY_TYPES"]
		if hasQT != (adapter == AdapterCottenDNS) {
			t.Errorf("%s: QUERY_TYPES present = %v, want %v", adapter, hasQT, adapter == AdapterCottenDNS)
		}
	}
}

func TestClientQueryTypeRotation(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS)
	z.QueryTypes = []string{"txt", "cname", "null", "https", "txt"}
	out, err := RenderClient(d, z, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := toml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	got, _ := m["QUERY_TYPES"].([]any)
	if len(got) != 4 || got[0] != "TXT" || got[3] != "HTTPS" {
		t.Fatalf("QUERY_TYPES = %v, want the 4 unique types upper-cased", got)
	}
}

func TestRenderResolvers(t *testing.T) {
	out := RenderResolvers(nil)
	for _, r := range DefaultResolvers {
		if !strings.Contains(out, r) {
			t.Errorf("default resolvers missing %s", r)
		}
	}
	if out := RenderResolvers([]string{"192.168.1.1:53", "10.0.0.0/8"}); !strings.Contains(out, "10.0.0.0/8") {
		t.Errorf("custom resolvers not rendered: %s", out)
	}
}

func TestGenerateKeyIsUniqueHex(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateKey()
	// 16 bytes hex-encoded = 32 chars — the length StormDNS/CottenDNS/MasterDNS
	// accept; a 64-char key is rejected by their clients.
	if a == b || len(a) != 32 {
		t.Fatalf("keys %q / %q are not distinct 32-char hex", a, b)
	}
}
