package upstream

import (
	"strings"
	"testing"
)

// overrideZone is a CottenDNS zone carrying an advanced override.
func overrideZone(override string) (Descriptor, ZoneConfig) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS)
	z.EncryptKey = "c0ffee0123456789c0ffee0123456789"
	z.OverrideTOML = override
	return d, z
}

// TestMergePrecedence pins the whole point of the layering: the override beats
// the managed settings (an escape hatch that loses to the form is not an escape
// hatch), and the panel-owned runtime values beat the override.
func TestMergePrecedence(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	e := Merge(m, ScopeServer,
		Document{"UDP_PORT": 53, "LOG_LEVEL": "INFO"},
		Document{"UDP_PORT": 5353, "DOMAIN": []string{"v.example.com"}},
		Document{"UDP_PORT": 5354, "LOG_LEVEL": "DEBUG", "CONFIG_VERSION": "12", "WEIRD": "kept"},
		Document{"CONFIG_VERSION": "14", "ENCRYPTION_KEY_FILE": EncryptKeyFile},
	)
	if got, _ := asInt(e.Values["UDP_PORT"]); got != 5354 {
		t.Errorf("UDP_PORT = %v, want the override's 5354", e.Values["UDP_PORT"])
	}
	if e.Origin["UDP_PORT"] != LayerOverride || e.Origin["DOMAIN"] != LayerManaged {
		t.Errorf("origins = %v", e.Origin)
	}
	if e.Values["CONFIG_VERSION"] != "14" {
		t.Errorf("CONFIG_VERSION = %v; the runtime layer must win — the binary rejects any other dialect",
			e.Values["CONFIG_VERSION"])
	}
	if len(e.Ignored) != 1 || e.Ignored[0] != "CONFIG_VERSION" {
		t.Errorf("ignored = %v, want [CONFIG_VERSION]", e.Ignored)
	}
	if len(e.Unknown) != 1 || e.Unknown[0] != "WEIRD" {
		t.Errorf("unknown = %v, want [WEIRD]", e.Unknown)
	}
	if e.Values["WEIRD"] != "kept" {
		t.Error("an unknown override key must survive the merge")
	}
}

// TestOverrideReachesRenderedFile: the override is not a display-only feature —
// it must land in the file the supervised process actually reads.
func TestOverrideReachesRenderedFile(t *testing.T) {
	d, z := overrideZone(`
UDP_PORT = 5353
DOH_LISTENER_ENABLED = true
EXPERIMENTAL_KNOB = "hold on to me"
CONFIG_VERSION = "12"
`)
	out, err := RenderServer(d, z)
	if err != nil {
		t.Fatal(err)
	}
	m := parseTOMLMap(t, out)
	if m["UDP_PORT"] != int64(5353) || m["DOH_LISTENER_ENABLED"] != true {
		t.Errorf("override did not reach the file: %v / %v", m["UDP_PORT"], m["DOH_LISTENER_ENABLED"])
	}
	if m["EXPERIMENTAL_KNOB"] != "hold on to me" {
		t.Errorf("unknown key was dropped: %v", m["EXPERIMENTAL_KNOB"])
	}
	if m["CONFIG_VERSION"] != "14" {
		t.Errorf("CONFIG_VERSION = %v, want the adapter's 14 regardless of the override", m["CONFIG_VERSION"])
	}
	if m["DOMAIN"] == nil || m["ENCRYPTION_KEY_FILE"] != EncryptKeyFile {
		t.Errorf("managed and runtime keys must survive an override: %v", m)
	}
	if !strings.Contains(out, "# overridden:") {
		t.Errorf("the generated file should say which keys were overridden:\n%s", out)
	}
}

// TestRenderIsDeterministic: the manager restarts a zone when the rendered
// config's signature changes, so a map-order wobble would restart every tunnel
// on every sync.
func TestRenderIsDeterministic(t *testing.T) {
	d, z := overrideZone("ZZZ_LAST = 1\nAAA_FIRST = 2\nUDP_PORT = 5353\n")
	first, err := RenderServer(d, z)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := RenderServer(d, z)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("render %d differs:\n%s\n---\n%s", i, first, again)
		}
	}
	// Known keys keep the renderer's order; unknown ones are appended in a
	// stable alphabetical block rather than interleaved.
	body := first[strings.Index(first, "DOMAIN"):]
	iDomain, iPort := strings.Index(body, "DOMAIN"), strings.Index(body, "UDP_PORT")
	iA, iZ := strings.Index(body, "AAA_FIRST"), strings.Index(body, "ZZZ_LAST")
	if !(iDomain < iPort && iPort < iA && iA < iZ) {
		t.Fatalf("unexpected key order:\n%s", first)
	}
}

// TestClientOverrideAndSecretMasking: the client file IS the credential (§4d),
// so every path that shows it to a human must mask the key, and the masked value
// must round-trip back to the stored secret instead of overwriting it.
func TestClientOverrideAndSecretMasking(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS)
	z.EncryptKey = "5ecret5ecret5ecret5ecret5ecret5e"
	z.ClientOverrideTOML = "SOCKS5_AUTH = true\nSOCKS5_PASS = \"hunter2\"\n"
	m, _ := ManifestFor(AdapterCottenDNS)

	e, err := EffectiveClient(d, z, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Values["ENCRYPTION_KEY"] != z.EncryptKey {
		t.Fatalf("the real document must carry the real key, got %v", e.Values["ENCRYPTION_KEY"])
	}
	masked, err := e.MaskedTOML(m, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{z.EncryptKey, "hunter2"} {
		if strings.Contains(masked, secret) {
			t.Errorf("masked config leaks %q:\n%s", secret, masked)
		}
	}
	if !strings.Contains(masked, MaskedValue) {
		t.Errorf("masked config shows no mask:\n%s", masked)
	}
	if got := e.SecretKeys(m); strings.Join(got, ",") != "ENCRYPTION_KEY,SOCKS5_PASS" {
		t.Errorf("secret keys = %v", got)
	}

	// An editor round-trip: what was shown masked comes back masked.
	shown, err := ParseTOML(masked)
	if err != nil {
		t.Fatal(err)
	}
	restored := UnmaskDocument(shown, e.Values)
	if restored["ENCRYPTION_KEY"] != z.EncryptKey || restored["SOCKS5_PASS"] != "hunter2" {
		t.Errorf("unmasking lost a secret: %v / %v", restored["ENCRYPTION_KEY"], restored["SOCKS5_PASS"])
	}
	if UnmaskDocument(Document{"NEW_PASS": MaskedValue}, Document{})["NEW_PASS"] != nil {
		t.Error("a mask with nothing behind it must be dropped, never stored literally")
	}
}

// TestSecretHeuristicForUndeclaredKeys: an operator can paste anything into the
// override, and a leaked key nobody declared is still a leaked key.
func TestSecretHeuristicForUndeclaredKeys(t *testing.T) {
	for key, want := range map[string]bool{
		"SOME_API_KEY": true, "AUTH_TOKEN": true, "DB_PASSWORD": true,
		"CLIENT_SECRET": true, "ENCRYPTION_KEY_FILE": false,
		"UDP_PORT": false, "DOMAIN": false,
	} {
		if got := looksSecret(key); got != want {
			t.Errorf("looksSecret(%q) = %v, want %v", key, got, want)
		}
	}
}

// TestEffectiveRejectsInvalidStoredOverride: an override that stops validating
// (a fork upgrade, a hand-edited database) must surface as a zone error rather
// than be written out and crash-loop the binary.
func TestEffectiveRejectsInvalidStoredOverride(t *testing.T) {
	d, z := overrideZone(`UDP_PORT = "not a number"`)
	if _, err := RenderServer(d, z); err == nil {
		t.Fatal("expected a validation error for a non-integer UDP_PORT")
	} else if !strings.Contains(err.Error(), "UDP_PORT") {
		t.Errorf("error should name the key, got %v", err)
	}
	_, z = overrideZone("this is not toml")
	if _, err := RenderServer(d, z); err == nil {
		t.Fatal("expected a parse error for a malformed override")
	}
}

// TestNoOverrideKeepsHandWrittenFile: the common case must keep the commented
// file an operator can diff against the release's own sample.
func TestNoOverrideKeepsHandWrittenFile(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS)
	out, err := RenderServer(d, z)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "# overridden:") {
		t.Error("a zone with no override should not get the merged-document header")
	}
	if !strings.Contains(out, "0=None 1=XOR") {
		t.Errorf("the hand-written renderer's key comments went missing:\n%s", out)
	}
}
