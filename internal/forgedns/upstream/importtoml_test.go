package upstream

import (
	"reflect"
	"strings"
	"testing"
)

// goldenServerTOML is a MasterDnsVPN server config as shipped (§1, verbatim key
// lines) plus three things the panel must not choke on: a key it has never heard
// of, a table it has never heard of, and a comment.
const goldenServerTOML = `
# hand-tuned on the box, do not lose this
DOMAIN = ["v.example.com", "w.example.com"]
PROTOCOL_TYPE = "SOCKS5"
UDP_HOST = "0.0.0.0"
UDP_PORT = 5353
USE_EXTERNAL_SOCKS5 = false
FORWARD_IP = ""
FORWARD_PORT = 0
DATA_ENCRYPTION_METHOD = 2
ENCRYPTION_KEY_FILE = "/etc/somewhere/else/key.txt"
LOG_LEVEL = "DEBUG"
CONFIG_VERSION = "12"
EXPERIMENTAL_KNOB = "hold on to me"

[TUNING]
window = 64
`

// TestImportPreservesUnknownKeys is the golden test for the rule this package is
// built around: an operator hands over a file that works, possibly with knobs
// this panel has never read about (§0). Losing one would silently change how
// their tunnel behaves the first time the panel rewrites the file.
func TestImportPreservesUnknownKeys(t *testing.T) {
	managed, override, err := ImportServerTOML(goldenServerTOML)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if managed.Adapter != AdapterMasterDNS {
		t.Errorf("adapter = %q, want masterdns (detected from CONFIG_VERSION 12)", managed.Adapter)
	}
	for _, key := range []string{"DOMAIN", "UDP_PORT", "DATA_ENCRYPTION_METHOD", "LOG_LEVEL"} {
		if _, ok := managed.Values[key]; !ok {
			t.Errorf("%s should be recognised as a managed setting", key)
		}
	}
	if _, ok := override["EXPERIMENTAL_KNOB"]; !ok {
		t.Fatalf("the unknown key was DISCARDED; override = %v", override)
	}
	if override["EXPERIMENTAL_KNOB"] != "hold on to me" {
		t.Errorf("unknown key value = %v", override["EXPERIMENTAL_KNOB"])
	}
	if _, ok := override["TUNING"].(map[string]any); !ok {
		t.Errorf("the unknown table was discarded; override = %v", override)
	}
	if _, ok := override["UDP_PORT"]; ok {
		t.Error("a key the panel models must land in the managed layer, not the override")
	}
	// The panel owns the key file path, so importing one must be reported, not
	// obeyed — a config that points at a path the panel does not write is a zone
	// that starts with the wrong key.
	joined := strings.Join(managed.Warnings, "\n")
	if !strings.Contains(joined, "ENCRYPTION_KEY_FILE") {
		t.Errorf("importing a foreign ENCRYPTION_KEY_FILE must warn, got %v", managed.Warnings)
	}
}

// TestImportRoundTripsThroughRender: import → zone + override → rendered file →
// parse must preserve everything, with the panel's own values re-stamped.
func TestImportRoundTripsThroughRender(t *testing.T) {
	managed, override, err := ImportServerTOML(goldenServerTOML)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ManifestFor(managed.Adapter)
	text, err := RenderOverride(m, ScopeServer, override)
	if err != nil {
		t.Fatal(err)
	}
	var z ZoneConfig
	managed.ApplyTo(&z)
	z.EncryptKey = "0123456789abcdef0123456789abcdef"
	z.OverrideTOML = text

	d, err := Lookup(z.Adapter)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderServer(d, z)
	if err != nil {
		t.Fatalf("render after import: %v", err)
	}
	got := parseTOMLMap(t, out)

	// Managed settings survived the trip.
	if got["UDP_PORT"] != int64(5353) || got["DATA_ENCRYPTION_METHOD"] != int64(2) || got["LOG_LEVEL"] != "DEBUG" {
		t.Errorf("managed values lost: %v / %v / %v", got["UDP_PORT"], got["DATA_ENCRYPTION_METHOD"], got["LOG_LEVEL"])
	}
	domains, _ := asStrings(got["DOMAIN"])
	if strings.Join(domains, ",") != "v.example.com,w.example.com" {
		t.Errorf("DOMAIN = %v, want both imported domains", got["DOMAIN"])
	}
	// The unknown key and table are still there.
	if got["EXPERIMENTAL_KNOB"] != "hold on to me" {
		t.Errorf("unknown key did not survive the render: %v", got["EXPERIMENTAL_KNOB"])
	}
	tuning, ok := got["TUNING"].(map[string]any)
	if !ok || tuning["window"] != int64(64) {
		t.Errorf("unknown table did not survive the render: %v", got["TUNING"])
	}
	// The panel took its own values back.
	if got["CONFIG_VERSION"] != "12" {
		t.Errorf("CONFIG_VERSION = %v, want masterdns's 12", got["CONFIG_VERSION"])
	}
	if got["ENCRYPTION_KEY_FILE"] != EncryptKeyFile {
		t.Errorf("ENCRYPTION_KEY_FILE = %v, want the panel-owned %q", got["ENCRYPTION_KEY_FILE"], EncryptKeyFile)
	}
	if strings.Contains(out, z.EncryptKey) {
		t.Error("the server config must never inline the shared key")
	}

	// And rendering the parsed result again is a fixed point.
	e, err := EffectiveServer(d, z)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.TOML("")
	if err != nil {
		t.Fatal(err)
	}
	reparsed := parseTOMLMap(t, again)
	if len(reparsed) != len(e.Values) {
		t.Errorf("round-trip changed the key set: %d keys out, %d back", len(e.Values), len(reparsed))
	}
	for k, want := range e.Values {
		if !reflect.DeepEqual(normValue(reparsed[k]), normValue(want)) {
			t.Errorf("round-trip changed %s: %v -> %v", k, want, reparsed[k])
		}
	}
}

// TestImportClientAdoptsExistingKey: importing a client config is how an operator
// keeps already-deployed clients working — the key must come across.
func TestImportClientAdoptsExistingKey(t *testing.T) {
	const clientTOML = `
DOMAINS = ["v.example.com"]
QUERY_TYPES = ["TXT", "CNAME"]
DATA_ENCRYPTION_METHOD = 3
ENCRYPTION_KEY = "aabbccddeeff00112233445566778899"
PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18000
RESOLVER_TRANSPORT = "auto"
STARTUP_MODE = "resolvers"
QNAME_LABEL_LENGTH = 40
CONFIG_VERSION = "14"
`
	managed, override, err := ImportClientTOML(clientTOML)
	if err != nil {
		t.Fatal(err)
	}
	if managed.Adapter != AdapterCottenDNS {
		t.Fatalf("adapter = %q, want cottendns", managed.Adapter)
	}
	var z ZoneConfig
	managed.ApplyTo(&z)
	if z.EncryptKey != "aabbccddeeff00112233445566778899" {
		t.Errorf("the existing shared key was not adopted: %q", z.EncryptKey)
	}
	if strings.Join(z.QueryTypes, ",") != "TXT,CNAME" {
		t.Errorf("QUERY_TYPES = %v", z.QueryTypes)
	}
	// A knob the panel knows about but never writes belongs to the override.
	if override["QNAME_LABEL_LENGTH"] != int64(40) {
		t.Errorf("QNAME_LABEL_LENGTH should be preserved in the override, got %v", override["QNAME_LABEL_LENGTH"])
	}
}

// TestImportRejectsBadValues: import validates, so a broken paste fails at the
// API instead of crash-looping the supervised binary at start (§4b).
func TestImportRejectsBadValues(t *testing.T) {
	_, _, err := ImportServerTOML("UDP_PORT = \"fifty-three\"\nCONFIG_VERSION = \"14\"\n")
	if err == nil || !strings.Contains(err.Error(), "UDP_PORT") {
		t.Fatalf("expected a UDP_PORT type error, got %v", err)
	}
	_, _, err = ImportServerTOML("DOMAIN = [\"v.example.com\"]\nnot toml at all")
	if err == nil {
		t.Fatal("expected a parse error")
	}
}

// TestImportWithoutConfigVersion falls back to the default adapter and says so,
// rather than guessing silently.
func TestImportWithoutConfigVersion(t *testing.T) {
	managed, _, err := ImportServerTOML("DOMAIN = [\"v.example.com\"]\nUDP_PORT = 53\n")
	if err != nil {
		t.Fatal(err)
	}
	if managed.Adapter != DefaultAdapter {
		t.Errorf("adapter = %q, want the default %q", managed.Adapter, DefaultAdapter)
	}
	if len(managed.Warnings) == 0 || !strings.Contains(strings.Join(managed.Warnings, " "), "CONFIG_VERSION") {
		t.Errorf("a missing CONFIG_VERSION must be warned about, got %v", managed.Warnings)
	}
}
