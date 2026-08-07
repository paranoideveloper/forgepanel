package upstream

import (
	"strings"
	"testing"
)

// unknownDescriptor is a fork the manifest table has never heard of. Descriptor
// is a plain value the API layer can build, so "no manifest for this adapter"
// has to be an error rather than a nil-map panic.
var unknownDescriptor = Descriptor{Adapter: "not-a-fork", Owner: "nobody", Repo: "nothing", ConfigVersion: "99"}

// TestEffectiveServerRejectsEveryBadInput walks each way the server merge can
// refuse, since every one of them is a zone the panel must NOT write a config for.
func TestEffectiveServerRejectsEveryBadInput(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)

	if _, err := EffectiveServer(unknownDescriptor, zone(AdapterCottenDNS)); err == nil {
		t.Error("an adapter with no manifest must be an error")
	}

	noKey := zone(AdapterCottenDNS)
	noKey.EncryptKey = ""
	if _, err := EffectiveServer(d, noKey); err == nil || !strings.Contains(err.Error(), "encryption key") {
		t.Errorf("an unkeyed zone must be refused, got %v", err)
	}

	badTOML := zone(AdapterCottenDNS)
	badTOML.OverrideTOML = "= this is not toml"
	if _, err := EffectiveServer(d, badTOML); err == nil || !strings.Contains(err.Error(), "not valid TOML") {
		t.Errorf("a malformed override must be refused, got %v", err)
	}

	badValue := zone(AdapterCottenDNS)
	badValue.OverrideTOML = "UDP_PORT = 99999\n"
	if _, err := EffectiveServer(d, badValue); err == nil || !strings.Contains(err.Error(), "UDP_PORT") {
		t.Errorf("an out-of-range override must name the key, got %v", err)
	}
}

// TestEffectiveClientRejectsEveryBadInput is the client-side mirror.
func TestEffectiveClientRejectsEveryBadInput(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)

	if _, err := EffectiveClient(unknownDescriptor, zone(AdapterCottenDNS), ClientOptions{}); err == nil {
		t.Error("an adapter with no manifest must be an error")
	}

	noKey := zone(AdapterCottenDNS)
	noKey.EncryptKey = ""
	if _, err := EffectiveClient(d, noKey, ClientOptions{}); err == nil {
		t.Error("an unkeyed zone must be refused")
	}

	badTOML := zone(AdapterCottenDNS)
	badTOML.ClientOverrideTOML = "= nope"
	if _, err := EffectiveClient(d, badTOML, ClientOptions{}); err == nil {
		t.Error("a malformed client override must be refused")
	}

	badValue := zone(AdapterCottenDNS)
	badValue.ClientOverrideTOML = "LISTEN_PORT = \"eighteen thousand\"\n"
	if _, err := EffectiveClient(d, badValue, ClientOptions{}); err == nil ||
		!strings.Contains(err.Error(), "LISTEN_PORT") {
		t.Errorf("a mistyped client override must name the key, got %v", err)
	}
}

// TestClientOverrideReachesTheBundleFile: the client file is what the user runs,
// so an override has to reach it — with the panel's key still on top.
func TestClientOverrideReachesTheBundleFile(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS)
	z.EncryptKey = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
	z.ClientOverrideTOML = "QNAME_LABEL_LENGTH = 40\nENCRYPTION_KEY = \"attacker-supplied\"\nWILD_KNOB = true\n"

	out, err := RenderClient(d, z, ClientOptions{ListenIP: "0.0.0.0", ListenPort: 1080})
	if err != nil {
		t.Fatal(err)
	}
	m := parseTOMLMap(t, out)
	if m["QNAME_LABEL_LENGTH"] != int64(40) {
		t.Errorf("override did not reach the client file: %v", m["QNAME_LABEL_LENGTH"])
	}
	if m["WILD_KNOB"] != true {
		t.Errorf("an unknown client key was dropped: %v", m["WILD_KNOB"])
	}
	if m["ENCRYPTION_KEY"] != z.EncryptKey {
		t.Errorf("an override rewrote the zone secret: %v", m["ENCRYPTION_KEY"])
	}
	if m["LISTEN_IP"] != "0.0.0.0" || m["LISTEN_PORT"] != int64(1080) {
		t.Errorf("bundle listener options were lost: %v / %v", m["LISTEN_IP"], m["LISTEN_PORT"])
	}
	if !strings.Contains(out, "# ignored   : ENCRYPTION_KEY") {
		t.Errorf("the file should say the panel took the key back:\n%s", out)
	}
	if !strings.Contains(out, "# ForgeDNS client config") {
		t.Errorf("missing the generated-file header:\n%s", out)
	}
}

// TestParseTOMLEmptyDocuments: no override is the common case and must not be an
// error or a nil map.
func TestParseTOMLEmptyDocuments(t *testing.T) {
	for _, text := range []string{"", "   ", "\n\t\n"} {
		doc, err := ParseTOML(text)
		if err != nil {
			t.Fatalf("ParseTOML(%q): %v", text, err)
		}
		if doc == nil || len(doc) != 0 {
			t.Fatalf("ParseTOML(%q) = %v, want an empty document", text, doc)
		}
	}
}

// TestRenderDocumentShapes covers the writer's quoting rules and the table block
// it has to append last for the file to stay parseable.
func TestRenderDocumentShapes(t *testing.T) {
	doc := Document{
		"DOMAIN":       []string{"a.example.com", "b.example.com"},
		"MIXED":        []any{"one", int64(2), true},
		"ENABLED":      true,
		"RATIO":        1.5,
		"COUNT":        int64(7),
		"weird key":    "quoted",
		"advanced":     map[string]any{"nested": "value"},
		"NOT_IN_ORDER": "skipped because it is not in the order list",
	}
	order := []string{"DOMAIN", "MIXED", "ENABLED", "RATIO", "COUNT", "weird key", "advanced", "ABSENT"}

	out, err := renderDocument("# header with no newline", order, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "# header with no newline\n") {
		t.Errorf("a header without a trailing newline must get one:\n%q", out)
	}
	if strings.Contains(out, "NOT_IN_ORDER") {
		t.Error("a key outside the order list must not be written")
	}
	m := parseTOMLMap(t, out)
	if m["ENABLED"] != true || m["RATIO"] != 1.5 || m["COUNT"] != int64(7) {
		t.Errorf("scalars did not round-trip: %v", m)
	}
	if m["weird key"] != "quoted" {
		t.Errorf("a non-bare key must be quoted so the file still parses: %v", m)
	}
	tbl, ok := m["advanced"].(map[string]any)
	if !ok || tbl["nested"] != "value" {
		t.Errorf("table-valued key was lost: %v", m["advanced"])
	}
	// The table header must come after every scalar, or TOML re-reads the
	// scalars as members of the table.
	if strings.Index(out, "[advanced]") < strings.LastIndex(out, "COUNT = 7") {
		t.Errorf("table block was written before the top-level keys:\n%s", out)
	}

	if _, err := renderDocument("", []string{"BAD"}, Document{"BAD": struct{ X int }{1}}); err == nil {
		t.Error("a value with no TOML spelling must be an error, not silent corruption")
	}
	if out, err := renderDocument("", nil, Document{}); err != nil || out != "" {
		t.Errorf("an empty document renders to nothing, got %q / %v", out, err)
	}
}

func TestTOMLKeyQuoting(t *testing.T) {
	for in, want := range map[string]string{
		"UDP_PORT":  "UDP_PORT",
		"a-b-1":     "a-b-1",
		"has space": `"has space"`,
		"dotted.k":  `"dotted.k"`,
		"":          `""`,
	} {
		if got := tomlKey(in); got != want {
			t.Errorf("tomlKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTOMLValueSpellings(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"text", `"text"`},
		{`with "quotes"`, `"with \"quotes\""`},
		{true, "true"},
		{false, "false"},
		{2.5, "2.5"},
		{int64(3), "3"},
		{4, "4"},
		{int32(5), "5"},
		{uint(6), "6"},
		{uint64(7), "7"},
		{float64(8), "8"},
		{[]string{"a", "b"}, `["a", "b"]`},
		{[]any{"a", int64(1), true}, `["a", 1, true]`},
		{[]any{}, "[]"},
	} {
		got, err := tomlValue(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("tomlValue(%#v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := tomlValue([]any{make(chan int)}); err == nil {
		t.Error("an array holding an unrenderable value must be an error")
	}
	if _, err := tomlValue(map[string]int{"a": 1}); err == nil {
		t.Error("an unrenderable value must be an error")
	}
}

func TestAsIntNormalisesEveryShape(t *testing.T) {
	for _, in := range []any{1, int32(1), int64(1), uint(1), uint64(1), float64(1)} {
		if n, ok := asInt(in); !ok || n != 1 {
			t.Errorf("asInt(%#v) = %d, %v", in, n, ok)
		}
	}
	for _, in := range []any{1.5, "1", true, nil, []any{1}} {
		if n, ok := asInt(in); ok {
			t.Errorf("asInt(%#v) = %d, true; want not-an-integer", in, n)
		}
	}
}

func TestAsStringsNormalisesEveryShape(t *testing.T) {
	if got, ok := asStrings([]string{"a"}); !ok || len(got) != 1 || got[0] != "a" {
		t.Errorf("asStrings([]string) = %v, %v", got, ok)
	}
	if got, ok := asStrings([]any{"a", "b"}); !ok || strings.Join(got, ",") != "a,b" {
		t.Errorf("asStrings([]any) = %v, %v", got, ok)
	}
	if _, ok := asStrings([]any{"a", 1}); ok {
		t.Error("a mixed array is not a string list")
	}
	if _, ok := asStrings("a"); ok {
		t.Error("a bare string is not a string list")
	}
}

// TestMaskDocumentUsesManifestAndHeuristic: a value is masked either because the
// manifest declares it secret or because its name says so.
func TestMaskDocumentUsesManifestAndHeuristic(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	got := MaskDocument(m, ScopeClient, Document{
		"ENCRYPTION_KEY":  "real-secret",      // declared secret
		"LISTEN_PORT":     int64(18000),       // declared, not secret
		"UNDECLARED_PASS": "guessable",        // unknown, name says secret
		"ENCRYPT_KEY_MAP": "not key material", // unknown but *_KEY_FILE-like names stay clear
	})
	if got["ENCRYPTION_KEY"] != MaskedValue || got["UNDECLARED_PASS"] != MaskedValue {
		t.Errorf("a secret escaped masking: %v", got)
	}
	if got["ENCRYPT_KEY_MAP"] != MaskedValue {
		t.Errorf("an undeclared KEY-shaped name should be masked eagerly: %v", got["ENCRYPT_KEY_MAP"])
	}
	if got["LISTEN_PORT"] != int64(18000) {
		t.Errorf("a harmless value was masked: %v", got["LISTEN_PORT"])
	}
	if !isSecretKey(m, ScopeClient, "ENCRYPTION_KEY") {
		t.Error("a manifest-declared secret must be treated as one")
	}
	if isSecretKey(m, ScopeServer, "UDP_PORT") {
		t.Error("a declared non-secret must not be masked")
	}
}

func TestManifestForUnknownAdapter(t *testing.T) {
	if _, err := ManifestFor("not-a-fork"); err == nil {
		t.Error("an unknown adapter must be an error, not an empty manifest")
	}
	if _, err := ManifestFor("  CottenDNS  "); err != nil {
		t.Errorf("adapter names are matched case- and space-insensitively: %v", err)
	}
	if got := Manifests(); len(got) != len(Names()) || got[0].Adapter != DefaultAdapter {
		t.Errorf("Manifests must list every fork, recommended first: %+v", got)
	}
}
