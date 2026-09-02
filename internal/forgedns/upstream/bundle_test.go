package upstream

import (
	"strings"
	"testing"
)

// TestBuildBundleOptionsAndFailures covers the bundle beyond the happy path:
// explicit listener options, and the two ways a zone can be un-bundleable.
func TestBuildBundleOptionsAndFailures(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS, "v.example.com")

	b, err := BuildBundle(d, z, BundleOptions{
		ServerIP:  "203.0.113.9",
		NSHost:    "NS1.Example.COM.",
		Resolvers: []string{"9.9.9.9", " ", "1.0.0.1"},
		Client:    ClientOptions{ListenIP: "0.0.0.0", ListenPort: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.NSHost != "ns1.example.com" {
		t.Errorf("an explicit ns host must win and be normalised, got %q", b.NSHost)
	}
	if b.Socks5 != "0.0.0.0:1080" {
		t.Errorf("bundle socks address = %q", b.Socks5)
	}
	if !strings.Contains(b.ClientResolversTXT, "9.9.9.9") || strings.Contains(b.ClientResolversTXT, "8.8.8.8") {
		t.Errorf("supplied resolvers must replace the defaults:\n%s", b.ClientResolversTXT)
	}
	if b.ClientFilenames.Config != "client_config.toml" || b.ClientFilenames.Resolvers != "client_resolvers.txt" {
		t.Errorf("bundle filenames = %+v", b.ClientFilenames)
	}
	if b.ReleasesPage == "" || b.Repo != d.Owner+"/"+d.Repo {
		t.Errorf("bundle provenance = %q / %q", b.ReleasesPage, b.Repo)
	}
	for _, rec := range b.NSRecords {
		if rec.Type == "A" && rec.Value != "203.0.113.9" {
			t.Errorf("glue record points at %q", rec.Value)
		}
	}

	// A zone that would not validate must not produce a half-built bundle.
	broken := zone(AdapterCottenDNS)
	broken.EncryptKey = ""
	if _, err := BuildBundle(d, broken, BundleOptions{}); err == nil {
		t.Error("an unkeyed zone must not be bundleable")
	}
	badOverride := zone(AdapterCottenDNS)
	badOverride.ClientOverrideTOML = "LISTEN_PORT = true\n"
	if _, err := BuildBundle(d, badOverride, BundleOptions{}); err == nil {
		t.Error("a client override that no longer validates must fail the bundle")
	}
}

// TestNSHostFor pins the delegation rule: the nameserver host lives in the
// PARENT zone, because that is where the operator can create records.
func TestNSHostFor(t *testing.T) {
	for _, tc := range []struct{ zone, override, want string }{
		{"v.example.com", "", "ns.example.com"},
		{"deep.v.example.com", "", "ns.v.example.com"},
		{"example.com", "", "ns.example.com"}, // no parent to move up into
		{"localhost", "", "ns.localhost"},
		{"v.example.com", "NS.Custom.NET.", "ns.custom.net"},
	} {
		if got := NSHostFor(tc.zone, tc.override); got != tc.want {
			t.Errorf("NSHostFor(%q, %q) = %q, want %q", tc.zone, tc.override, got, tc.want)
		}
	}
}

// TestHostArch: the panel must resolve its own release-asset arch token.
func TestHostArch(t *testing.T) {
	got, err := HostArch()
	if err != nil {
		t.Skipf("this host has no verified release asset naming: %v", err)
	}
	if got == "" {
		t.Fatal("HostArch returned an empty token with no error")
	}
	if want, _ := ArchToken("amd64"); got != want && got != "ARM64" && got != "ARMV7" {
		t.Fatalf("HostArch = %q, which is not one of the tokens the releases use", got)
	}
}

// TestDescriptorsOrderFallback: the UI listing must never lose
// an adapter just because someone added one to the table and forgot the order
// list. Mutating the package-level order is safe here — no test in this package
// runs in parallel.
func TestDescriptorsOrderFallback(t *testing.T) {
	full := Descriptors()
	if len(full) != len(descriptors) || full[0].Adapter != DefaultAdapter {
		t.Fatalf("Descriptors = %+v, want every fork with the default first", full)
	}

	prev := order
	order = []string{AdapterCottenDNS}
	t.Cleanup(func() { order = prev })

	got := Descriptors()
	if len(got) != len(descriptors) {
		t.Fatalf("an incomplete order list dropped adapters: %+v", got)
	}
	// The fallback is alphabetical, which is at least stable.
	if got[0].Adapter != AdapterCottenDNS || got[1].Adapter != AdapterMasterDNS || got[2].Adapter != AdapterStormDNS {
		t.Fatalf("fallback order = %s/%s/%s, want alphabetical",
			got[0].Adapter, got[1].Adapter, got[2].Adapter)
	}
}

// TestSplitAndJoinDomains covers the store column format.
func TestSplitAndJoinDomainsColumn(t *testing.T) {
	if got := SplitList("a, b;c\nd\te"); strings.Join(got, "|") != "a|b|c|d|e" {
		t.Errorf("SplitList = %v", got)
	}
	got := SplitDomains("V.Example.com., v.example.com , b.example.net\n")
	if strings.Join(got, ",") != "v.example.com,b.example.net" {
		t.Errorf("SplitDomains = %v, want normalised and de-duplicated", got)
	}
	if JoinDomains([]string{"B.Example.net.", "b.example.net", ""}) != "b.example.net" {
		t.Errorf("JoinDomains = %q", JoinDomains([]string{"B.Example.net.", "b.example.net", ""}))
	}
	if JoinDomains(nil) != "" {
		t.Error("an empty domain list joins to an empty column")
	}
}

// TestValidDomainRejects covers the shapes a tunnel domain may not take, since
// each one produces a config the binary would answer for incorrectly.
func TestValidDomainRejects(t *testing.T) {
	for _, bad := range []string{
		"",                             // empty
		"nodot",                        // must be a delegated name
		"has..empty.label",             // empty label
		strings.Repeat("a", 64) + ".x", // label over 63 bytes
		"-lead.example.com",            // leading hyphen
		"trail-.example.com",           // trailing hyphen
		"UPPER.example.com",            // must be normalised before validation
		"bad$char.example.com",         // illegal byte
		strings.Repeat("a.", 130) + "com",
	} {
		if validDomain(bad) {
			t.Errorf("validDomain(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"v.example.com", "a-b.example.co.uk", "_acme.example.com", "x1.example.com"} {
		if !validDomain(ok) {
			t.Errorf("validDomain(%q) = false, want true", ok)
		}
	}
}

// TestZoneValidateEgressAndQueryTypes covers the two validations the renderer
// tests do not reach.
func TestZoneValidateEgressAndQueryTypes(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)

	chained := zone(AdapterCottenDNS)
	chained.ExternalSocks5 = true
	chained.Normalize(d)
	if err := chained.Validate(); err == nil || !strings.Contains(err.Error(), "FORWARD_IP") {
		t.Errorf("a chained egress with no proxy host must be refused, got %v", err)
	}
	chained.ForwardIP = "10.0.0.9"
	if err := chained.Validate(); err != nil {
		t.Errorf("a complete chained egress must validate: %v", err)
	}

	rotate := zone(AdapterCottenDNS)
	rotate.QueryTypes = []string{"TXT", "NOTATYPE"}
	rotate.Normalize(d)
	if err := rotate.Validate(); err == nil || !strings.Contains(err.Error(), "query type") {
		t.Errorf("an unrecognised query type must be refused, got %v", err)
	}
}

// TestTOMLTypeName: the validation messages name what the operator actually
// wrote, which is the difference between a fixable error and a puzzle.
func TestTOMLTypeName(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"s", "a string"},
		{true, "a boolean"},
		{int64(1), "an integer"},
		{1.5, "a float"},
		{[]any{}, "an array"},
		{[]string{}, "an array"},
		{map[string]any{}, "a table"},
		{nil, "<nil>"},
	} {
		if got := tomlTypeName(tc.in); got != tc.want {
			t.Errorf("tomlTypeName(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestValidateCompleteAndDialect covers the pre-apply gate's remaining answers.
func TestValidateCompleteAndDialect(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)

	err := ValidateComplete(m, ScopeServer, Document{"DOMAIN": []string{"v.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "CONFIG_VERSION") {
		t.Errorf("a config with no dialect stamp must be refused, got %v", err)
	}

	err = ValidateComplete(m, ScopeClient, Document{"CONFIG_VERSION": "14", "DOMAINS": []string{}})
	if err == nil || !strings.Contains(err.Error(), "DOMAINS") {
		t.Errorf("a client config with no tunnel domain must be refused, got %v", err)
	}

	err = ValidateComplete(m, ScopeServer, Document{"CONFIG_VERSION": "14", "DOMAIN": []string{"v.example.com"}})
	if err != nil {
		t.Errorf("a complete config was rejected: %v", err)
	}

	// A document that fails plain validation never reaches the completeness check.
	err = ValidateComplete(m, ScopeServer, Document{"UDP_PORT": "fifty-three"})
	if err == nil || !strings.Contains(err.Error(), "UDP_PORT") {
		t.Errorf("expected the type error first, got %v", err)
	}

	for _, tc := range []struct {
		value any
		want  string
	}{
		{int64(14), "not the integer"},
		{true, `must be the string "14"`},
		{"10", "stormdns dialect"},
		{"99", "not a dialect this panel knows"},
	} {
		err := checkConfigVersion(m, tc.value)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("checkConfigVersion(%#v) = %v, want it to mention %q", tc.value, err, tc.want)
		}
	}
	if err := checkConfigVersion(m, "14"); err != nil {
		t.Errorf("this fork's own version must pass: %v", err)
	}
}

// TestValidateOverrideTOMLWarns: a stored override that is legal but risky has
// to come back with the warning attached.
func TestValidateOverrideTOMLWarns(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	doc, warnings, err := ValidateOverrideTOML(m, ScopeServer, "FORWARD_IP = \"10.0.0.9\"\nWHO_KNOWS = 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if doc["FORWARD_IP"] != "10.0.0.9" {
		t.Errorf("parsed override = %v", doc)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "WHO_KNOWS") || !strings.Contains(joined, "shipped sample") {
		t.Errorf("warnings = %q", joined)
	}
	if _, _, err := ValidateOverrideTOML(m, ScopeServer, "UDP_PORT = 0\n"); err == nil {
		t.Error("an out-of-range value must be an error, not a warning")
	}
}

// TestImportUnknownDialectAndRuntimeKeys covers the import branches that decide
// which fork a pasted file is written in and what the panel will regenerate.
func TestImportUnknownDialectAndRuntimeKeys(t *testing.T) {
	managed, override, err := ImportServerTOML("CONFIG_VERSION = \"99\"\nDOMAIN = [\"v.example.com\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if managed.Adapter != DefaultAdapter {
		t.Errorf("an unknown dialect must fall back to %q, got %q", DefaultAdapter, managed.Adapter)
	}
	if !strings.Contains(strings.Join(managed.Warnings, "\n"), `"99" is not a dialect`) {
		t.Errorf("the fallback must be announced, got %v", managed.Warnings)
	}
	if len(override) != 0 {
		t.Errorf("nothing here belongs in the override layer: %v", override)
	}

	// A client file carries the secret; the panel owns it and says so.
	managed, _, err = ImportClientTOML("CONFIG_VERSION = \"14\"\nDOMAINS = [\"v.example.com\"]\n" +
		"ENCRYPTION_KEY = \"imported-secret\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(managed.Warnings, "\n"), "ENCRYPTION_KEY: the panel owns this value") {
		t.Errorf("an imported key must be flagged as panel-owned, got %v", managed.Warnings)
	}
	var z ZoneConfig
	managed.ApplyTo(&z)
	if z.EncryptKey != "imported-secret" || z.Zone != "v.example.com" {
		t.Errorf("import did not adopt the existing zone: %+v", z)
	}
}

// TestRenderOverrideEmptyDocument: an empty override stores as empty text, so an
// unchanged zone never looks changed.
func TestRenderOverrideEmptyDocument(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	out, err := RenderOverride(m, ScopeServer, Document{})
	if err != nil || out != "" {
		t.Fatalf("RenderOverride(empty) = %q, %v", out, err)
	}
	out, err = RenderOverride(m, ScopeServer, Document{"UDP_PORT": int64(5353), "ZZZ": "kept"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "UDP_PORT = 5353") || !strings.Contains(out, `ZZZ = "kept"`) {
		t.Fatalf("RenderOverride dropped a key:\n%s", out)
	}
	if strings.Index(out, "UDP_PORT") > strings.Index(out, "ZZZ") {
		t.Fatalf("known keys must keep manifest order:\n%s", out)
	}
}
