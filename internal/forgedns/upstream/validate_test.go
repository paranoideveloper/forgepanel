package upstream

import (
	"strings"
	"testing"
)

// TestValidateTypesAndRanges: every message must name the key and say what was
// expected — the alternative is an operator reading a crash-loop log.
func TestValidateTypesAndRanges(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	cases := map[string]struct{ doc, want string }{
		"string for an int":   {`UDP_PORT = "53"`, "expected an integer"},
		"int for a bool":      {`DOT_LISTENER_ENABLED = 1`, "expected true or false"},
		"int for a string":    {`LOG_LEVEL = 3`, "expected a string"},
		"string for a list":   {`DOMAIN = "v.example.com"`, "expected an array of strings"},
		"cipher above range":  {`DATA_ENCRYPTION_METHOD = 9`, "above the maximum 5"},
		"port below range":    {`UDP_PORT = 0`, "below the minimum 1"},
		"unknown query type":  {`QUERY_TYPES = ["TXT", "NOPE"]`, `"NOPE" is not one of`},
		"wrong-case protocol": {`PROTOCOL_TYPE = "socks5"`, "is not one of SOCKS5, TCP"},
		"invalid log level":   {`LOG_LEVEL = "CHATTY"`, "is not one of DEBUG"},
	}
	for name, tc := range cases {
		doc, err := ParseTOML(tc.doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		scope := ScopeServer
		if strings.HasPrefix(tc.doc, "QUERY_TYPES") {
			scope = ScopeClient
		}
		err = ValidateDocument(m, scope, doc)
		if err == nil {
			t.Errorf("%s: expected a validation error for %s", name, tc.doc)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not explain %q", name, err, tc.want)
		}
	}
}

// TestValidateCollectsEveryError: an operator editing raw TOML should fix all
// their mistakes in one pass, not one save per mistake.
func TestValidateCollectsEveryError(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	doc, _ := ParseTOML("UDP_PORT = 0\nDATA_ENCRYPTION_METHOD = 9\nLOG_LEVEL = 3\n")
	err := ValidateDocument(m, ScopeServer, doc)
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error is %T, want *ValidationError", err)
	}
	if len(ve.Errors) != 3 {
		t.Fatalf("got %d field errors, want 3: %v", len(ve.Errors), ve.Errors)
	}
	if ve.Errors[0].Key != "DATA_ENCRYPTION_METHOD" {
		t.Errorf("field errors should be in a stable key order, got %v", ve.Errors)
	}
}

// TestValidateCompleteChecksDialect is the §4b guard at the last moment before a
// file is written: these binaries reject a config whose CONFIG_VERSION they do
// not know, and the most likely cause is a config pasted from a sibling fork —
// so the message names that fork.
func TestValidateCompleteChecksDialect(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	doc := Document{"DOMAIN": []string{"v.example.com"}, "CONFIG_VERSION": "12"}
	err := ValidateComplete(m, ScopeServer, doc)
	if err == nil {
		t.Fatal("expected a dialect error")
	}
	for _, want := range []string{"masterdns", "cottendns", `"14"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q should mention %s", err, want)
		}
	}

	doc["CONFIG_VERSION"] = 14 // the integer, not the string the samples use
	if err := ValidateComplete(m, ScopeServer, doc); err == nil ||
		!strings.Contains(err.Error(), "quoted string") {
		t.Errorf("an unquoted CONFIG_VERSION should be called out, got %v", err)
	}

	delete(doc, "CONFIG_VERSION")
	if err := ValidateComplete(m, ScopeServer, doc); err == nil ||
		!strings.Contains(err.Error(), "missing") {
		t.Errorf("a missing CONFIG_VERSION must fail the pre-apply check, got %v", err)
	}

	doc = Document{"CONFIG_VERSION": "14"}
	if err := ValidateComplete(m, ScopeServer, doc); err == nil ||
		!strings.Contains(err.Error(), "DOMAIN") {
		t.Errorf("a config with no tunnel domain must fail, got %v", err)
	}
	// The happy path stays happy.
	doc["DOMAIN"] = []string{"v.example.com"}
	if err := ValidateComplete(m, ScopeServer, doc); err != nil {
		t.Errorf("valid document rejected: %v", err)
	}
}

// TestValidateIgnoresUnknownAndOwnedKeys: unknown keys are preserved, not
// rejected, and keys the panel owns cannot reach the file so a value for them is
// a warning rather than an error.
func TestValidateIgnoresUnknownAndOwnedKeys(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	doc, _ := ParseTOML(`
WHO_KNOWS = "some value"
ENCRYPTION_KEY_FILE = "/somewhere/else.txt"
CONFIG_VERSION = "10"
`)
	if err := ValidateDocument(m, ScopeServer, doc); err != nil {
		t.Fatalf("override validation must not reject preserved or panel-owned keys: %v", err)
	}
	warnings := strings.Join(Warnings(m, ScopeServer, doc), "\n")
	for _, want := range []string{"WHO_KNOWS", "ENCRYPTION_KEY_FILE", "not applied"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings %q should mention %s", warnings, want)
		}
	}
}

// TestWarnUnverifiedKey: a key the panel emits for a fork whose own sample never
// showed it is worth saying out loud before someone debugs a rejected config.
func TestWarnUnverifiedKey(t *testing.T) {
	m, _ := ManifestFor(AdapterCottenDNS)
	doc, _ := ParseTOML(`FORWARD_IP = "10.0.0.9"`)
	warnings := strings.Join(Warnings(m, ScopeServer, doc), "\n")
	if !strings.Contains(warnings, "shipped sample") {
		t.Errorf("expected an unverified-key warning, got %q", warnings)
	}
}

func TestValidateOverrideTOMLRejectsGarbage(t *testing.T) {
	m, _ := ManifestFor(AdapterStormDNS)
	if _, _, err := ValidateOverrideTOML(m, ScopeServer, "= not toml"); err == nil {
		t.Fatal("expected a parse error")
	}
	doc, warnings, err := ValidateOverrideTOML(m, ScopeServer, "UDP_PORT = 5353\n")
	if err != nil {
		t.Fatalf("valid override rejected: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("a plain known key should warn about nothing, got %v", warnings)
	}
	if got, _ := asInt(doc["UDP_PORT"]); got != 5353 {
		t.Errorf("parsed document = %v", doc)
	}
}
