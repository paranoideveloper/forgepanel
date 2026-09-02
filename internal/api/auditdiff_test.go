package api

import (
	"strings"
	"testing"
)

// AuditLog.Diff was stored, served, and never written, so every entry said that
// someone changed something and nothing about what. These pin the two things
// that make a diff worth having: it names the change, and it never carries a
// credential into a table people are encouraged to read.

func TestDiffNamesTheFieldsThatChanged(t *testing.T) {
	before := []byte(`{"remark":"edge","port":443,"enabled":true}`)
	after := []byte(`{"remark":"edge-eu","port":8443,"enabled":true}`)

	d := diffJSON(before, after)
	if !strings.Contains(d, "remark: edge → edge-eu") {
		t.Errorf("the remark change is not described: %q", d)
	}
	if !strings.Contains(d, "port: 443 → 8443") {
		t.Errorf("the port change is not described: %q", d)
	}
	// An unchanged field must not appear, or the diff is noise.
	if strings.Contains(d, "enabled") {
		t.Errorf("an unchanged field appears in the diff: %q", d)
	}
}

// A full before/after dump would copy private keys and passwords into the audit
// trail, turning an access-control record into a second place secrets live.
func TestSecretsAreNamedButNeverValued(t *testing.T) {
	before := []byte(`{"uuid":"aaaa-1111","security":{"reality":{"private_key":"OLD-SECRET","dest":"a.example:443"}},"password":"hunter2"}`)
	after := []byte(`{"uuid":"bbbb-2222","security":{"reality":{"private_key":"NEW-SECRET","dest":"b.example:443"}},"password":"hunter3"}`)

	d := diffJSON(before, after)
	for _, leak := range []string{"OLD-SECRET", "NEW-SECRET", "hunter2", "hunter3", "aaaa-1111", "bbbb-2222"} {
		if strings.Contains(d, leak) {
			t.Errorf("the diff leaks a credential (%s): %q", leak, d)
		}
	}
	// It still has to say they changed, or a key rotation is invisible.
	if !strings.Contains(d, "security.reality.private_key: changed") {
		t.Errorf("a private-key change is not recorded at all: %q", d)
	}
	if !strings.Contains(d, "password: changed") {
		t.Errorf("a password change is not recorded: %q", d)
	}
	// Non-secret siblings are still described in full.
	if !strings.Contains(d, "security.reality.dest: a.example:443 → b.example:443") {
		t.Errorf("a non-secret nested field is not described: %q", d)
	}
}

// Nested paths must read the way an operator refers to them.
func TestNestedFieldsUseDottedPaths(t *testing.T) {
	d := diffJSON(
		[]byte(`{"transport":{"network":"tcp","path":"/a"}}`),
		[]byte(`{"transport":{"network":"xhttp","path":"/a"}}`))
	if !strings.Contains(d, "transport.network: tcp → xhttp") {
		t.Fatalf("nested change not described with a dotted path: %q", d)
	}
}

func TestAddedAndRemovedFieldsAreDistinguished(t *testing.T) {
	d := diffJSON([]byte(`{"remark":"a"}`), []byte(`{"remark":"a","country":"NL"}`))
	if !strings.Contains(d, "country: set to NL") {
		t.Errorf("an added field is not described: %q", d)
	}
	d = diffJSON([]byte(`{"remark":"a","country":"NL"}`), []byte(`{"remark":"a"}`))
	if !strings.Contains(d, "country: removed") {
		t.Errorf("a removed field is not described: %q", d)
	}
}

// An identical document must produce nothing, or every save writes a diff that
// says a change happened when none did.
func TestNoChangeProducesNoDiff(t *testing.T) {
	doc := []byte(`{"remark":"a","port":443,"transport":{"network":"tcp"}}`)
	if d := diffJSON(doc, doc); d != "" {
		t.Fatalf("an unchanged document produced %q", d)
	}
}

// JSON numbers are float64; 443 must not render as "443 → 443".
func TestIntegersDoNotLookChanged(t *testing.T) {
	if d := diffJSON([]byte(`{"port":443}`), []byte(`{"port":443}`)); d != "" {
		t.Fatalf("an unchanged integer looked changed: %q", d)
	}
	if got := scalarString(float64(443)); got != "443" {
		t.Fatalf("443 rendered as %q", got)
	}
}

// A pathological change must not put an unbounded blob in every row.
func TestDiffIsBounded(t *testing.T) {
	big := strings.Repeat("x", 50000)
	d := diffJSON([]byte(`{"a":"1"}`), []byte(`{"a":"`+big+`"}`))
	if len(d) > maxDiffLen+40 {
		t.Fatalf("diff is %d bytes, above the %d bound", len(d), maxDiffLen)
	}
}

// Unparseable input must not lose the audit entry; it simply has no diff.
func TestMalformedDocumentsYieldNoDiffRatherThanAnError(t *testing.T) {
	if d := diffJSON([]byte("not json"), []byte(`{"a":1}`)); d != "" {
		t.Fatalf("malformed input produced %q", d)
	}
}

// A new secret-bearing field should default to redacted, not to leaked.
func TestUnknownSecretlikeFieldsAreRedactedByDefault(t *testing.T) {
	for _, name := range []string{"api_key", "refresh_token", "client_secret", "mldsa65_seed", "auth_pw"} {
		if !isSecretField(name) {
			t.Errorf("%q is not treated as secret-bearing; a new secret field would leak", name)
		}
	}
	for _, name := range []string{"remark", "port", "network", "country"} {
		if isSecretField(name) {
			t.Errorf("%q is redacted but carries no secret, which hides real changes", name)
		}
	}
}
