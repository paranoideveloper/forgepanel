package dns

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fixedRand makes {rand} deterministic so name assertions are exact.
func fixedRand(values ...string) func(int) (string, error) {
	i := 0
	return func(n int) (string, error) {
		if i < len(values) {
			v := values[i]
			i++
			return v, nil
		}
		return fmt.Sprintf("r%d", i+1), nil
	}
}

func TestNameTemplateRender(t *testing.T) {
	tpl := NewNameTemplate("{proto}-{node}-{rand}")
	got, err := tpl.Render(TemplateVars{Proto: "ws", Node: "fra1", RandFn: fixedRand("k7m2qp")})
	requireNoError(t, err)
	if got != "ws-fra1-k7m2qp" {
		t.Fatalf("got %q", got)
	}
}

func TestNameTemplatePlaceholders(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		pattern string
		want    string
	}{
		{"{proto}-{node}", "ws-fra1"},
		{"{region}-{proto}", "eu-ws"},
		{"{proto}{seq}", "ws3"},
		{"{date}-{proto}", "20260807-ws"},
		{"{rand:4}", "abcd"},
		{"cdn-{proto}", "cdn-ws"},
		{"{custom}-{proto}", "zed-ws"},
	}
	for _, tc := range cases {
		got, err := NewNameTemplate(tc.pattern).Render(TemplateVars{
			Proto: "ws", Node: "fra1", Region: "eu", Seq: 3, Now: now,
			Extra: map[string]string{"custom": "zed"}, RandFn: fixedRand("abcd"),
		})
		requireNoError(t, err)
		if got != tc.want {
			t.Errorf("template %q rendered %q, want %q", tc.pattern, got, tc.want)
		}
	}
}

// A typo'd placeholder must be an error, not a literal brace that becomes a
// real DNS label and fails much later at the provider.
func TestNameTemplateRejectsUnknownPlaceholder(t *testing.T) {
	_, err := NewNameTemplate("{nodee}-{proto}").Render(TemplateVars{Proto: "ws"})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "unknown template placeholder {nodee}", "unknown placeholder")
	requireContains(t, e.Remediation, "{node}", "unknown placeholder remediation lists the real ones")
}

func TestNameTemplateRejectsUnclosedBrace(t *testing.T) {
	_, err := NewNameTemplate("node-{proto").Render(TemplateVars{Proto: "ws"})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "unclosed", "unclosed brace")
	requireContains(t, e.Remediation, "{proto}-{node}-{rand}", "unclosed brace remediation")

	// A brace nested inside another reads as one malformed placeholder name,
	// which is still caught — just as an unknown placeholder.
	_, err = NewNameTemplate("{proto-{node}").Render(TemplateVars{Proto: "ws"})
	e = requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "unknown template placeholder", "nested brace")
}

func TestNameTemplateSanitisesToALegalLabel(t *testing.T) {
	got, err := NewNameTemplate("{node}").Render(TemplateVars{Node: "  Frankfurt Node_01. "})
	requireNoError(t, err)
	if got != "frankfurt-node-01" {
		t.Fatalf("expected a sanitised label, got %q", got)
	}
	requireNoError(t, ValidateFQDN(got+".example.com"))
}

func TestNameTemplateRejectsOverlongLabel(t *testing.T) {
	_, err := NewNameTemplate("{node}").Render(TemplateVars{Node: strings.Repeat("a", 70)})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "over the 63-character DNS label limit", "overlong label")
	requireContains(t, e.Remediation, "shorten the node name", "overlong label remediation")
}

func TestNameTemplateRejectsEmptyRender(t *testing.T) {
	_, err := NewNameTemplate("{node}").Render(TemplateVars{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "empty label", "empty render")
}

func TestGenerateNamesAreUniqueAndQualified(t *testing.T) {
	names, err := NewNameTemplate("{proto}-{rand:6}").GenerateNames("example.com", 20, TemplateVars{Proto: "ws"})
	requireNoError(t, err)
	if len(names) != 20 {
		t.Fatalf("expected 20 names, got %d", len(names))
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate name %q", n)
		}
		seen[n] = true
		if !strings.HasSuffix(n, ".example.com") {
			t.Fatalf("name %q is not under the domain", n)
		}
		requireNoError(t, ValidateFQDN(n))
	}
}

// A fully deterministic template cannot produce two names; say so rather than
// silently returning fewer records than asked for.
func TestGenerateNamesRejectsNonUniqueTemplate(t *testing.T) {
	_, err := NewNameTemplate("{proto}-{node}").GenerateNames("example.com", 3, TemplateVars{Proto: "ws", Node: "fra1"})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "cannot produce 3 distinct names", "non-unique template")
	requireContains(t, e.Remediation, "add {rand} or {seq}", "non-unique template remediation")
}

func TestGenerateNamesBounds(t *testing.T) {
	_, err := NewNameTemplate("").GenerateNames("example.com", 0, TemplateVars{})
	requireKind(t, err, KindValidation)

	_, err = NewNameTemplate("").GenerateNames("example.com", 1000, TemplateVars{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "500-record safety cap", "count cap")
}

// The random alphabet excludes vowels and look-alikes so a generated label can
// never spell a filterable word and is unambiguous read aloud.
func TestRandomLabelAlphabet(t *testing.T) {
	for i := 0; i < 200; i++ {
		label, err := RandomLabel(12)
		requireNoError(t, err)
		if len(label) != 12 {
			t.Fatalf("expected 12 characters, got %d", len(label))
		}
		for _, r := range label {
			if !strings.ContainsRune(nameAlphabet, r) {
				t.Fatalf("label %q contains %q, which is outside the reduced alphabet", label, string(r))
			}
		}
	}
	for _, vowel := range "aeiou01l" {
		if strings.ContainsRune(nameAlphabet, vowel) {
			t.Fatalf("the alphabet must exclude %q", string(vowel))
		}
	}
}

func TestBulkCreateAgainstCloudflare(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	results, err := BulkCreate(context.Background(), m.client(), BulkSpec{
		ZoneRef: "zone1", Domain: "example.com", Template: "{proto}-{node}-{rand:5}",
		Type: TypeA, Content: "203.0.113.10", Count: 8, Proxied: true,
		Vars: TemplateVars{Proto: "ws", Node: "fra1"},
	})
	requireNoError(t, err)
	if len(results) != 8 {
		t.Fatalf("expected 8 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Error != "" || r.Action != "created" {
			t.Fatalf("unexpected result: %+v", r)
		}
		if !r.Record.Proxied {
			t.Fatalf("expected the bulk records to be proxied: %+v", r.Record)
		}
	}
	if len(m.Records["zone1"]) != 8 {
		t.Fatalf("expected 8 records at the provider, got %d", len(m.Records["zone1"]))
	}
}

// A bulk run must be idempotent: re-running reports "unchanged", not a pile of
// conflicts.
func TestBulkCreateIsIdempotentPerName(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	spec := BulkSpec{
		ZoneRef: "zone1", Domain: "example.com", Template: "{proto}-{seq}",
		Type: TypeA, Content: "203.0.113.10", Count: 3,
		Vars: TemplateVars{Proto: "ws"},
	}
	first, err := BulkCreate(context.Background(), m.client(), spec)
	requireNoError(t, err)
	second, err := BulkCreate(context.Background(), m.client(), spec)
	requireNoError(t, err)
	for i := range second {
		if second[i].Action != "unchanged" {
			t.Fatalf("re-run %d should be unchanged, got %q", i, second[i].Action)
		}
		if second[i].Name != first[i].Name {
			t.Fatalf("deterministic template changed names between runs: %q vs %q", first[i].Name, second[i].Name)
		}
	}
	if len(m.Records["zone1"]) != 3 {
		t.Fatalf("expected 3 records, got %d", len(m.Records["zone1"]))
	}
}

// A permission failure partway through must stop rather than repeating the same
// error for every remaining name, and must return what already landed.
func TestBulkCreateStopsOnPermissionFailure(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	m.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	results, err := BulkCreate(context.Background(), m.client(), BulkSpec{
		ZoneRef: "zone1", Domain: "example.com", Type: TypeA,
		Content: "203.0.113.10", Count: 10, Vars: TemplateVars{Proto: "ws"},
	})
	e := requireKind(t, err, KindPermission)
	if e.MissingScope != ScopeDNSEdit {
		t.Fatalf("expected the DNS edit scope, got %q", e.MissingScope)
	}
	if len(results) != 1 {
		t.Fatalf("expected the run to stop after the first failure, got %d results", len(results))
	}
	requireContains(t, results[0].Remediation, "Zone Resources", "bulk failure carries remediation")
}

func TestDeleteByNameIsIdempotent(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()
	_, err := c.CreateRecord(ctx, "zone1", Record{Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10"})
	requireNoError(t, err)

	n, err := DeleteByName(ctx, c, "zone1", TypeA, "ws.example.com")
	requireNoError(t, err)
	if n != 1 {
		t.Fatalf("expected one deletion, got %d", n)
	}
	n, err = DeleteByName(ctx, c, "zone1", TypeA, "ws.example.com")
	requireNoError(t, err)
	if n != 0 {
		t.Fatalf("deleting a missing name should be a no-op, got %d", n)
	}
}
