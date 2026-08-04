package upstream

import (
	"fmt"
	"sort"
	"strings"
)

// Validation for the layered config, run BEFORE anything is written or applied.
//
// Why validate at all when the binary will complain anyway: it will not, usefully.
// These forks reject a config by exiting at start (§4b), which the panel can only
// report as "the zone crash-looped" with whatever the process printed. Catching a
// wrong type, an out-of-range cipher or a CONFIG_VERSION from a different fork at
// save time turns that into a message naming the key.

// FieldError is one rejected key.
type FieldError struct {
	Key     string `json:"key"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Key + ": " + e.Message }

// ValidationError collects every problem in one document, so an operator editing
// raw TOML fixes all of them in one pass instead of one save per mistake.
type ValidationError struct {
	Scope  Scope        `json:"scope"`
	Errors []FieldError `json:"errors"`
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fe.Error())
	}
	return fmt.Sprintf("forgedns: %d invalid %s option(s): %s",
		len(e.Errors), e.Scope, strings.Join(parts, "; "))
}

// ValidateDocument checks every key the manifest knows and can act on.
//
// Two deliberate non-errors. Keys the manifest does NOT know pass: preserving
// them is the whole point of the override layer, and a fork can carry knobs this
// panel has never read about. Keys the panel OWNS (CONFIG_VERSION, the key file,
// the client key) also pass, because the merge discards them anyway — rejecting
// a value that cannot reach the file would block the ordinary act of pasting a
// working config from a sibling fork. Both are reported by Warnings instead.
func ValidateDocument(m Manifest, scope Scope, doc Document) error {
	ve := &ValidationError{Scope: scope}
	for _, k := range sortedKeys(doc) {
		o, ok := m.Option(scope, k)
		if !ok || o.Runtime {
			continue
		}
		if err := ValidateOption(o, doc[k]); err != nil {
			ve.Errors = append(ve.Errors, FieldError{k, err.Error()})
		}
	}
	if len(ve.Errors) == 0 {
		return nil
	}
	return ve
}

// ValidateComplete is the pre-apply gate: a document that is about to become a
// real server_config.toml must also BE one — right dialect, and a tunnel domain
// to answer for.
func ValidateComplete(m Manifest, scope Scope, doc Document) error {
	if err := ValidateDocument(m, scope, doc); err != nil {
		return err
	}
	ve := &ValidationError{Scope: scope}
	version, ok := doc["CONFIG_VERSION"]
	if !ok {
		ve.Errors = append(ve.Errors, FieldError{"CONFIG_VERSION",
			fmt.Sprintf("missing: %s rejects a config that does not declare version %q", m.Adapter, m.ConfigVersion)})
	} else if err := checkConfigVersion(m, version); err != nil {
		ve.Errors = append(ve.Errors, FieldError{"CONFIG_VERSION", err.Error()})
	}
	domainKey := "DOMAIN"
	if scope == ScopeClient {
		domainKey = "DOMAINS"
	}
	if list, _ := asStrings(doc[domainKey]); len(list) == 0 {
		ve.Errors = append(ve.Errors, FieldError{domainKey, "at least one tunnel domain is required"})
	}
	if len(ve.Errors) == 0 {
		return nil
	}
	return ve
}

// checkConfigVersion enforces §4b: the stamped version must be this fork's.
// Naming the fork that DOES use the wrong version is the useful half of the
// message — it is nearly always a config pasted from a sibling project.
func checkConfigVersion(m Manifest, v any) error {
	got, ok := v.(string)
	if !ok {
		if n, isInt := asInt(v); isInt {
			return fmt.Errorf("must be the quoted string %q, not the integer %d", m.ConfigVersion, n)
		}
		return fmt.Errorf("must be the string %q", m.ConfigVersion)
	}
	if got == m.ConfigVersion {
		return nil
	}
	if other, known := AdapterForConfigVersion(got); known {
		return fmt.Errorf("%q is the %s dialect; %s only accepts %q",
			got, other, m.Adapter, m.ConfigVersion)
	}
	return fmt.Errorf("%q is not a dialect this panel knows; %s accepts %q",
		got, m.Adapter, m.ConfigVersion)
}

// ValidateOption checks one value against one option's type, range and choices.
func ValidateOption(o Option, v any) error {
	switch o.Type {
	case TypeString:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected a string, got %s", tomlTypeName(v))
		}
		return checkChoice(o, s)
	case TypeBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("expected true or false, got %s", tomlTypeName(v))
		}
		return nil
	case TypeInt:
		n, ok := asInt(v)
		if !ok {
			return fmt.Errorf("expected an integer, got %s", tomlTypeName(v))
		}
		if o.Min != nil && n < int64(*o.Min) {
			return fmt.Errorf("%d is below the minimum %d", n, *o.Min)
		}
		if o.Max != nil && n > int64(*o.Max) {
			return fmt.Errorf("%d is above the maximum %d", n, *o.Max)
		}
		return checkChoice(o, n)
	case TypeStringList:
		list, ok := asStrings(v)
		if !ok {
			return fmt.Errorf("expected an array of strings, got %s", tomlTypeName(v))
		}
		if len(o.Members) == 0 {
			return nil
		}
		allowed := map[string]bool{}
		for _, member := range o.Members {
			allowed[member] = true
		}
		for _, item := range list {
			if !allowed[item] {
				return fmt.Errorf("%q is not one of %s", item, strings.Join(o.Members, ", "))
			}
		}
		return nil
	}
	return fmt.Errorf("unknown option type %q", o.Type)
}

// checkChoice enforces an exhaustive value set. Matching is exact: these values
// go straight into a config the upstream parses, and "socks5" is not "SOCKS5".
func checkChoice(o Option, v any) error {
	if len(o.Choices) == 0 {
		return nil
	}
	labels := make([]string, 0, len(o.Choices))
	for _, c := range o.Choices {
		if sameValue(c.Value, v) {
			return nil
		}
		labels = append(labels, fmt.Sprintf("%v", c.Value))
	}
	return fmt.Errorf("%v is not one of %s", v, strings.Join(labels, ", "))
}

// sameValue compares after numeric normalisation, so a manifest int matches a
// TOML int64 and a JSON float64.
func sameValue(a, b any) bool {
	if an, aok := asInt(a); aok {
		bn, bok := asInt(b)
		return bok && an == bn
	}
	return a == b
}

func tomlTypeName(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int, int32, int64:
		return "an integer"
	case float64:
		return "a float"
	case []any, []string:
		return "an array"
	case map[string]any:
		return "a table"
	}
	return fmt.Sprintf("%T", v)
}

// Warnings reports what is legal but worth saying out loud: keys the manifest
// does not know, keys this fork's own sample never showed, and keys the panel
// owns and will therefore ignore.
func Warnings(m Manifest, scope Scope, doc Document) []string {
	out := []string{}
	for _, k := range sortedKeys(doc) {
		o, ok := m.Option(scope, k)
		if !ok {
			out = append(out, fmt.Sprintf("%s: not a key this panel knows for %s — kept verbatim and written as-is", k, m.Adapter))
			continue
		}
		if o.Runtime {
			out = append(out, fmt.Sprintf("%s: owned by the panel — kept in your document but not applied", k))
			continue
		}
		if !o.Verified {
			out = append(out, fmt.Sprintf("%s: not present in %s's own shipped sample — verify your build accepts it", k, m.Adapter))
		}
	}
	sort.Strings(out)
	return out
}

// ValidateOverrideTOML parses and validates an advanced-override document. It is
// the single entry point the API uses before storing one.
func ValidateOverrideTOML(m Manifest, scope Scope, text string) (Document, []string, error) {
	doc, err := ParseTOML(text)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateDocument(m, scope, doc); err != nil {
		return nil, nil, err
	}
	return doc, Warnings(m, scope, doc), nil
}
