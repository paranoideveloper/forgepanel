package settings

// The registry of operator-editable settings.
//
// Every knob outside panel.json lived as a bare row in the SQLite settings
// table, and everything else about it — its type, its default, the values it
// legally takes, whether it is a secret, what it means — lived in whichever
// reader happened to want it. That had three consequences, all of them observed
// in this codebase:
//
//	the default was written twice   subRoutingPreset() returned "iran" from two
//	                                branches, and nothing tied either to the
//	                                value the UI showed as selected.
//	the write was not checked       POST /settings/subscription stored whatever
//	                                arrived. routing.Preset() then silently fell
//	                                back to the Iran rules for a name it did not
//	                                know, so the panel displayed one policy and
//	                                served another.
//	the surface was not listable    nothing could enumerate the knobs, so the UI
//	                                carried its own hardcoded copy of every enum
//	                                and every default, free to drift.
//
// A Def is the single description each key gets. The shape deliberately mirrors
// upstream.Option (internal/forgedns/upstream/options.go) so this panel has one
// idiom for "a typed, validated, documented setting" rather than two.

import (
	"fmt"
	"sort"
	"strings"
)

// Kind is the value type, which fixes both the stored encoding and the widget
// the UI should offer. Only the kinds this panel actually stores exist here: a
// kind nothing uses is a kind nothing tests.
type Kind string

const (
	KindString     Kind = "string"
	KindBool       Kind = "bool"
	KindEnum       Kind = "enum"
	KindStringList Kind = "string_list"
	KindIntList    Kind = "int_list"
	KindDomain     Kind = "domain"
	KindSecret     Kind = "secret"
)

// Scope groups keys by the card that owns them. ScopeInternal is the important
// one: it marks a key the PANEL owns and an operator must never be offered —
// mid-enrolment TOTP secrets and the edge feed's bearer token. It plays the same
// role as upstream.Option.Runtime.
type Scope string

const (
	ScopeSubscription Scope = "subscription"
	ScopePanel        Scope = "panel"
	ScopeTelegram     Scope = "telegram"
	ScopeBackup       Scope = "backup"
	ScopeInternal     Scope = "internal"
)

// Def describes one setting key.
//
// Default is stored in the SAME encoding as a written value, never a prettier
// one: sub_expand_sni defaults to "1" because its reader treats anything other
// than "0" as on, and a Def that said "true" would read back as on after being
// switched off. Kind fixes that encoding; Normalize and Validate are the escape
// hatch for the handful of keys that need more than their kind can express.
type Def struct {
	Key   string
	Kind  Kind
	Scope Scope

	// Default is the value every reader falls back to when the key is absent.
	Default string

	// Choices are the only legal values for KindEnum, in the order the UI should
	// offer them.
	Choices []string

	// Secret marks a credential: it is never echoed back over the API, and only
	// its presence is reported.
	Secret bool

	// Prefix marks a key family rather than a key — the stored key is this
	// string plus a per-subject suffix (pending_totp_<username>). Lookup matches
	// such a def by prefix so per-subject keys still get typed, validated writes.
	Prefix bool

	// Help is shown to the operator. A knob no one can explain is a knob no one
	// should be given.
	Help string

	// Validate runs after the kind's own check, for a rule the kind cannot
	// express — "every entry in this list is an address", say.
	Validate func(string) error
}

// FieldError is one rejected key.
type FieldError struct {
	Key     string `json:"key"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Key + ": " + e.Message }

// ValidationError collects every problem in one save. A settings card writes
// eleven keys at once; reporting the first bad one would mean one round trip per
// mistake, and the operator fixing the last one would have already been told the
// save succeeded ten times.
type ValidationError struct {
	Errors []FieldError `json:"errors"`
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fe.Error())
	}
	return fmt.Sprintf("settings: %d invalid value(s): %s", len(e.Errors), strings.Join(parts, "; "))
}

// Fields renders the errors as the {field: reason} map the rest of this API
// answers a refused write with, so the UI can mark the offending input instead
// of showing a sentence in a toast.
func (e *ValidationError) Fields() map[string]string {
	out := make(map[string]string, len(e.Errors))
	for _, fe := range e.Errors {
		out[fe.Key] = fe.Message
	}
	return out
}

// Registry holds the defs. Order is preserved and never derived from map
// iteration: the registry is served to the UI and compared in tests, and a
// listing that reshuffles itself between calls is one nobody can diff.
type Registry struct {
	defs  map[string]Def
	order []string
}

func NewRegistry() *Registry {
	return &Registry{defs: map[string]Def{}}
}

// Register adds a def. A duplicate key panics rather than overwriting: both
// registrations run at init, one of them would silently win, and the losing
// half's type and default would apply to nothing while still looking correct in
// the source.
func (r *Registry) Register(d Def) {
	if d.Key == "" {
		panic("settings: a def with no key")
	}
	if _, dup := r.defs[d.Key]; dup {
		panic("settings: duplicate registration for " + d.Key)
	}
	r.defs[d.Key] = d
	r.order = append(r.order, d.Key)
}

// Lookup resolves a stored key to its def, matching prefix defs by prefix so
// pending_totp_alice finds the pending_totp_ family.
func (r *Registry) Lookup(key string) (Def, bool) {
	if r == nil {
		return Def{}, false
	}
	if d, ok := r.defs[key]; ok && !d.Prefix {
		return d, true
	}
	for _, k := range r.order {
		d := r.defs[k]
		if d.Prefix && strings.HasPrefix(key, d.Key) {
			return d, true
		}
	}
	return Def{}, false
}

// All returns every def in registration order.
func (r *Registry) All() []Def {
	if r == nil {
		return nil
	}
	out := make([]Def, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, r.defs[k])
	}
	return out
}

// normalize applies the kind's canonical encoding. Every write goes through it,
// so the stored form of a value never depends on which caller wrote it.
func (d Def) normalize(v string) string {
	switch d.Kind {
	case KindBool:
		v = boolString(truthy(v))
	case KindEnum:
		v = strings.ToLower(strings.TrimSpace(v))
	case KindDomain:
		v = NormalizeDomain(v)
	case KindStringList, KindIntList:
		// Rejoined in one canonical separator so the stored form is stable no
		// matter which of the accepted separators the operator typed.
		v = strings.Join(SplitList(v), ", ")
	default:
		v = strings.TrimSpace(v)
	}
	return v
}

// check validates an ALREADY normalized value.
func (d Def) check(v string) error {
	switch d.Kind {
	case KindEnum:
		if !contains(d.Choices, v) {
			return fmt.Errorf("%q is not one of: %s", v, strings.Join(d.Choices, ", "))
		}
	case KindDomain:
		if v != "" && !ValidDomain(v) {
			return fmt.Errorf("%q is not a hostname", v)
		}
	case KindSecret:
		// A credential with a control character in it corrupts the header or the
		// URL it is pasted into, and the failure surfaces far from here.
		if strings.ContainsAny(v, "\x00\r\n\t ") {
			return fmt.Errorf("contains whitespace or a control character")
		}
	case KindIntList:
		for _, f := range SplitList(v) {
			if !isInt(f) {
				return fmt.Errorf("%q is not a whole number", f)
			}
		}
	}
	if d.Validate != nil {
		return d.Validate(v)
	}
	return nil
}

// SplitList splits an operator-typed list on any of the separators a human
// plausibly uses. It is shared by the clean-IP list and the Telegram chat ids so
// the two cannot disagree about what a list is.
func SplitList(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func isInt(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
