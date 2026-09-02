package settings

// Typed access to the settings table.
//
// This is the ONLY place in the panel that reaches the key/value store for a
// setting. Everything else asks for a key and gets a value of the right type,
// already defaulted; everything else writes a key and gets an error back if the
// value was not one the key accepts. Before this, each reader carried its own
// copy of the default and no writer checked anything at all.

import (
	"errors"
	"fmt"
	"strings"
)

// KV is the slice of the store this package needs. *store.Store satisfies it,
// and so does anything in a test that wants to watch the writes.
type KV interface {
	GetSetting(key string) string
	SetSetting(key, value string) error
}

// Values reads and writes settings through a Registry.
//
// A nil *Values is usable and answers every read with the registered default.
// That is not a convenience: the stateless constructor (api.New, used by the
// Config Studio and by unit tests) has no database at all, and every reader in
// the panel already had to behave sensibly without one.
type Values struct {
	kv  KV
	reg *Registry
}

func NewValues(kv KV) *Values { return &Values{kv: kv, reg: Defs()} }

// ErrNoStore is returned by a write when there is no database behind this
// Values. Callers that mirror a value best-effort ignore it; callers that must
// persist report it.
var ErrNoStore = errors.New("settings: no store is open")

func (v *Values) registry() *Registry {
	if v == nil || v.reg == nil {
		return defaults
	}
	return v.reg
}

func (v *Values) raw(key string) string {
	if v == nil || v.kv == nil {
		return ""
	}
	return v.kv.GetSetting(key)
}

// stored returns the value to interpret: what is in the store, or the def's
// default when the key has never been written.
func (v *Values) stored(key string) (Def, string) {
	d, ok := v.registry().Lookup(key)
	raw := strings.TrimSpace(v.raw(key))
	if raw == "" && ok {
		return d, d.Default
	}
	return d, raw
}

// String returns a string-ish setting, falling back to its default.
func (v *Values) String(key string) string {
	d, raw := v.stored(key)
	if raw == "" {
		return ""
	}
	// Normalized on the way out as well as in, so a row written before this key
	// had a def — or edited in the database by hand — reads the same as one this
	// package wrote.
	return d.normalize(raw)
}

// Bool returns a boolean setting, falling back to its default.
func (v *Values) Bool(key string) bool {
	_, raw := v.stored(key)
	return truthy(raw)
}

// List splits a list setting into its entries. Nil, not an empty slice, when
// there is nothing set: the callers pass it straight into range and into
// len() == 0 checks.
func (v *Values) List(key string) []string {
	_, raw := v.stored(key)
	return SplitList(raw)
}

// Has reports whether a key holds a value of its own, which is how a secret's
// presence is reported without echoing it.
func (v *Values) Has(key string) bool {
	return strings.TrimSpace(v.raw(key)) != ""
}

// Set writes one setting, normalizing and validating it first.
func (v *Values) Set(key, value string) error {
	return v.SetAll(map[string]string{key: value})
}

// SetAll writes a batch atomically with respect to validation: every value is
// checked before ANY of them is written, so a card that saves eleven keys and
// gets one wrong leaves all eleven as they were. Half-applying it was the old
// behaviour and it left the operator looking at a form whose state nobody chose.
func (v *Values) SetAll(values map[string]string) error {
	if v == nil || v.kv == nil {
		return ErrNoStore
	}
	keys := sortedKeys(values)
	ve := &ValidationError{}
	normalized := make(map[string]string, len(values))
	for _, k := range keys {
		d, ok := v.registry().Lookup(k)
		if !ok {
			ve.Errors = append(ve.Errors, FieldError{k, "not a setting this panel knows"})
			continue
		}
		n := d.normalize(values[k])
		if err := d.check(n); err != nil {
			ve.Errors = append(ve.Errors, FieldError{k, err.Error()})
			continue
		}
		normalized[k] = n
	}
	if len(ve.Errors) > 0 {
		return ve
	}
	// Sorted, so a store failure part-way through leaves a state that can be
	// reasoned about rather than one that depends on map iteration.
	for _, k := range keys {
		if err := v.kv.SetSetting(k, normalized[k]); err != nil {
			return fmt.Errorf("settings: writing %s: %w", k, err)
		}
	}
	return nil
}

// DefaultValue renders a def's default in its own type, for the API's registry
// listing. A UI that gets "1" for a checkbox has to know the encoding, which is
// exactly the knowledge this package exists to hold.
func DefaultValue(d Def) any {
	switch d.Kind {
	case KindBool:
		return truthy(d.Default)
	case KindStringList, KindIntList:
		return SplitList(d.Default)
	case KindSecret:
		return nil
	default:
		return d.Default
	}
}

// Value renders a key's current value in its own type. A secret returns nil: the
// registry lists that the key exists and whether it is set, never what it holds.
func (v *Values) Value(d Def) any {
	switch d.Kind {
	case KindBool:
		return v.Bool(d.Key)
	case KindStringList, KindIntList:
		return v.List(d.Key)
	case KindSecret:
		return nil
	default:
		return v.String(d.Key)
	}
}
