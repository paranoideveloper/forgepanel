package upstream

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Layered configuration: the panel's answer to "let me edit the raw TOML"
// without giving up the ability to keep managing the zone.
//
// Four layers, applied in this exact order, lowest first:
//
//	default   the adapter's documented default for keys the panel already emits
//	managed   the zone's typed settings (the DB columns / the zone form)
//	override  the operator's advanced-override TOML document
//	runtime   values the panel OWNS — the key file path, the shared secret and
//	          CONFIG_VERSION
//
// Why the override sits above managed: an escape hatch that loses to the form is
// not an escape hatch. Why runtime sits above the override: those three values
// are not preferences. CONFIG_VERSION decides whether the binary accepts the
// file at all (§4b), ENCRYPTION_KEY_FILE is a path the panel created and writes,
// and the client's ENCRYPTION_KEY is the zone's secret — an override that could
// rewrite them would turn a config editor into a way to point the server at
// another key or to publish one. They are still parsed and preserved, then
// reported as ignored, so nothing an operator typed silently disappears.
//
// The merge is deterministic: same inputs, same output text, key order fixed by
// the manifest. That matters because the manager restarts a zone when the
// rendered config's signature changes — a map-order wobble would restart every
// tunnel on every sync.

// Document is a parsed TOML config: flat upstream keys to decoded values.
type Document map[string]any

// Layer names where an effective value came from.
type Layer string

const (
	LayerDefault  Layer = "default"
	LayerManaged  Layer = "managed"
	LayerOverride Layer = "override"
	LayerRuntime  Layer = "runtime"
)

// MaskedValue replaces key material in every response. It is also accepted back
// on write and means "keep the stored value" — otherwise an operator who edits a
// config that was shown to them masked would save the mask as the new secret.
const MaskedValue = "********"

// Effective is a merged configuration plus the provenance the UI needs to show
// which keys are panel-managed, which the operator overrode, and which were
// preserved but not understood.
type Effective struct {
	Adapter string           `json:"adapter"`
	Scope   Scope            `json:"scope"`
	Values  Document         `json:"-"` // never marshalled directly: may hold secrets
	Order   []string         `json:"order"`
	Origin  map[string]Layer `json:"origin"`
	Unknown []string         `json:"unknown"` // in the override, not in the manifest
	Ignored []string         `json:"ignored"` // override keys the runtime layer took back
}

// Merge applies the four layers in order and records where each key came from.
func Merge(m Manifest, scope Scope, defaults, managed, override, runtime Document) Effective {
	e := Effective{
		Adapter: m.Adapter, Scope: scope,
		Values: Document{}, Origin: map[string]Layer{},
		Unknown: []string{}, Ignored: []string{},
	}
	for _, l := range []struct {
		name Layer
		doc  Document
	}{{LayerDefault, defaults}, {LayerManaged, managed}} {
		for k, v := range l.doc {
			e.Values[k], e.Origin[k] = v, l.name
		}
	}
	for _, k := range sortedKeys(override) {
		opt, known := m.Option(scope, k)
		if !known {
			e.Unknown = append(e.Unknown, k)
		} else if opt.Runtime {
			// Parsed and kept in the stored override document, but never applied:
			// the panel owns this value (see the file comment).
			e.Ignored = append(e.Ignored, k)
			continue
		}
		e.Values[k], e.Origin[k] = override[k], LayerOverride
	}
	for k, v := range runtime {
		e.Values[k], e.Origin[k] = v, LayerRuntime
	}
	e.Order = orderKeys(m, scope, e.Values)
	return e
}

// orderKeys puts the keys in manifest (= renderer) order so a generated file
// diffs cleanly against the upstream's own sample, with anything the manifest
// does not know appended in a stable alphabetical block.
func orderKeys(m Manifest, scope Scope, doc Document) []string {
	out := make([]string, 0, len(doc))
	seen := map[string]bool{}
	for _, k := range m.Order(scope) {
		if _, ok := doc[k]; ok {
			out, seen[k] = append(out, k), true
		}
	}
	rest := []string{}
	for k := range doc {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// Masked returns a copy of the values with every secret replaced by MaskedValue.
func (e Effective) Masked(m Manifest) Document { return MaskDocument(m, e.Scope, e.Values) }

// MaskDocument replaces every secret value with MaskedValue. Two sources of
// "secret": the manifest's own Secret flag, and a name heuristic for keys the
// manifest has never heard of — an operator can paste anything into the
// override, and a response that leaks a key nobody declared is still a leak.
func MaskDocument(m Manifest, scope Scope, doc Document) Document {
	out := Document{}
	for k, v := range doc {
		if isSecretKey(m, scope, k) {
			out[k] = MaskedValue
			continue
		}
		out[k] = v
	}
	return out
}

// UnmaskDocument restores masked values from the document that was shown to the
// operator. Without this an editor round-trip — GET (masked) then PUT — would
// save the literal mask as the new secret, which is the classic way a config UI
// destroys a credential.
func UnmaskDocument(next, previous Document) Document {
	out := Document{}
	for k, v := range next {
		if s, ok := v.(string); ok && s == MaskedValue {
			if prev, had := previous[k]; had {
				out[k] = prev
			}
			// Dropped when there is nothing to restore: writing the mask itself
			// would be worse than leaving the key unset.
			continue
		}
		out[k] = v
	}
	return out
}

// SecretKeys lists the keys of this document whose value is masked.
func (e Effective) SecretKeys(m Manifest) []string {
	out := []string{}
	for k := range e.Values {
		if e.isSecret(m, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (e Effective) isSecret(m Manifest, key string) bool {
	return isSecretKey(m, e.Scope, key)
}

func isSecretKey(m Manifest, scope Scope, key string) bool {
	if o, ok := m.Option(scope, key); ok {
		return o.Secret
	}
	return looksSecret(key)
}

// looksSecret is the heuristic for undeclared keys. It is deliberately eager:
// masking a harmless key costs an operator one round-trip, publishing a secret
// costs them the zone.
func looksSecret(key string) bool {
	k := strings.ToUpper(key)
	for _, frag := range []string{"KEY", "SECRET", "PASS", "TOKEN", "CREDENTIAL"} {
		if strings.Contains(k, frag) {
			return !strings.HasSuffix(k, "_KEY_FILE") // a path is not key material
		}
	}
	return false
}

// TOML renders the merged document, secrets included — this is what gets written
// to disk for the supervised process.
func (e Effective) TOML(header string) (string, error) {
	return renderDocument(header, e.Order, e.Values)
}

// MaskedTOML renders the same document with key material replaced, for display.
func (e Effective) MaskedTOML(m Manifest, header string) (string, error) {
	return renderDocument(header, e.Order, e.Masked(m))
}

// ParseTOML decodes an upstream config file into a Document.
func ParseTOML(text string) (Document, error) {
	doc := Document{}
	if strings.TrimSpace(text) == "" {
		return doc, nil
	}
	if err := toml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("forgedns: config is not valid TOML: %w", err)
	}
	return doc, nil
}

// renderDocument writes a flat upstream config. Values are emitted with the same
// quoting the shipped samples use (double-quoted strings, inline arrays) rather
// than via a generic marshaller, so the panel's file and the release's own file
// stay diffable. Table-valued keys can only come from an imported override, so
// they are appended last — TOML requires top-level keys before any table header.
func renderDocument(header string, order []string, doc Document) (string, error) {
	var b strings.Builder
	if header != "" {
		b.WriteString(header)
		if !strings.HasSuffix(header, "\n") {
			b.WriteString("\n")
		}
	}
	var tables []string
	for _, k := range order {
		v, ok := doc[k]
		if !ok {
			continue
		}
		if isTable(v) {
			tables = append(tables, k)
			continue
		}
		s, err := tomlValue(v)
		if err != nil {
			return "", fmt.Errorf("forgedns: %s: %w", k, err)
		}
		fmt.Fprintf(&b, "%s = %s\n", tomlKey(k), s)
	}
	for _, k := range tables {
		out, err := toml.Marshal(map[string]any{k: doc[k]})
		if err != nil {
			return "", fmt.Errorf("forgedns: %s: %w", k, err)
		}
		b.WriteString("\n" + string(out))
	}
	return b.String(), nil
}

func isTable(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// tomlKey quotes a key that is not a bare TOML key. Imported files can carry
// quoted keys, and writing one back raw would produce a file that no longer parses.
func tomlKey(k string) string {
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return strconv.Quote(k)
		}
	}
	if k == "" {
		return `""`
	}
	return k
}

func tomlValue(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return strconv.Quote(t), nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	case []string:
		return tomlStrings(t), nil
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			s, err := tomlValue(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	}
	if n, ok := asInt(v); ok {
		return strconv.FormatInt(n, 10), nil
	}
	return "", fmt.Errorf("cannot render %T as TOML", v)
}

// asInt normalises every integer shape that can reach a Document: Go ints from
// the panel's own structs, int64 from the TOML decoder, and float64 from JSON.
func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint:
		return int64(t), true
	case uint64:
		return int64(t), true
	case float64:
		if t == float64(int64(t)) {
			return int64(t), true
		}
	}
	return 0, false
}

// asStrings normalises a string list from either the panel ([]string) or the
// TOML/JSON decoders ([]any).
func asStrings(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func sortedKeys(doc Document) []string {
	out := make([]string, 0, len(doc))
	for k := range doc {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
