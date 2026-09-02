package upstream

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the versioned option MANIFEST: a per-adapter description of every
// upstream config key the panel knows about.
//
// Why this exists next to the Descriptor capability flags rather than replacing
// them: the booleans in Descriptor answer exactly one question — "may the
// renderer emit this block for this fork at all" — which is all the renderer
// needs. An *editable* config surface has to answer four more questions per key
// that a bool cannot: what type and range is legal, is the value secret, does
// changing it restart the tunnel, and is it something the panel's own managed
// form owns or something only the advanced override may set. Guessing any of
// those in the UI means either a rejected config (§4b: these binaries reject a
// file whose CONFIG_VERSION — and, in practice, whose unknown keys — they do not
// know) or a leaked key. So the manifest carries them explicitly, per adapter.
//
// The three forks are deliberately NOT modelled as one key set. Every option
// below is attributed to the fork whose shipped config it was actually read from
// (docs/FORGEDNS_UPSTREAM_SETUP.md §1 MasterDnsVPN, §2 StormDNS, §3 CottenDNS);
// where the panel emits a key for a fork whose own sample did not show it, the
// option is marked Verified=false instead of being silently promoted.

// Scope separates the two files the panel generates per zone: the server config
// it writes and supervises, and the client config it hands the user in a bundle.
// The same key name can exist in both with different rules — DATA_ENCRYPTION_METHOD
// is managed on both sides, but ENCRYPTION_KEY_FILE is server-only and
// ENCRYPTION_KEY is client-only, and mixing them up leaks the key into the file
// that is meant to stay on the server.
type Scope string

const (
	ScopeServer Scope = "server"
	ScopeClient Scope = "client"
)

// OptionType is the TOML type an option's value must decode to.
type OptionType string

const (
	TypeString     OptionType = "string"
	TypeInt        OptionType = "int"
	TypeBool       OptionType = "bool"
	TypeStringList OptionType = "string_list"
)

// Choice is one allowed value of an enumerated option, with the label the UI
// shows. Values are compared after numeric normalisation, so an int choice
// matches a TOML-decoded int64.
type Choice struct {
	Value any    `json:"value"`
	Label string `json:"label"`
}

// Option describes ONE upstream config key for ONE adapter.
type Option struct {
	Key   string     `json:"key"`
	Scope Scope      `json:"scope"`
	Type  OptionType `json:"type"`

	// Default is what the panel (or the upstream) uses when nothing sets the
	// key. It is a fallback for a key the panel already emits — never a reason
	// to START emitting a key the fork may not know (see Merge).
	Default any `json:"default,omitempty"`

	Min     *int     `json:"min,omitempty"`
	Max     *int     `json:"max,omitempty"`
	Choices []Choice `json:"choices,omitempty"` // exhaustive allowed values
	Members []string `json:"members,omitempty"` // allowed members of a string list

	// Secret marks key material. A secret value is masked in every GET response
	// and is never echoed back, whichever layer set it.
	Secret bool `json:"secret"`

	// Restart is true when changing the key restarts the supervised process.
	// Server keys are read once at start, so all of them restart the zone;
	// client keys only take effect when the *user* restarts their client.
	Restart bool `json:"restart_required"`

	// Managed means the panel models this key as a first-class zone setting and
	// emits it from the managed layer. A Managed=false option is real and
	// documented but reachable only through the advanced override.
	Managed bool `json:"managed"`

	// Runtime means the panel owns the value: paths it created and secrets it
	// minted. The runtime layer is applied last, so an override that sets one of
	// these is parsed, preserved and then ignored rather than silently trusted.
	Runtime bool `json:"runtime"`

	// SafeEdit is the single flag a UI needs: may the managed (form) surface
	// offer this key for editing. Derived, not hand-set — see finalize.
	SafeEdit bool `json:"safe_for_managed_editing"`

	// Verified records whether the key was read from THIS fork's own shipped
	// config, as opposed to inherited from the shared dialect (§0). An
	// unverified key is still emitted where the panel already emitted it, but
	// the UI should say so before an operator debugs a rejected config.
	Verified bool `json:"verified"`

	// Adapters lists every fork whose manifest carries this key+scope. Filled in
	// by finalize so the UI can say "CottenDNS only" without a second table.
	Adapters []string `json:"adapters"`

	Help string `json:"help"`
}

// HealthInfo is the fork's own health/metrics endpoint.
type HealthInfo struct {
	URL  string `json:"url"`
	Note string `json:"note"`
}

// Manifest is one adapter's complete option surface.
type Manifest struct {
	Adapter       string      `json:"adapter"`
	ConfigVersion string      `json:"config_version"`
	Health        *HealthInfo `json:"health,omitempty"`
	Server        []Option    `json:"server"`
	Client        []Option    `json:"client"`
}

// manifests is built once at init from the descriptor table, so the manifest and
// the renderer can never disagree about which fork sees which block.
var manifests = buildManifests()

func buildManifests() map[string]Manifest {
	out := map[string]Manifest{}
	for name, d := range descriptors {
		m := Manifest{
			Adapter:       d.Adapter,
			ConfigVersion: d.ConfigVersion,
			Server:        serverOptions(d),
			Client:        clientOptions(d),
		}
		if d.HealthURL != "" {
			m.Health = &HealthInfo{
				URL: d.HealthURL,
				Note: "Polled by the supervisor. The TOML keys that configure this " +
					"endpoint are not documented upstream, so the panel emits none; " +
					"set them through the advanced override if your build accepts them.",
			}
		}
		out[name] = m
	}
	finalize(out)
	return out
}

// finalize fills the derived fields: which forks carry each key, and whether the
// managed form may edit it. Deriving SafeEdit instead of hand-setting it is what
// keeps "the panel owns this" and "the form may edit this" from drifting apart.
func finalize(all map[string]Manifest) {
	owners := map[string][]string{} // scope+key -> adapters
	for _, name := range order {
		m := all[name]
		for _, list := range [][]Option{m.Server, m.Client} {
			for _, o := range list {
				k := string(o.Scope) + "\x00" + o.Key
				owners[k] = append(owners[k], m.Adapter)
			}
		}
	}
	for name, m := range all {
		for _, list := range [][]Option{m.Server, m.Client} {
			for i := range list {
				o := &list[i]
				o.Adapters = owners[string(o.Scope)+"\x00"+o.Key]
				o.SafeEdit = o.Managed && !o.Runtime && !o.Secret
			}
		}
		all[name] = m
	}
}

// ManifestFor returns one adapter's option manifest (case-insensitive).
func ManifestFor(adapter string) (Manifest, error) {
	m, ok := manifests[Canonical(adapter)]
	if !ok {
		return Manifest{}, fmt.Errorf("forgedns upstream: %q is not a real-binary adapter", adapter)
	}
	return m, nil
}

// Manifests lists every adapter's manifest in the UI's preferred order.
func Manifests() []Manifest {
	out := make([]Manifest, 0, len(manifests))
	for _, d := range Descriptors() {
		out = append(out, manifests[d.Adapter])
	}
	return out
}

// Options returns a copy of one scope's options, in declaration order — which is
// also the order the generated file uses, so a diff against the upstream's own
// sample stays readable.
func (m Manifest) Options(scope Scope) []Option {
	src := m.Server
	if scope == ScopeClient {
		src = m.Client
	}
	return append([]Option(nil), src...)
}

// Option looks up one key in one scope.
func (m Manifest) Option(scope Scope, key string) (Option, bool) {
	src := m.Server
	if scope == ScopeClient {
		src = m.Client
	}
	for _, o := range src {
		if o.Key == key {
			return o, true
		}
	}
	return Option{}, false
}

// Order lists a scope's keys in declaration order.
func (m Manifest) Order(scope Scope) []string {
	opts := m.Options(scope)
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		out = append(out, o.Key)
	}
	return out
}

// Defaults is the bottom layer of the merge: the default of every MANAGED option
// in a scope. Override-only options contribute nothing, because a default is a
// fallback for a key the panel already writes, and materialising an unrequested
// key into a fork's config is exactly the §4b risk this package exists to avoid.
func (m Manifest) Defaults(scope Scope) Document {
	doc := Document{}
	for _, o := range m.Options(scope) {
		if o.Managed && o.Default != nil {
			doc[o.Key] = o.Default
		}
	}
	return doc
}

// SecretKeys lists the keys in a scope whose value is key material.
func (m Manifest) SecretKeys(scope Scope) []string {
	out := []string{}
	for _, o := range m.Options(scope) {
		if o.Secret {
			out = append(out, o.Key)
		}
	}
	sort.Strings(out)
	return out
}

// RuntimeKeys lists the keys in a scope the panel owns outright.
func (m Manifest) RuntimeKeys(scope Scope) []string {
	out := []string{}
	for _, o := range m.Options(scope) {
		if o.Runtime {
			out = append(out, o.Key)
		}
	}
	sort.Strings(out)
	return out
}

// AdapterForConfigVersion maps a CONFIG_VERSION back to the fork that stamps it
// (StormDNS 10, MasterDnsVPN 12, CottenDNS 14 — §4b). Import uses it to work out
// which dialect a pasted file is written in instead of asking the operator.
func AdapterForConfigVersion(version string) (string, bool) {
	v := strings.TrimSpace(version)
	for _, d := range Descriptors() {
		if d.ConfigVersion == v {
			return d.Adapter, true
		}
	}
	return "", false
}

// intPtr is a tiny helper so the option tables can state ranges inline.
func intPtr(v int) *int { return &v }
