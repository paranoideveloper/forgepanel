package upstream

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// normValue collapses the shapes the same value takes in a Go struct, a TOML
// document and a JSON payload, so a comparison is about the VALUE and not about
// which decoder produced it.
func normValue(v any) any {
	if n, ok := asInt(v); ok {
		return n
	}
	if list, ok := asStrings(v); ok {
		return "[" + strings.Join(list, "\x00") + "]"
	}
	return v
}

func parseTOMLMap(t *testing.T, text string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := toml.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("not valid TOML: %v\n---\n%s", err, text)
	}
	return m
}

// TestManifestMatchesRenderer is the load-bearing test of this change: the
// manifest claims to describe what the panel writes, and an editable surface
// built on a manifest that has drifted from the renderer is worse than no
// surface at all — it would show an operator a key the file does not contain, or
// silently drop one it does. Checked in BOTH directions, for both scopes.
func TestManifestMatchesRenderer(t *testing.T) {
	for _, adapter := range Names() {
		d, err := Lookup(adapter)
		if err != nil {
			t.Fatal(err)
		}
		m, err := ManifestFor(adapter)
		if err != nil {
			t.Fatal(err)
		}
		z := zone(adapter)
		z.EncryptKey = "0123456789abcdef"

		serverText, err := RenderServer(d, z)
		if err != nil {
			t.Fatal(err)
		}
		clientText, err := RenderClient(d, z, ClientOptions{})
		if err != nil {
			t.Fatal(err)
		}
		normal := z
		normal.Normalize(d)
		for _, tc := range []struct {
			scope Scope
			text  string
			doc   Document
		}{
			{ScopeServer, serverText, mergeDocs(ServerManagedDocument(d, normal), serverRuntimeDocument(d))},
			{ScopeClient, clientText, mergeDocs(ClientManagedDocument(d, normal, ClientOptions{}), clientRuntimeDocument(d, normal))},
		} {
			rendered := parseTOMLMap(t, tc.text)
			managed := map[string]bool{}
			for _, o := range m.Options(tc.scope) {
				if o.Managed {
					managed[o.Key] = true
				}
			}
			for key := range rendered {
				if !managed[key] {
					t.Errorf("%s %s: renderer writes %s but the manifest does not mark it managed",
						adapter, tc.scope, key)
				}
			}
			for key := range managed {
				if _, ok := rendered[key]; !ok {
					t.Errorf("%s %s: manifest marks %s managed but the renderer never writes it",
						adapter, tc.scope, key)
				}
			}
			// The document builders feed the merge; they must agree with the
			// hand-written renderer value for value, not just key for key.
			for key, want := range tc.doc {
				if got := normValue(rendered[key]); got != normValue(want) {
					t.Errorf("%s %s: %s = %v in the file, %v in the managed document",
						adapter, tc.scope, key, rendered[key], want)
				}
			}
		}
	}
}

func mergeDocs(docs ...Document) Document {
	out := Document{}
	for _, d := range docs {
		for k, v := range d {
			out[k] = v
		}
	}
	return out
}

// TestManifestForksDiffer guards the §0 trap: these are three forks of one
// codebase, and the panel must not pretend their key sets are identical.
func TestManifestForksDiffer(t *testing.T) {
	cotten, _ := ManifestFor(AdapterCottenDNS)
	storm, _ := ManifestFor(AdapterStormDNS)
	master, _ := ManifestFor(AdapterMasterDNS)

	for _, key := range []string{"TCP_LISTENER_ENABLED", "DOT_LISTENER_ENABLED",
		"DOH_LISTENER_ENABLED", "ENCRYPTION_AUTO_DETECT", "A_RECORD_DATA_DELIVERY"} {
		if _, ok := cotten.Option(ScopeServer, key); !ok {
			t.Errorf("cottendns server manifest is missing %s (§3)", key)
		}
		for _, m := range []Manifest{storm, master} {
			if o, ok := m.Option(ScopeServer, key); ok {
				t.Errorf("%s must not offer %s (its CONFIG_VERSION does not know it): %+v", m.Adapter, key, o)
			}
		}
	}
	if _, ok := cotten.Option(ScopeClient, "QUERY_TYPES"); !ok {
		t.Error("QUERY_TYPES is a CottenDNS client knob and must be in its manifest")
	}
	if _, ok := storm.Option(ScopeClient, "QUERY_TYPES"); ok {
		t.Error("stormdns must not offer QUERY_TYPES")
	}
	// StormDNS's shipped sample carries the balancing key; the other two only
	// get it as an unverified override-only option, never managed.
	if o, _ := storm.Option(ScopeClient, "RESOLVER_BALANCING_STRATEGY"); !o.Managed || !o.Verified {
		t.Errorf("stormdns RESOLVER_BALANCING_STRATEGY should be managed+verified, got %+v", o)
	}
	for _, m := range []Manifest{cotten, master} {
		o, ok := m.Option(ScopeClient, "RESOLVER_BALANCING_STRATEGY")
		if !ok || o.Managed || o.Verified {
			t.Errorf("%s RESOLVER_BALANCING_STRATEGY should be override-only and unverified, got %+v/%v", m.Adapter, o, ok)
		}
	}
	for adapter, want := range map[string]string{
		AdapterStormDNS: "10", AdapterMasterDNS: "12", AdapterCottenDNS: "14",
	} {
		m, _ := ManifestFor(adapter)
		if m.ConfigVersion != want {
			t.Errorf("%s manifest CONFIG_VERSION = %q, want %q", adapter, m.ConfigVersion, want)
		}
		if o, _ := m.Option(ScopeServer, "CONFIG_VERSION"); o.Default != want {
			t.Errorf("%s CONFIG_VERSION default = %v, want %q", adapter, o.Default, want)
		}
	}
}

// TestManifestSecretsAndRuntime pins the two rules that keep the editor safe:
// the server file never inlines key material, and the values the panel owns are
// marked so the merge and the UI both refuse to let an override touch them.
func TestManifestSecretsAndRuntime(t *testing.T) {
	for _, adapter := range Names() {
		m, _ := ManifestFor(adapter)
		if keys := m.SecretKeys(ScopeServer); len(keys) != 0 {
			t.Errorf("%s: server config must hold no secret (it references a key FILE), got %v", adapter, keys)
		}
		if got := m.SecretKeys(ScopeClient); len(got) == 0 || got[0] != "ENCRYPTION_KEY" {
			t.Errorf("%s: client ENCRYPTION_KEY must be marked secret, got %v", adapter, got)
		}
		// The runtime set is pinned so a key cannot quietly become panel-owned:
		// an override that sets one is parsed, preserved and then IGNORED, which
		// is exactly the behaviour an operator would not expect to be given by
		// accident.
		//
		// DOT_LISTEN_HOST and DOH_LISTEN_HOST were added to it deliberately. The
		// panel pins them to 127.0.0.1 whenever the matching port is private,
		// because a private port on a public interface is still reachable from
		// the internet — a client that knows the number bypasses the front
		// router entirely. Leaving that key operator-editable would let an
		// override silently undo the isolation the port move exists to create.
		// CottenDNS-only, hence the adapter split below.
		serverRuntime := []string{"CONFIG_VERSION", "ENCRYPTION_KEY_FILE"}
		if d, err := Lookup(adapter); err == nil && d.HasListenerToggles {
			serverRuntime = []string{"CONFIG_VERSION", "DOH_LISTEN_HOST", "DOT_LISTEN_HOST", "ENCRYPTION_KEY_FILE"}
		}
		for scope, want := range map[Scope][]string{
			ScopeServer: serverRuntime,
			ScopeClient: {"CONFIG_VERSION", "ENCRYPTION_KEY"},
		} {
			got := m.RuntimeKeys(scope)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s %s runtime keys = %v, want %v", adapter, scope, got, want)
			}
		}
		// SafeEdit is derived, never hand-set: panel-owned and secret keys are
		// out of the managed form's reach by construction.
		for _, scope := range []Scope{ScopeServer, ScopeClient} {
			for _, o := range m.Options(scope) {
				if want := o.Managed && !o.Runtime && !o.Secret; o.SafeEdit != want {
					t.Errorf("%s %s.%s SafeEdit = %v, want %v", adapter, scope, o.Key, o.SafeEdit, want)
				}
				if o.Scope != scope {
					t.Errorf("%s: %s is filed under %s but declares scope %s", adapter, o.Key, scope, o.Scope)
				}
			}
		}
	}
}

// TestOptionAdapterAttribution: every option says which forks carry it, so the
// UI does not need a second table to say "CottenDNS only".
func TestOptionAdapterAttribution(t *testing.T) {
	cotten, _ := ManifestFor(AdapterCottenDNS)
	o, _ := cotten.Option(ScopeServer, "DOMAIN")
	if len(o.Adapters) != 3 {
		t.Errorf("DOMAIN should be attributed to all three forks, got %v", o.Adapters)
	}
	o, _ = cotten.Option(ScopeServer, "TCP_LISTENER_ENABLED")
	if len(o.Adapters) != 1 || o.Adapters[0] != AdapterCottenDNS {
		t.Errorf("TCP_LISTENER_ENABLED adapters = %v, want [cottendns]", o.Adapters)
	}
	// The chained-egress trio is inherited from the shared dialect (§4b) rather
	// than read from the CottenDNS sample — that must be visible, not hidden.
	if o, _ := cotten.Option(ScopeServer, "FORWARD_IP"); o.Verified {
		t.Error("cottendns FORWARD_IP is not in its own shipped sample; it must be flagged unverified")
	}
	storm, _ := ManifestFor(AdapterStormDNS)
	if o, _ := storm.Option(ScopeServer, "FORWARD_IP"); !o.Verified {
		t.Error("stormdns FORWARD_IP is verbatim in §2 and should be marked verified")
	}
}

func TestAdapterForConfigVersion(t *testing.T) {
	for version, want := range map[string]string{
		"10": AdapterStormDNS, "12": AdapterMasterDNS, "14": AdapterCottenDNS,
	} {
		if got, ok := AdapterForConfigVersion(version); !ok || got != want {
			t.Errorf("AdapterForConfigVersion(%q) = %q/%v, want %q", version, got, ok, want)
		}
	}
	if _, ok := AdapterForConfigVersion("99"); ok {
		t.Error("an unknown CONFIG_VERSION must not resolve to an adapter")
	}
}
