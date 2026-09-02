package settings

import (
	"errors"
	"strings"
	"testing"
)

// memKV is a settings table in a map, so these tests assert on what was WRITTEN
// and not merely on what was returned.
type memKV struct {
	m       map[string]string
	failOn  string
	written []string
}

func newKV() *memKV { return &memKV{m: map[string]string{}} }

func (k *memKV) GetSetting(key string) string { return k.m[key] }

func (k *memKV) SetSetting(key, value string) error {
	if key == k.failOn {
		return errors.New("disk full")
	}
	k.m[key] = value
	k.written = append(k.written, key)
	return nil
}

// A reader with no store behind it answers the registered default. Every
// accessor in the API relied on this: the stateless constructor has no database
// and each one carried its own hand-written copy of the same fallback.
func TestReadersFallBackToTheRegisteredDefault(t *testing.T) {
	var v *Values // nil on purpose: no store at all

	if got := v.String("sub_routing_preset"); got != "iran" {
		t.Errorf("routing preset with no store = %q, want iran", got)
	}
	if !v.Bool("sub_expand_sni") {
		t.Error("sub_expand_sni is ON by default and must read ON with no store")
	}
	if v.Bool("sub_front_cleanip") {
		t.Error("sub_front_cleanip is OFF by default")
	}
	if got := v.String("sub_name_template"); got != "" {
		t.Errorf("name template with no store = %q, want empty", got)
	}
	if got := v.List("sub_clean_ips"); got != nil {
		t.Errorf("clean IPs with no store = %v, want nil", got)
	}
	if err := v.Set("sub_routing_preset", "full"); !errors.Is(err, ErrNoStore) {
		t.Errorf("writing with no store returned %v, want ErrNoStore", err)
	}
}

// The stored encoding is the def's business, not the caller's. sub_expand_sni is
// the one that bites: its reader treats anything other than "0" as ON, so an
// "off" written as "false" reads back as on and the toggle appears not to save.
func TestBoolsAreStoredInTheEncodingTheReaderExpects(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	for _, in := range []string{"false", "0", "off", "no"} {
		if err := v.Set("sub_expand_sni", in); err != nil {
			t.Fatalf("Set(%q): %v", in, err)
		}
		if raw := kv.m["sub_expand_sni"]; raw != "0" {
			t.Fatalf("Set(%q) stored %q, want %q", in, raw, "0")
		}
		if v.Bool("sub_expand_sni") {
			t.Fatalf("Set(%q) reads back as ON", in)
		}
	}
	if err := v.Set("sub_expand_sni", "true"); err != nil {
		t.Fatal(err)
	}
	if raw := kv.m["sub_expand_sni"]; raw != "1" || !v.Bool("sub_expand_sni") {
		t.Fatalf("back on stored %q, reads %v", raw, v.Bool("sub_expand_sni"))
	}
}

func TestEnumsRejectAnythingNotInChoices(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	for _, tc := range []struct {
		key, value string
		ok         bool
	}{
		{"sub_routing_preset", "full", true},
		{"sub_routing_preset", "  FULL  ", true}, // trimmed and lowered first
		{"sub_routing_preset", "nonsense", false},
		{"sub_routing_preset", "strict", false}, // an alias routing.Preset takes on a URL, not a stored value
		{"sub_pattern_default", "both", true},
		{"sub_pattern_default", "1", false},
		{"sub_front_mode", "cdn", true},
		{"sub_front_mode", "sideways", false},
	} {
		err := v.Set(tc.key, tc.value)
		if tc.ok && err != nil {
			t.Errorf("%s=%q was refused: %v", tc.key, tc.value, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s=%q was accepted; stored %q", tc.key, tc.value, kv.m[tc.key])
		}
	}
	if kv.m["sub_routing_preset"] != "full" {
		t.Errorf("sub_routing_preset = %q; a refused write reached the store", kv.m["sub_routing_preset"])
	}
	// The refusal has to name the key AND the choices, or the operator is told
	// "invalid" about a form with eleven inputs on it.
	err := v.Set("sub_routing_preset", "nonsense")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("a bad enum returned %T, want *ValidationError", err)
	}
	if msg := ve.Fields()["sub_routing_preset"]; !strings.Contains(msg, "iran") {
		t.Errorf("the refusal does not list the legal values: %q", msg)
	}
}

func TestDomainsAreNormalizedAndChecked(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	// The raw form an operator types is not the form a generated link can dial.
	if err := v.Set("public_address", "HTTPS://Panel.Example.com:8443/admin"); err != nil {
		t.Fatal(err)
	}
	if got := kv.m["public_address"]; got != "panel.example.com" {
		t.Errorf("public_address stored as %q, want the normalized hostname", got)
	}
	if err := v.Set("sub_front_domain", "not a domain"); err == nil {
		t.Error("a front domain with a space in it was accepted")
	}
	// Empty is how fronting is turned off, and must stay legal.
	if err := v.Set("sub_front_domain", ""); err != nil {
		t.Errorf("clearing the front domain was refused: %v", err)
	}
}

func TestCleanIPListRejectsAnEntryThatIsNeitherAddressNorHost(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	good := "104.16.0.1, speed.cloudflare.com\n2606:4700::1111"
	if err := v.Set("sub_clean_ips", good); err != nil {
		t.Fatalf("a valid list was refused: %v", err)
	}
	if got := v.List("sub_clean_ips"); len(got) != 3 || got[0] != "104.16.0.1" {
		t.Fatalf("clean IPs = %v", got)
	}
	if err := v.Set("sub_clean_ips", "104.16.0.1, not a host!"); err == nil {
		t.Error("a clean-IP list with a junk entry was accepted; the fan-out would render configs that dial nothing")
	}
}

// A batch is refused whole. The subscription card saves eleven keys at once, and
// applying the good half leaves the operator looking at a state nobody chose.
func TestSetAllWritesNothingWhenAnyKeyIsBad(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	err := v.SetAll(map[string]string{
		"sub_name_template":  "{FLAG} {NAME}",
		"sub_routing_preset": "nonsense",
		"sub_front_mode":     "sideways",
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("SetAll returned %T (%v), want *ValidationError", err, err)
	}
	if len(ve.Errors) != 2 {
		t.Errorf("reported %d bad key(s), want both of them in one pass: %v", len(ve.Errors), ve.Errors)
	}
	if len(kv.written) != 0 {
		t.Errorf("a refused batch wrote %v", kv.written)
	}
}

func TestUnknownKeysAreRefusedRatherThanStored(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	if err := v.Set("sub_routing_pre5et", "iran"); err == nil {
		t.Fatal("a misspelled key was written; nothing would ever read it back")
	}
	if len(kv.written) != 0 {
		t.Errorf("an unknown key reached the store: %v", kv.written)
	}
}

// pending_totp_<username> is one key per admin, so it is registered as a family.
func TestPerAdminKeysResolveThroughTheirPrefix(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	if err := v.Set("pending_totp_alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("stashing a pending TOTP secret was refused: %v", err)
	}
	if got := v.String("pending_totp_alice"); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("pending secret read back as %q", got)
	}
	d, ok := Lookup("pending_totp_alice")
	if !ok || d.Scope != ScopeInternal {
		t.Errorf("pending_totp_alice resolved to %+v; it is panel-owned state, not an operator setting", d)
	}
}

// A secret carrying a newline produces a broken Authorization header far away
// from the form that accepted it.
func TestSecretsRejectEmbeddedWhitespace(t *testing.T) {
	kv := newKV()
	v := NewValues(kv)

	if err := v.Set("telegram_bot_token", "  123:ABCdef  "); err != nil {
		t.Fatalf("a token with surrounding whitespace should be trimmed, not refused: %v", err)
	}
	if got := kv.m["telegram_bot_token"]; got != "123:ABCdef" {
		t.Errorf("token stored as %q", got)
	}
	if err := v.Set("telegram_bot_token", "123:ABC\ndef"); err == nil {
		t.Error("a token with a newline in it was accepted")
	}
}

// Every registered def has to be describable: the registry is served to the UI
// and a knob with no help and no scope explains nothing to the operator it is
// shown to.
func TestEveryDefIsFullyDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range All() {
		if seen[d.Key] {
			t.Errorf("%s is registered twice", d.Key)
		}
		seen[d.Key] = true
		if d.Kind == "" || d.Scope == "" || d.Help == "" {
			t.Errorf("%s = {kind:%q scope:%q help:%q}: incomplete", d.Key, d.Kind, d.Scope, d.Help)
		}
		if d.Kind == KindEnum {
			if len(d.Choices) == 0 {
				t.Errorf("%s is an enum with no choices, so nothing can be written to it", d.Key)
			}
			if !contains(d.Choices, d.Default) {
				t.Errorf("%s defaults to %q, which is not one of its own choices %v", d.Key, d.Default, d.Choices)
			}
		}
		// A default has to survive its own validator, or the panel ships in a
		// state it would refuse to be put into.
		if err := d.check(d.normalize(d.Default)); err != nil {
			t.Errorf("%s's own default is invalid: %v", d.Key, err)
		}
	}
}

// The order the registry is listed in is the order it was declared in, always.
// It is served to a UI and diffed in tests; a listing that reshuffles itself is
// one nobody can read.
func TestListingOrderIsStable(t *testing.T) {
	first := All()
	for i := 0; i < 20; i++ {
		next := All()
		if len(next) != len(first) {
			t.Fatalf("registry length changed between calls")
		}
		for n := range first {
			if first[n].Key != next[n].Key {
				t.Fatalf("registry order wobbled at %d: %q then %q", n, first[n].Key, next[n].Key)
			}
		}
	}
}

func TestAStoreFailureIsReportedNotSwallowed(t *testing.T) {
	kv := newKV()
	kv.failOn = "sub_name_template"
	v := NewValues(kv)

	err := v.Set("sub_name_template", "{NAME}")
	if err == nil {
		t.Fatal("a failed write reported success")
	}
	if !strings.Contains(err.Error(), "sub_name_template") {
		t.Errorf("the error does not name the key: %v", err)
	}
}
