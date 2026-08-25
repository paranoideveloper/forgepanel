package xrayapi

import (
	"encoding/json"
	"testing"
)

// The diff is where the danger is. Deciding "this is only a user change" when it
// is not leaves a running core silently disagreeing with its own config — a far
// worse outcome than the restart it was trying to avoid. Every test here that
// asserts `ok == false` is protecting against exactly that.

func cfg(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// base is a config in the shape BuildMulti emits.
func base(clients ...any) map[string]any {
	return map[string]any{
		"log":   map[string]any{"loglevel": "warning", "access": ""},
		"api":   map[string]any{"tag": "api", "services": []string{"HandlerService", "StatsService"}},
		"stats": map[string]any{},
		"inbounds": []any{
			map[string]any{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1"}},
			map[string]any{"tag": "in-1", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
				"settings":       map[string]any{"clients": clients, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp"}},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
}

func client(email, id string) any {
	return map[string]any{"id": id, "email": email}
}

func TestAddedUserIsADelta(t *testing.T) {
	old := cfg(t, base(client("u.1", "aaa")))
	next := cfg(t, base(client("u.1", "aaa"), client("u.2", "bbb")))

	deltas, ok, err := DiffUsersOnly(old, next)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v, want a hot-appliable user change", ok, err)
	}
	if len(deltas) != 1 || deltas[0].Tag != "in-1" {
		t.Fatalf("deltas = %+v, want one for in-1", deltas)
	}
	if len(deltas[0].Add) != 1 || len(deltas[0].Remove) != 0 {
		t.Fatalf("add=%d remove=%d, want 1 and 0", len(deltas[0].Add), len(deltas[0].Remove))
	}
}

func TestRemovedUserIsADelta(t *testing.T) {
	old := cfg(t, base(client("u.1", "aaa"), client("u.2", "bbb")))
	next := cfg(t, base(client("u.1", "aaa")))

	deltas, ok, _ := DiffUsersOnly(old, next)
	if !ok || len(deltas) != 1 {
		t.Fatalf("deltas=%+v ok=%v", deltas, ok)
	}
	if len(deltas[0].Remove) != 1 || deltas[0].Remove[0] != "u.2" {
		t.Fatalf("remove = %v, want [u.2]", deltas[0].Remove)
	}
}

func TestRotatedCredentialIsRemoveThenAdd(t *testing.T) {
	old := cfg(t, base(client("u.1", "old-uuid")))
	next := cfg(t, base(client("u.1", "new-uuid")))

	deltas, ok, _ := DiffUsersOnly(old, next)
	if !ok || len(deltas) != 1 {
		t.Fatalf("deltas=%+v ok=%v", deltas, ok)
	}
	d := deltas[0]
	// There is no "update user" call. Adding without removing would leave the
	// OLD credential working, which defeats the entire point of a rotation.
	if len(d.Remove) != 1 || d.Remove[0] != "u.1" {
		t.Fatalf("remove = %v, want [u.1] so the old UUID stops working", d.Remove)
	}
	if len(d.Add) != 1 {
		t.Fatalf("add = %d, want 1", len(d.Add))
	}
}

func TestNoChangeIsNoRestart(t *testing.T) {
	old := cfg(t, base(client("u.1", "aaa")))
	// Same content, different key order and whitespace — what happens when the
	// config is regenerated for an unrelated reason.
	next := []byte(`{
	  "outbounds": [{"protocol":"freedom","tag":"direct"}],
	  "stats": {},
	  "api": {"services":["HandlerService","StatsService"],"tag":"api"},
	  "log": {"access":"","loglevel":"warning"},
	  "inbounds": [
	    {"settings":{"address":"127.0.0.1"},"protocol":"dokodemo-door","port":10085,"listen":"127.0.0.1","tag":"api"},
	    {"streamSettings":{"network":"tcp"},"settings":{"decryption":"none","clients":[{"email":"u.1","id":"aaa"}]},"protocol":"vless","port":443,"listen":"0.0.0.0","tag":"in-1"}
	  ]
	}`)

	deltas, ok, err := DiffUsersOnly(old, next)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("re-serialised identical config was treated as a restart-worthy change")
	}
	// Comparing bytes rather than values would report a difference here and
	// drop every connection on the box for no change at all.
	if len(deltas) != 0 {
		t.Fatalf("deltas = %+v, want none", deltas)
	}
}

func TestNonUserChangesRefuseTheHotPath(t *testing.T) {
	old := cfg(t, base(client("u.1", "aaa")))

	cases := map[string]func(m map[string]any){
		"port": func(m map[string]any) {
			m["inbounds"].([]any)[1].(map[string]any)["port"] = 8443
		},
		"transport": func(m map[string]any) {
			m["inbounds"].([]any)[1].(map[string]any)["streamSettings"] = map[string]any{"network": "ws"}
		},
		"listen address": func(m map[string]any) {
			m["inbounds"].([]any)[1].(map[string]any)["listen"] = "127.0.0.1"
		},
		"protocol": func(m map[string]any) {
			m["inbounds"].([]any)[1].(map[string]any)["protocol"] = "vmess"
		},
		"a sibling of clients inside settings": func(m map[string]any) {
			in := m["inbounds"].([]any)[1].(map[string]any)
			in["settings"].(map[string]any)["decryption"] = "xyz"
		},
		"routing": func(m map[string]any) {
			m["routing"] = map[string]any{"rules": []any{}}
		},
		"outbounds": func(m map[string]any) {
			m["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "blackhole"}}
		},
		"log level": func(m map[string]any) {
			m["log"].(map[string]any)["loglevel"] = "debug"
		},
		"a new inbound": func(m map[string]any) {
			m["inbounds"] = append(m["inbounds"].([]any), map[string]any{
				"tag": "in-2", "listen": "0.0.0.0", "port": 8080, "protocol": "vless",
				"settings": map[string]any{"clients": []any{}, "decryption": "none"}})
		},
		"a removed inbound": func(m map[string]any) {
			m["inbounds"] = m["inbounds"].([]any)[:1]
		},
		"a renamed inbound": func(m map[string]any) {
			m["inbounds"].([]any)[1].(map[string]any)["tag"] = "in-renamed"
		},
	}

	for name, mutate := range cases {
		m := base(client("u.1", "aaa"))
		mutate(m)
		_, ok, _ := DiffUsersOnly(old, cfg(t, m))
		if ok {
			t.Errorf("%s was accepted as a user-only change; it needs a restart to take effect, "+
				"and hot-applying would leave the core disagreeing with its own config", name)
		}
	}
}

func TestInboundsWithoutKeyedClientsRefuseTheHotPath(t *testing.T) {
	// A user with no email cannot be REMOVED — `rmu` addresses users by email —
	// so an inbound carrying one is not hot-appliable in either direction.
	old := cfg(t, base(map[string]any{"id": "aaa"}))
	next := cfg(t, base(map[string]any{"id": "aaa"}, map[string]any{"id": "bbb"}))
	if _, ok, _ := DiffUsersOnly(old, next); ok {
		t.Error("an inbound with an email-less client was accepted; its users cannot be removed by the handler API")
	}

	// Duplicate emails make "which user" ambiguous, so any CHANGE to such an
	// inbound must be refused — a removal would hit whichever entry the core
	// happened to index first.
	//
	// An UNCHANGED one is a different matter: no add and no removal is issued, so
	// there is nothing for the ambiguity to affect. Asserting a refusal there
	// would be demanding a restart for a config that did not change.
	dup := cfg(t, base(client("u.1", "aaa"), client("u.1", "bbb")))
	dupChanged := cfg(t, base(client("u.1", "aaa"), client("u.1", "bbb"), client("u.2", "ccc")))
	if _, ok, _ := DiffUsersOnly(dup, dupChanged); ok {
		t.Error("a change to an inbound with duplicate client emails was accepted; a removal would be ambiguous")
	}
	if _, ok, _ := DiffUsersOnly(dup, dup); !ok {
		t.Error("an unchanged inbound was refused; nothing is applied, so there is nothing to be ambiguous about")
	}
}

func TestMalformedConfigsFallBackRatherThanError(t *testing.T) {
	good := cfg(t, base(client("u.1", "aaa")))
	for _, bad := range [][]byte{[]byte("{"), []byte("null"), []byte(`{"inbounds": 3}`), {}} {
		// The caller treats an error the same as "not hot-appliable", but it must
		// never panic or report success.
		_, ok, _ := DiffUsersOnly(bad, good)
		if ok {
			t.Errorf("unparseable old config %q was accepted as hot-appliable", bad)
		}
		_, ok, _ = DiffUsersOnly(good, bad)
		if ok {
			t.Errorf("unparseable new config %q was accepted as hot-appliable", bad)
		}
	}
}

func TestParseCountReadsTheCLIsOwnReport(t *testing.T) {
	// `xray api adu` exits ZERO and prints "Added 0 user(s) in total." when the
	// document shape is wrong. Trusting the exit status alone would report a
	// success for a change that never happened, and the panel would then believe
	// a user exists that the core has never heard of.
	if got := parseCount(addedRe, "processing inbound: in-1\nadd user: u.2\nresult: ok\nAdded 1 user(s) in total.\n"); got != 1 {
		t.Errorf("added count = %d, want 1", got)
	}
	if got := parseCount(addedRe, "Added 0 user(s) in total.\n"); got != 0 {
		t.Errorf("zero-add count = %d, want 0", got)
	}
	if got := parseCount(removedRe, "remove user: u.2\nRemoved 1 user(s) in total.\n"); got != 1 {
		t.Errorf("removed count = %d, want 1", got)
	}
	// No count line at all: the CLI did something other than what was asked.
	if got := parseCount(addedRe, "some other output"); got != -1 {
		t.Errorf("missing count = %d, want -1 so the caller reports a mismatch", got)
	}
}

func TestSanitizeTagCannotEscapeTheDirectory(t *testing.T) {
	// The tag comes from an inbound remark, which an operator types. It becomes
	// part of a file name.
	for _, tag := range []string{"../../etc/passwd", "a/b", "..", "", "x\x00y"} {
		got := sanitizeTag(tag)
		for _, bad := range []string{"/", "..", "\x00"} {
			if bad == ".." && got == ".." {
				t.Errorf("sanitizeTag(%q) = %q", tag, got)
			}
			if bad != ".." && contains(got, bad) {
				t.Errorf("sanitizeTag(%q) = %q, still contains %q", tag, got, bad)
			}
		}
		if got == "" {
			t.Errorf("sanitizeTag(%q) produced an empty name", tag)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
