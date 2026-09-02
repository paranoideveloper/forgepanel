package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/cdncheck"
)

// The preflight exists so a failing setup is ONE round of fixes rather than one
// per attempt. What matters is that it writes nothing, that it answers every
// question it can, and that each failure carries the fix.

func preflight(t *testing.T, s *Server, token, body string) (int, map[string]any) {
	t.Helper()
	code, raw := doPOST(t, s, "/api/admin/wizard/preset/preflight", token, body)
	var out map[string]any
	if code == 200 {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("bad JSON: %v: %s", err, raw)
		}
	}
	return code, out
}

func checkNamed(res map[string]any, name string) map[string]any {
	list, _ := res["checks"].([]any)
	for _, c := range list {
		m, _ := c.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func TestPreflightWithNoDomainStillReportsWhatWillBeBuilt(t *testing.T) {
	s, token := adminAPI(t)
	code, res := preflight(t, s, token, `{}`)
	if code != 200 {
		t.Fatalf("preflight: %d", code)
	}
	d := checkNamed(res, "domain")
	if d == nil {
		t.Fatal("no domain check")
	}
	if d["ok"] == true {
		t.Error("an absent domain was reported as fine")
	}
	// Not fatal: the direct inbounds still work without one, and refusing
	// outright would block a legitimate domain-free install.
	if d["fatal"] == true {
		t.Error("a missing domain should reduce what is built, not block it")
	}
	if !strings.Contains(d["fix"].(string), "REALITY") {
		t.Errorf("the fix should say what you still get: %v", d["fix"])
	}
}

func TestPreflightSaysWhenNoTokenWasGiven(t *testing.T) {
	s, token := adminAPI(t)
	_, res := preflight(t, s, token, `{"domain":"example.com"}`)
	c := checkNamed(res, "Cloudflare token")
	if c == nil {
		t.Fatal("no token check")
	}
	if c["ok"] == true {
		t.Error("a missing token was reported as fine")
	}
	if !strings.Contains(strings.ToLower(c["fix"].(string)), "dns") {
		t.Errorf("the fix should name the permission needed: %v", c["fix"])
	}
}

// A bad token must be caught HERE, before anything is created — that is the
// whole point of the endpoint.
func TestPreflightRejectsATokenCloudflareDoesNotAccept(t *testing.T) {
	s, token := adminAPI(t)
	_, res := preflight(t, s, token,
		`{"domain":"example.com","cf_token":"definitely-not-a-real-token"}`)
	c := checkNamed(res, "Cloudflare token")
	if c == nil {
		t.Fatal("no token check")
	}
	if c["ok"] == true {
		t.Error("an invalid token was accepted")
	}
	if res["ready"] == true {
		t.Error("preflight reported ready with an unusable token")
	}
	if res["blocking"] == nil || res["blocking"].(float64) < 1 {
		t.Errorf("an unusable token must be blocking, got %v", res["blocking"])
	}
}

// Nothing may be written. The endpoint's value is that an operator can run it
// repeatedly while fixing things.
func TestPreflightCreatesNothing(t *testing.T) {
	s, token := adminAPI(t)
	before, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if code, _ := preflight(t, s, token, `{"domain":"example.com","cf_token":"nope"}`); code != 200 {
			t.Fatalf("preflight %d: %d", i, code)
		}
	}
	after, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("preflight created %d inbounds; it must only read", len(after)-len(before))
	}
}

func TestEveryFailedCheckCarriesAFix(t *testing.T) {
	s, token := adminAPI(t)
	for _, body := range []string{
		`{}`,
		`{"domain":"example.com"}`,
		`{"domain":"example.com","cf_token":"bad"}`,
	} {
		_, res := preflight(t, s, token, body)
		list, _ := res["checks"].([]any)
		if len(list) == 0 {
			t.Fatalf("no checks for %s", body)
		}
		for _, c := range list {
			m, _ := c.(map[string]any)
			if m["ok"] == true {
				continue
			}
			if fix, _ := m["fix"].(string); strings.TrimSpace(fix) == "" {
				t.Errorf("%s: check %q failed with no fix", body, m["name"])
			}
		}
	}
}

// The ports the preset actually uses must be ports Cloudflare proxies. This is
// the guard that would have caught the whole "CDN configs do not work" class if
// a plan ever moved to a port outside the set.
func TestThePresetsCDNPortsAreOnesCloudflareProxies(t *testing.T) {
	ports := wizardCDNPorts()
	if len(ports) == 0 {
		t.Fatal("the preset defines no CDN inbounds")
	}
	for _, p := range ports {
		if !cdncheck.PortIsProxied(p) {
			t.Errorf("the preset puts a CDN inbound on %d, which Cloudflare does not proxy for HTTPS — "+
				"the record would look correct and carry nothing", p)
		}
	}
}
