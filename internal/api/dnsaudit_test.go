package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The DNS routes were mounted with Deps.Audit nil, so NOT ONE DNS mutation was
// ever recorded. Adding a provider credential, repointing a domain, rotating an
// address — the changes most likely to break a deployment and most worth tracing
// afterwards — happened with no trail, while every other mutation in the panel
// was logged.

func TestDNSMutationsAreAudited(t *testing.T) {
	s, token := adminAPI(t)

	// Storing a provider credential is the mutation most worth tracing: it is
	// the key to somebody's DNS. Verification is a separate step, so this stores
	// without contacting Cloudflare.
	if code, b := doPOST(t, s, "/api/admin/dns/credentials", token,
		`{"provider":"cloudflare","label":"main","data":{"api_token":"tok-abcdef"}}`); code != 201 {
		t.Fatalf("storing a credential: %d %s", code, b)
	}

	code, body := doGET(t, s, "/api/admin/audit?limit=100", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var page struct {
		Items []store.AuditLog `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range page.Items {
		if strings.HasPrefix(e.Action, "dns.") {
			found = true
			// The DNS package supplies actions already prefixed with "dns.".
			// Prefixing again would produce "dns.dns.credential.create", which
			// breaks the action filter the audit view offers.
			if strings.HasPrefix(e.Action, "dns.dns.") {
				t.Errorf("action is double-prefixed: %q", e.Action)
			}
		}
	}
	if !found {
		t.Fatal("a DNS mutation produced no audit entry; the routes are mounted with a nil Audit hook")
	}
}

func TestDNSAuditDoesNotRecordTheSecret(t *testing.T) {
	s, token := adminAPI(t)
	const secret = "tok-do-not-log-me"
	if code, b := doPOST(t, s, "/api/admin/dns/credentials", token,
		`{"provider":"cloudflare","label":"main","data":{"api_token":"`+secret+`"}}`); code != 201 {
		t.Fatalf("%d: %s", code, b)
	}
	_, body := doGET(t, s, "/api/admin/audit?limit=100", token)
	// An audit trail that records the credential it is auditing turns the trail
	// into a second copy of every secret, in a table more people can read than
	// the encrypted store it was carefully put in.
	if strings.Contains(body, secret) {
		t.Fatal("the DNS credential appears verbatim in the audit trail")
	}
}

func TestDNSRoutesAreActuallyMounted(t *testing.T) {
	s, token := adminAPI(t)
	// Registration is best-effort, and when it silently did not happen the DNS
	// section of the UI 404'd and looked like a frontend bug.
	code, body := doGET(t, s, "/api/admin/dns/credentials", token)
	if code == 404 {
		t.Fatalf("the DNS routes are not mounted: %s", body)
	}
}
