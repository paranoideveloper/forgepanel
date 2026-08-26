package api

// Cross-language guard: the navigation the panel OFFERS must match the policy
// the API ENFORCES.
//
// Both POST /login and GET /admin/me have always returned the caller's role and
// the frontend read neither, so all sixteen tabs rendered for every principal.
// A reseller saw Certificates, Admins, the Audit trail, Nodes, Routing and
// ForgeDNS, clicked one, and got a 403 from a route the panel already knew they
// could not use.
//
// Filtering the navigation creates a second copy of the policy, and a second
// copy is a thing that drifts: a route re-scoped here goes on being offered
// there, or a new tab is hidden from a role that is entitled to it. This reads
// the frontend's TAB_ROLES table and checks every entry against rolesForRoute,
// in both directions.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// tabRoutes maps a navigation tab to the API route its page is USELESS without.
//
// Not every route a page touches — the narrowest one, because that is what
// decides whether the tab leads anywhere. The Users view reads /admin/inbounds
// to render an assignment picker, but a reseller who cannot read inbounds still
// has a working Users page; a reseller who cannot reach /admin/users does not.
var tabRoutes = map[string]struct {
	method string
	path   string
}{
	"overview": {"GET", "/api/admin/overview"},
	"usage":    {"GET", "/api/admin/traffic"},
	"online":   {"GET", "/api/admin/online"},
	"users":    {"POST", "/api/admin/users"},
	"inbounds": {"POST", "/api/admin/inbounds"},
	"routing":  {"POST", "/api/admin/routing"},
	"nodes":    {"POST", "/api/admin/nodes"},
	"domains":  {"POST", "/api/admin/domains"},
	"forgedns": {"POST", "/api/admin/forgedns"},
	"edge":     {"POST", "/api/admin/edge"},
	"studio":   {"POST", "/api/admin/inbounds"},
	"wizard":   {"POST", "/api/admin/wizard"},
	"audit":    {"GET", "/api/admin/audit"},
	"admins":   {"POST", "/api/admin/admins"},
	"certs":    {"POST", "/api/admin/panel-address"},
	"system":   {"POST", "/api/admin/backup"},
}

// tabRolesFromFrontend parses the TAB_ROLES table out of session.svelte.ts.
func tabRolesFromFrontend(t *testing.T) map[string][]string {
	t.Helper()
	src, err := os.ReadFile(filepath.FromSlash("../../frontend/src/lib/session.svelte.ts"))
	if err != nil {
		t.Skipf("frontend source not available: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "export const TAB_ROLES")
	if start < 0 {
		t.Fatal("TAB_ROLES not found — the scan is broken, not the table")
	}
	end := strings.Index(body[start:], "};")
	if end < 0 {
		t.Fatal("TAB_ROLES is not terminated")
	}
	block := body[start : start+end]

	entry := regexp.MustCompile(`(?m)^\s*(\w+):\s*\[([^\]]*)\]`)
	out := map[string][]string{}
	for _, m := range entry.FindAllStringSubmatch(block, -1) {
		var roles []string
		for _, r := range strings.Split(m[2], ",") {
			r = strings.TrimSpace(strings.Trim(strings.TrimSpace(r), "'\""))
			if r != "" {
				roles = append(roles, r)
			}
		}
		sort.Strings(roles)
		out[m[1]] = roles
	}
	return out
}

func TestNavigationMatchesTheAuthzPolicy(t *testing.T) {
	tabs := tabRolesFromFrontend(t)
	if len(tabs) < 10 {
		t.Fatalf("only %d tabs parsed — the scan is broken, not the table", len(tabs))
	}

	for tab, offered := range tabs {
		route, ok := tabRoutes[tab]
		if !ok {
			t.Errorf("tab %q has no route in tabRoutes, so nothing checks what it offers against what the API allows", tab)
			continue
		}
		allowed := rolesForRoute(route.method, route.path)
		if allowed == nil {
			t.Errorf("tab %q maps to %s %s, which matches no authz rule", tab, route.method, route.path)
			continue
		}
		want := append([]string(nil), allowed...)
		sort.Strings(want)

		// Offering MORE than the API allows is the defect this whole change is
		// about: a tab that leads to a 403.
		for _, r := range offered {
			if !contains(want, r) {
				t.Errorf("tab %q is offered to %q, but %s %s allows only %v — that click is a 403",
					tab, r, route.method, route.path, want)
			}
		}
		// Offering LESS is the other way to get it wrong: a control hidden from
		// someone entitled to use it, which reads as a broken panel.
		for _, r := range want {
			if !contains(offered, r) {
				t.Errorf("tab %q is hidden from %q, but %s %s allows it",
					tab, r, route.method, route.path)
			}
		}
	}

	// And every tab the sidebar renders must be in the table, or it is offered
	// to everyone by the fall-through and nothing here notices.
	for _, tab := range sidebarTabs(t) {
		if _, ok := tabs[tab]; !ok {
			t.Errorf("the sidebar renders tab %q, which TAB_ROLES does not classify", tab)
		}
	}
}

// sidebarTabs reads the tab ids the navigation actually renders.
func sidebarTabs(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.FromSlash("../../frontend/src/lib/components/Sidebar.svelte"))
	if err != nil {
		t.Skipf("frontend source not available: %v", err)
	}
	re := regexp.MustCompile(`\{\s*id:\s*'([a-z]+)',\s*labelKey:`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("no tabs found in the sidebar — the scan is broken")
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
