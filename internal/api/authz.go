package api

// Authorization for the admin API.
//
// The panel has always had a complete RBAC *design* — four roles in the
// database (owner/admin/reseller/viewer), a Role claim inside every JWT, and a
// correct auth.RequireRole middleware — but none of it was ever mounted. Every
// /api/admin route sat behind authentication only, so any authenticated token,
// including a viewer's, could drive owner-level endpoints: create inbounds,
// delete nodes, deploy edges, read private keys. Data scoping in a couple of
// handlers limited which rows a reseller *saw*; nothing limited what they could
// *do*. This file closes that hole.
//
// Design choice: one policy table plus one middleware on the group, rather than
// a RequireRole call appended to each of ~118 route registrations. Per-route
// middleware fails open — the day someone adds a route and forgets the guard,
// it ships unprotected and nothing complains. Here the default is DENY, and
// TestAuthzEveryAdminRouteHasAPolicy walks the live router asserting that every
// admin route resolves to an explicit rule, so a new unguarded route fails the
// build instead of shipping.

import (
	"net/http"
	"strings"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/gin-gonic/gin"
)

// Role sets. Ordered most- to least-privileged for readability only; membership
// is what matters.
var (
	roleOwner    = string(store.RoleOwner)
	roleAdmin    = string(store.RoleAdmin)
	roleReseller = string(store.RoleReseller)
	roleViewer   = string(store.RoleViewer)

	// everyone is every authenticated principal — used for self-service routes
	// (who am I, change my own password, manage my own 2FA). Denying a viewer
	// the ability to rotate their own credentials would be its own security
	// problem, not a hardening win.
	everyone = []string{roleOwner, roleAdmin, roleReseller, roleViewer}

	// ownerAdmin is the default for infrastructure: inbounds, engines, nodes,
	// DNS, edge deployments, domains.
	ownerAdmin = []string{roleOwner, roleAdmin}

	// ownerOnly is reserved for actions that reconfigure the panel itself or
	// expose panel-wide TLS material. An admin managing proxy users has no
	// business moving the panel's own address or importing its certificate.
	ownerOnly = []string{roleOwner}

	// tenantMgmt is customer management: a reseller's actual job. Handlers
	// already scope resellers to their own rows (see handleListUsers), so this
	// grants the verb; the handler still constrains the blast radius.
	tenantMgmt = []string{roleOwner, roleAdmin, roleReseller}

	// readDash is what a viewer may look at: dashboards and inventory listings
	// that carry no credentials. Anything that returns a key, token, private
	// config or client bundle is deliberately absent.
	readDash = []string{roleOwner, roleAdmin, roleReseller, roleViewer}
)

// authzRule maps a route to the roles permitted to call it. Rules are evaluated
// in order and the FIRST match wins, so specific rules must precede general
// ones — which is why the sensitive-read rules sit above the section defaults.
type authzRule struct {
	// methods limits the rule to those HTTP verbs; empty means any verb.
	methods []string
	// path is matched against gin's route pattern (c.FullPath()), e.g.
	// "/api/admin/users/:id". exact selects equality, otherwise it is a prefix.
	path  string
	exact bool
	roles []string
}

func (r authzRule) matches(method, path string) bool {
	if len(r.methods) > 0 {
		ok := false
		for _, m := range r.methods {
			if m == method {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if r.exact {
		return path == r.path
	}
	return strings.HasPrefix(path, r.path)
}

var get = []string{http.MethodGet, http.MethodHead}

// adminAuthzRules is the whole policy, top to bottom.
//
// Read it as: self-service first, then the credential-bearing reads that must
// never reach a viewer, then per-section defaults, then a catch-all DENY-ish
// default of owner+admin for anything unclassified.
var adminAuthzRules = []authzRule{
	// --- self-service: your own identity and your own credentials ----------
	{path: "/api/admin/me", exact: true, roles: everyone},
	{path: "/api/admin/2fa", roles: everyone},
	{path: "/api/admin/change-password", roles: everyone},

	// --- panel-level configuration: owner only ----------------------------
	// These move the panel's own address, its TLS material, or global settings.
	{path: "/api/admin/panel-address", roles: ownerOnly},
	{path: "/api/admin/certs", roles: ownerOnly},
	{path: "/api/admin/settings", roles: ownerOnly},
	// Staging fetches and EXECUTES a panel binary on this host. Without a rule
	// here the catch-all below still resolves it, so nothing looks unclassified
	// while a plain admin quietly gains that.
	{path: "/api/admin/update", roles: ownerOnly},

	// --- credential-bearing reads: never a viewer, never a reseller -------
	// Each of these returns key material, a token, or a ready-to-use client
	// bundle. A "read-only" role that can read private keys is not read-only.
	{methods: get, path: "/api/admin/inbounds/:id/config", exact: true, roles: ownerAdmin},
	{methods: get, path: "/api/admin/engines/config", exact: true, roles: ownerAdmin},
	{methods: get, path: "/api/admin/forgedns/zones/:id/bundle", exact: true, roles: ownerAdmin},
	{methods: get, path: "/api/admin/forgedns/zones/:id/client", exact: true, roles: ownerAdmin},
	{methods: get, path: "/api/admin/forgedns/zones/:id/config", exact: true, roles: ownerAdmin},
	{path: "/api/admin/edge/feed-token", roles: ownerAdmin},
	{path: "/api/admin/dns/credentials", roles: ownerAdmin},
	// The endpoint inventory plus x-forgepanel-roles is the panel's own
	// authorization map — a precise list of what each role may reach, and by
	// omission what it may not. That is reconnaissance, not a dashboard, so it
	// does not go to a viewer or a reseller the way /api/admin/metrics does.
	{methods: get, path: "/api/admin/openapi.json", exact: true, roles: ownerAdmin},

	// --- backup: owner only -------------------------------------------------
	//
	// A backup carries the database, secrets.json (the master key and the token
	// signing secret) and the issued certificates. Anyone who can download one
	// can stand up a panel indistinguishable from this one, so it sits at the
	// same bar as importing a certificate or moving the panel address.
	{path: "/api/admin/backup", roles: ownerOnly},

	// --- usage history ------------------------------------------------------
	//
	// A reseller may chart their own customers, and the handler scopes each
	// request to what they own; node and inbound totals aggregate across
	// tenants and are refused there.
	{methods: get, path: "/api/admin/traffic", roles: tenantMgmt},

	// --- who is connected right now ---------------------------------------
	//
	// "Is my customer actually connected, and from where" is the support
	// question a reseller asks most, so this is tenant management like the rest
	// of their job — but the handler scopes it to the users they own, and
	// sessions it cannot attribute to any user are withheld from them entirely.
	// A source address is the most sensitive field the panel holds: it locates
	// a person. One tenant learning another's is a privacy breach, not a
	// cosmetic leak.
	{methods: get, path: "/api/admin/online", exact: true, roles: tenantMgmt},

	// --- foreign-panel import ---------------------------------------------
	//
	// Reads an arbitrary path on the host and writes inbounds and users across
	// the whole panel. Owner only.
	{path: "/api/admin/migrate", roles: ownerOnly},

	// --- config profiles --------------------------------------------------
	//
	// A profile writes inbounds across the whole fleet, which is infrastructure
	// rather than tenant management.
	{path: "/api/admin/profiles", roles: ownerAdmin},

	// --- metrics ----------------------------------------------------------
	//
	// readDash: a scraper needs no more than a viewer, and the observability
	// token scope maps to exactly that. The numbers still name every node and
	// count every user, which is why this is not public.
	{methods: get, path: "/api/admin/metrics", exact: true, roles: readDash},

	// --- API tokens -------------------------------------------------------
	//
	// A reseller automating their own customer management is the ordinary case,
	// and a token can never exceed the authority of the account that minted it,
	// so this does not widen anyone's reach. Listing is scoped in the handler:
	// enumerating another tenant's credentials would reveal what integrations
	// they run and when each was last used.
	{path: "/api/admin/tokens", roles: tenantMgmt},

	// --- routing ----------------------------------------------------------
	//
	// A routing rule can send any user's traffic anywhere, or stop it entirely,
	// and it applies across every tenant on the panel — so it is not a
	// reseller's to write. It also decides whether traffic leaves a relay chain,
	// which makes a bad rule a deanonymisation rather than a misconfiguration.
	{path: "/api/admin/routing", roles: ownerAdmin},

	// --- the audit trail --------------------------------------------------
	//
	// Entries name the actor, their IP and what they did, across every admin.
	// That is precisely what one reseller must not learn about another tenant,
	// and what a viewer has no business with at all.
	{methods: get, path: "/api/admin/audit", roles: ownerAdmin},

	// --- admin provisioning: owner only -----------------------------------
	//
	// A reseller able to mint another reseller, or to raise its own quota, is a
	// privilege escalation that looks identical to legitimate use in the audit
	// log. These routes create, re-role, disable and delete accounts, so they
	// belong to the one role that already has full authority.
	{path: "/api/admin/admins", roles: ownerOnly},

	// --- customer management: the reseller's job --------------------------
	{path: "/api/admin/users", roles: tenantMgmt},
	// Saved plans are customer management, but matches() ends in a bare
	// HasPrefix with no segment boundary — "/api/admin/user-templates" is not
	// prefixed by "/api/admin/users", so without this line it falls through to
	// the owner-only catch-all and 403s the one role that wanted plans. The
	// policy test only asserts a rule matched, so nothing would have said so.
	// The path must stay this exact string: "/api/admin/user" would swallow
	// "/api/admin/users" by the same rule and silently re-scope customers.
	{path: "/api/admin/user-templates", roles: tenantMgmt},
	{path: "/api/admin/groups", roles: tenantMgmt},
	{methods: get, path: "/api/admin/quota", exact: true, roles: tenantMgmt},

	// --- dashboards and inventory: safe for a viewer to read --------------
	{methods: get, path: "/api/admin/overview", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/stats", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/health/detail", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/doctor", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/geoip", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/inbounds", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/nodes", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/engines", exact: true, roles: readDash},
	{methods: get, path: "/api/admin/domains-status", exact: true, roles: readDash},

	// --- infrastructure: owner + admin ------------------------------------
	// Everything below mutates or inspects the serving plane.
	{path: "/api/admin/inbounds", roles: ownerAdmin},
	{path: "/api/admin/engines", roles: ownerAdmin},
	{path: "/api/admin/nodes", roles: ownerAdmin},
	{path: "/api/admin/domains", roles: ownerAdmin},
	{path: "/api/admin/forgedns", roles: ownerAdmin},
	{path: "/api/admin/dns", roles: ownerAdmin},
	{path: "/api/admin/edge", roles: ownerAdmin},
	{path: "/api/admin/wizard", roles: ownerAdmin},
	{path: "/api/admin/deploy", roles: ownerAdmin},
	{path: "/api/admin/capabilities", roles: readDash},

	// --- catch-all: fail closed -------------------------------------------
	// An unclassified admin route is treated as infrastructure. It is never
	// silently public, and the policy test flags it so it gets classified
	// deliberately rather than inheriting this by accident.
	{path: "/api/admin", roles: ownerAdmin},
}

// rolesForRoute resolves the permitted roles for a route, or nil when no rule
// matches at all (which the middleware treats as deny).
func rolesForRoute(method, fullPath string) []string {
	for _, r := range adminAuthzRules {
		if r.matches(method, fullPath) {
			return r.roles
		}
	}
	return nil
}

// authz enforces adminAuthzRules. It runs after the JWT middleware, so claims
// are present; a request that reaches here without claims is a bug in the chain
// and is denied rather than trusted.
func (s *Server) authz() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := auth.ClaimsFrom(c)
		if !ok || claims == nil {
			abortFail(c, http.StatusUnauthorized, "not authenticated")
			return
		}
		// FullPath is the registered pattern ("/api/admin/users/:id"). It is
		// empty for a 404, where there is nothing to authorise.
		path := c.FullPath()
		if path == "" {
			c.Next()
			return
		}
		allowed := rolesForRoute(c.Request.Method, path)
		if len(allowed) == 0 {
			abortFail(c, http.StatusForbidden,
				"this endpoint has no authorisation policy and is therefore denied")
			return
		}
		for _, r := range allowed {
			if claims.Role == r {
				c.Next()
				return
			}
		}
		// Say what was needed. A 403 that does not explain which role is
		// required just produces a support ticket.
		abortFailWith(c, &apierr.Error{Op: "authorize", Kind: apierr.KindPermission,
			Message: "insufficient role",
			Details: map[string]any{"your_role": claims.Role, "required_roles": allowed}})
	}
}
