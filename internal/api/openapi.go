package api

// The panel describes its own API.
//
// docs/API.md is hand-written, covers roughly a quarter of the ~200 routes, is
// not embedded in the binary and is imported by nothing, so it drifts from the
// first endpoint anyone adds. /api/protocols/schema, /api/capabilities and
// /api/admin/settings/registry each describe an object the panel handles —
// none of them says what the endpoint surface IS, so an operator wiring a
// script, or anyone generating a client, had to read routes() by hand.
//
// This is generated from the live router at request time rather than from a
// checked-in artifact, which is the whole point: a route added tomorrow appears
// in the document without anyone remembering to update it, and a route that was
// deleted stops being advertised.
//
// What it deliberately does NOT contain: request bodies, 2xx response schemas,
// tags and examples. Handlers bind heterogeneous anonymous structs and gin.H,
// there is no struct-tag schema generator here, and ~200 hand-written body
// schemas would be stale before they shipped. An operation with no requestBody
// is a gap a reader can see; one with `requestBody: {}` is a lie tooling acts on.

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/version"
)

// handleOpenAPI serves the machine-readable description of this API.
//
// It is mounted on the admin group, not the public one, because the document
// includes x-forgepanel-roles: the panel's own authorization map, a precise
// list of which paths each role cannot reach. That is reconnaissance material,
// so it sits at the same bar as the other credential-bearing reads.
func (s *Server) handleOpenAPI(c *gin.Context) {
	c.JSON(http.StatusOK, s.openapiDoc())
}

// openapiDoc builds an OpenAPI 3.1 document from the routes gin is actually
// serving right now.
//
// Reading the table at call time is load-bearing. routes() registers top to
// bottom, so anything computed while registering would capture only the routes
// above it and silently omit the settings, geoip, panel-address, edge-feed and
// node-agent blocks that come later.
func (s *Server) openapiDoc() map[string]any {
	all := s.router.Routes()
	kept := make([]gin.RouteInfo, 0, len(all))
	for _, r := range all {
		// Everything else the router serves is the panel UI, the embedded assets,
		// the subscription links and the health probe — pages and files, not an
		// API surface a client would be generated against.
		if !strings.HasPrefix(r.Path, "/api/") {
			continue
		}
		// A gin catch-all has no OpenAPI spelling: "{rest}" matches exactly one
		// segment, so publishing it would give every generator a path that cannot
		// reach the route. There is no such route under /api/ today; if one is
		// added, an honest absence beats an invented path.
		if strings.Contains(r.Path, "/*") {
			continue
		}
		kept = append(kept, r)
	}
	// Sorted before ids are assigned so the collision suffixes below land on the
	// same operations every run: the document has to be byte-stable, or every
	// regeneration shows up as a diff in whatever consumes it.
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Path != kept[j].Path {
			return kept[i].Path < kept[j].Path
		}
		return kept[i].Method < kept[j].Method
	})

	paths := make(map[string]any, len(kept))
	usedIDs := make(map[string]bool, len(kept))
	for _, r := range kept {
		p, params := openapiPath(r.Path)
		item, ok := paths[p].(map[string]any)
		if !ok {
			item = map[string]any{}
			paths[p] = item
		}
		op := map[string]any{
			"operationId": uniqueOperationID(usedIDs, operationIDFor(r)),
			"security":    openapiSecurity(r.Path),
			"responses": map[string]any{
				"default": map[string]any{
					"description": "Refused request. Every refusal this panel writes uses this envelope.",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"$ref": "#/components/schemas/Error"},
						},
					},
				},
			},
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		// Resolved from the ORIGINAL gin path: the rules table is written in gin
		// syntax ("/api/admin/users/:id"), so asking with the converted "{id}"
		// form would miss every exact rule and quietly report the catch-all's
		// roles for all of them — a wrong privilege map, worse than none.
		// Copied because the resolver hands back the live policy slice.
		if roles := rolesForRoute(r.Method, r.Path); len(roles) > 0 {
			op["x-forgepanel-roles"] = append([]string(nil), roles...)
		}
		item[strings.ToLower(r.Method)] = op
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title": "ForgePanel API",
			// .Version, the string field — version.Get() is a struct, and an
			// object here fails validation in every consumer.
			"version": version.Get().Version,
			"description": "Generated from this panel's live route table. Request bodies and " +
				"success response schemas are not described; error responses are.",
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
			"schemas": map[string]any{"Error": openapiErrorSchema()},
		},
	}
}

// openapiSecurity names the scheme a route actually reads.
//
// The admin group takes a session JWT or an API token in the Authorization
// header, and the edge pull feed compares its own bearer token there. The node
// agent endpoints DO require a credential, but they carry it in the request
// body (or in a client certificate), so claiming bearerAuth for them would make
// a generated client send a header nobody reads while omitting the token the
// route needs. An empty requirement list is the honest answer for those.
func openapiSecurity(path string) []any {
	if strings.HasPrefix(path, "/api/admin") || path == "/api/edge/feed" {
		return []any{map[string]any{"bearerAuth": []any{}}}
	}
	return []any{}
}

// openapiErrorSchema mirrors internal/apierr.Error.Body(), the one envelope
// every refusal in this package is written through.
//
// additionalProperties stays true because apierr merges Details at the TOP
// level of the body rather than nesting them, so endpoints legitimately add
// keys (totp_required, members, limit) this schema does not name.
func openapiErrorSchema() map[string]any {
	str := map[string]any{"type": "string"}
	return map[string]any{
		"type":     "object",
		"required": []any{"error"},
		"properties": map[string]any{
			"error":         map[string]any{"type": "string", "description": "The sentence to show a human."},
			"kind":          map[string]any{"type": "string", "description": "Machine-readable class of failure, e.g. validation, auth, not_found."},
			"op":            str,
			"code":          map[string]any{"type": "string", "description": "Specific reason a client may switch on, e.g. port_hop_conflict."},
			"remediation":   str,
			"missing_scope": str,
			"fields": map[string]any{
				"type":                 "object",
				"description":          "Per-input messages, keyed by field name.",
				"additionalProperties": str,
			},
		},
		"additionalProperties": true,
	}
}

// openapiPath converts a gin route pattern to an OpenAPI template and returns
// the path parameters it names.
func openapiPath(ginPath string) (string, []any) {
	segs := strings.Split(ginPath, "/")
	var params []any
	for i, seg := range segs {
		if !strings.HasPrefix(seg, ":") {
			continue
		}
		name := seg[1:]
		segs[i] = "{" + name + "}"
		params = append(params, map[string]any{
			"in":       "path",
			"name":     name,
			"required": true,
			"schema":   map[string]any{"type": "string"},
		})
	}
	return strings.Join(segs, "/"), params
}

// operationIDFor names an operation after its handler where that name means
// something, and after the route otherwise.
func operationIDFor(r gin.RouteInfo) string {
	// gin reports the full symbol of the LAST handler in the chain, e.g.
	// "github.com/forgepanel/forgepanel/internal/api.(*Server).handleMe-fm".
	name := r.Handler
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "-fm")
	if !namedHandler(name) {
		return synthOperationID(r.Method, r.Path)
	}
	return name
}

// namedHandler reports whether a trimmed symbol is a name worth publishing.
// A route registered with an inline closure (/api/version) trims to "func1", or
// to a bare "1" when the closure is nested — meaningless to a client generator,
// and liable to renumber when an unrelated line of routes() changes.
func namedHandler(name string) bool {
	if name == "" {
		return false
	}
	if c := rune(name[0]); !unicode.IsLetter(c) && c != '_' {
		return false
	}
	rest, ok := strings.CutPrefix(name, "func")
	if !ok || rest == "" {
		return true
	}
	for _, c := range rest {
		if !unicode.IsDigit(c) {
			return true
		}
	}
	return false
}

// synthOperationID builds an id from the verb and the path, e.g.
// GET /api/version -> "getApiVersion".
func synthOperationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, seg := range strings.Split(path, "/") {
		for _, word := range strings.FieldsFunc(seg, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			runes := []rune(word)
			b.WriteString(strings.ToUpper(string(runes[0])))
			b.WriteString(string(runes[1:]))
		}
	}
	return b.String()
}

// uniqueOperationID keeps operationId unique, which OpenAPI requires and this
// router genuinely violates: handleSaveProfile, handleSaveOutbound and
// handleEdgePush are each mounted on two routes. openapi-generator rejects a
// duplicate outright and other tools silently mangle one of the pair.
func uniqueOperationID(used map[string]bool, id string) string {
	if !used[id] {
		used[id] = true
		return id
	}
	for n := 2; ; n++ {
		cand := id + strconv.Itoa(n)
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}
