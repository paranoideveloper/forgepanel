package api

// Reachability guard: every HTTP handler this package defines must be mounted on
// the real router.
//
// This exists because "written, tested, and never mounted" has happened three
// separate times in this codebase, and each time every test passed:
//
//	RBAC          internal/api/authz.go carried a complete, ordered, fail-closed
//	              policy with its own test suite. It was never attached to the
//	              admin group, so a viewer could drive owner-only endpoints. The
//	              policy tests passed — they called the policy directly.
//	port checks   portCollisionGuard and registerPortRoutes were mounted only
//	              inside portcheck_test.go's own router. Production accepted two
//	              inbounds on one port, which makes the engine reject the whole
//	              generated document and takes EVERY inbound offline.
//	adapters      internal/core/adapter defines a complete CoreAdapter interface
//	              with conformance tests and has zero non-test importers.
//
// The pattern is always the same and is invisible to ordinary testing: unit
// tests exercise the function, integration tests wire their own router, and the
// gap is only in the one file nobody asserts about. Comparing the handlers the
// package DECLARES against the handlers the router REGISTERS is the only thing
// that sees it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// declaredHandlers returns every `func (s *Server) handleXxx` in the package.
func declaredHandlers(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !strings.HasPrefix(fn.Name.Name, "handle") {
				continue
			}
			out = append(out, fn.Name.Name)
		}
	}
	sort.Strings(out)
	return out
}

// mountedHandlers returns the handler names gin actually has registered.
func mountedHandlers(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	eng, ok := s.Handler().(*gin.Engine)
	if !ok {
		t.Fatalf("the server's handler is not a *gin.Engine, so routes cannot be enumerated")
	}
	out := map[string]bool{}
	for _, r := range eng.Routes() {
		// gin reports the full symbol, e.g.
		// "github.com/forgepanel/forgepanel/internal/api.(*Server).handleMe-fm".
		name := r.Handler
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		out[strings.TrimSuffix(name, "-fm")] = true
	}
	return out
}

// notMounted lists handlers that legitimately have no route, each with a reason.
// An entry with no reason is how this guard would get quietly neutered.
var notMounted = map[string]string{}

func TestEveryHandlerIsReachableFromTheRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, _ := createComprehensiveTestServer(t)

	mounted := mountedHandlers(t, s)
	if len(mounted) < 20 {
		t.Fatalf("only %d routes enumerated — the scan is broken, not the router", len(mounted))
	}

	var orphans []string
	for _, h := range declaredHandlers(t) {
		if mounted[h] || notMounted[h] != "" {
			continue
		}
		orphans = append(orphans, h)
	}
	if len(orphans) > 0 {
		t.Fatalf("%d handler(s) are defined but reachable from NO route, so the feature is dead in "+
			"production while its own tests pass:\n  - %s\n\n"+
			"Mount each on the router, or document it in notMounted with the reason it has no route.",
			len(orphans), strings.Join(orphans, "\n  - "))
	}
}

// gin only reports the LAST handler in a chain, so middleware mounted per-route
// is invisible to the scan above. The port-collision guard is exactly that shape
// — and was exactly the thing that went unmounted — so it gets a direct check:
// send two creates for one port at the real server and require the second to be
// refused.
func TestPerRouteMiddlewareIsActuallyInTheChain(t *testing.T) {
	stubListeners(t)
	s, _, token := createComprehensiveTestServer(t)

	body := map[string]any{
		"protocol": "vless", "remark": "guard-probe", "address": "0.0.0.0", "port": 25101,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
	}
	if code, resp := realPost(t, s, "/api/admin/inbounds", token, body); code != 201 {
		t.Fatalf("setup create failed: %d %s", code, resp)
	}
	body["remark"] = "guard-probe-2"
	if code, _ := realPost(t, s, "/api/admin/inbounds", token, body); code != 409 {
		t.Fatalf("the port-collision middleware is not in the real chain: second create returned %d, want 409", code)
	}
}

// A route table that answers 404 for a path the UI calls is the same failure
// wearing a different hat. These are paths the frontend depends on; a rename
// that misses one shows up here rather than as a dead button.
func TestRoutesTheUIDependsOnExist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, _ := createComprehensiveTestServer(t)
	eng, _ := s.Handler().(*gin.Engine)

	registered := map[string]bool{}
	for _, r := range eng.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, want := range []string{
		"GET /api/admin/me",
		"POST /api/admin/change-password",
		"POST /api/admin/2fa/enable",
		"POST /api/admin/2fa/disable",
		"POST /api/admin/2fa/recovery/regenerate",
		"GET /api/admin/inbounds",
		"POST /api/admin/inbounds",
		"PUT /api/admin/inbounds/:id",
		"POST /api/admin/ports/check",
		"GET /api/admin/users",
		"GET /api/admin/quota",
		"GET /api/protocols/schema",
		// The Nodes table's Disable/Enable button and its live log panel. Both
		// are the shape this guard exists for: a handler that exists, compiles
		// and tests green behind a path the router never learned.
		"PATCH /api/admin/nodes/:id",
		"GET /api/admin/nodes/:id/logs",
		// The Updates card on System Health.
		"GET /api/admin/update",
	} {
		if !registered[want] {
			t.Errorf("the UI calls %q and the router does not serve it", want)
		}
	}
}
