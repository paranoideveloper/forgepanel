package buildinfo_test

// Package-reachability guard: every internal package must be reachable from a
// shipped binary, or be documented as deliberately not.
//
// "Written, tested, and never wired in" is the single most common defect class
// in this codebase. Every instance passed its own tests, because the tests
// exercised the package directly; the gap was always in the one file that was
// supposed to call it, and nothing asserted about that file:
//
//	internal/api/authz.go       a complete fail-closed RBAC policy, never
//	                            attached to the admin group. A viewer could
//	                            drive owner-only endpoints.
//	portCollisionGuard          mounted only inside its own test's router.
//	                            Production accepted two inbounds on one port,
//	                            which makes the engine reject the whole config
//	                            and takes EVERY inbound offline.
//	internal/core/adapter       1,353 lines: a CoreAdapter interface, four real
//	                            adapters and a conformance suite. Zero non-test
//	                            importers — now wired into Controller.dispatch.
//	internal/service            404 lines of service layer. Same — and a
//	                            duplicate of the API's own handlers, so it was
//	                            deleted rather than wired.
//
// TestEveryHandlerIsReachableFromTheRouter covers HTTP handlers. This covers the
// level above it: a whole package that nothing links.
//
// It lives in its own package so it does not import any of the packages it
// judges — importing them would make them reachable and the test would pass by
// construction.

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// knownUnlinked records packages that SHOULD be linked and are not. They are
// listed separately from notLinked on purpose: these are open defects, not
// design decisions, and folding them into the same map is how a guard stops
// meaning anything. The test reports them on every run so the count cannot
// quietly grow.
//
// Currently EMPTY, and that is the point: both original entries were resolved
// rather than accepted. internal/core/adapter is now the live reload dispatch;
// internal/service was deleted as a duplicate of what the API already did.
var knownUnlinked = map[string]string{}

// notLinked documents internal packages that no shipped binary links, with the
// reason. An entry without a reason is how this guard gets quietly neutered.
var notLinked = map[string]string{
	// A test-only package: it holds cross-package round-trip tests and declares
	// package protocol_test, so it has no importable surface at all.
	"github.com/forgepanel/forgepanel/internal/protocol": "test-only package (package protocol_test); nothing to link",
	// This guard's own home. It deliberately imports none of the packages it
	// judges — importing them would make them reachable and the test would pass
	// by construction — so it has no non-test surface to link.
	"github.com/forgepanel/forgepanel/internal/buildinfo": "holds this reachability guard only; imports nothing by design",
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = "../.." // repo root
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Skipf("go list failed (%v): %s", err, ee.Stderr)
		}
		t.Skipf("go toolchain unavailable: %v", err)
	}
	var pkgs []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "github.com/forgepanel/forgepanel/internal") {
			pkgs = append(pkgs, l)
		}
	}
	return pkgs
}

func TestEveryInternalPackageIsLinkedIntoABinary(t *testing.T) {
	linked := map[string]bool{}
	for _, p := range goList(t, "-deps", "./cmd/...") {
		linked[p] = true
	}
	if len(linked) < 10 {
		t.Fatalf("only %d packages reachable from ./cmd/... — the scan is broken, not the build", len(linked))
	}

	var orphans []string
	var known []string
	for _, p := range goList(t, "./internal/...") {
		if linked[p] || notLinked[p] != "" {
			continue
		}
		if why := knownUnlinked[p]; why != "" {
			known = append(known, p+"\n      "+why)
			continue
		}
		orphans = append(orphans, p)
	}
	// Report the known ones every run. They are open defects; silence would let
	// them settle into looking like the intended design.
	if len(known) > 0 {
		sort.Strings(known)
		t.Logf("%d package(s) are built and tested but not linked into any binary — open defects, "+
			"not design decisions:\n  - %s", len(known), strings.Join(known, "\n  - "))
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Fatalf("%d internal package(s) are not linked into any binary under ./cmd, so the code "+
			"ships to nobody while its own tests pass:\n  - %s\n\n"+
			"Wire each into the product, delete it, or document it in notLinked with the reason.",
			len(orphans), strings.Join(orphans, "\n  - "))
	}
}

// A package reachable ONLY from ./tools is a lab harness, not a product
// feature. That distinction cost real confidence once: the DNS front router was
// built, and verified live against 1.1.1.1/8.8.8.8/9.9.9.9 on port 53 — through
// tools/dnsfrontlab. The shipped panel never linked it, so the demonstrated
// capability was not in the product.
func TestPackagesReachableOnlyFromToolsAreDeclaredAsSuch(t *testing.T) {
	fromCmd := map[string]bool{}
	for _, p := range goList(t, "-deps", "./cmd/...") {
		fromCmd[p] = true
	}
	fromTools := map[string]bool{}
	for _, p := range goList(t, "-deps", "./tools/...") {
		fromTools[p] = true
	}

	var labOnly []string
	for p := range fromTools {
		if !fromCmd[p] && notLinked[p] == "" && knownUnlinked[p] == "" {
			labOnly = append(labOnly, p)
		}
	}
	if len(labOnly) > 0 {
		sort.Strings(labOnly)
		t.Fatalf("%d package(s) are reachable only from ./tools, so they are lab harnesses rather "+
			"than shipped features:\n  - %s\n\n"+
			"Wire them into a binary under ./cmd, or record in notLinked that they are tooling.",
			len(labOnly), strings.Join(labOnly, "\n  - "))
	}
}
