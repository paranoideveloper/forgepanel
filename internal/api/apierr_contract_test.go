package api

// The API had four different ideas of what an error looks like.
//
// internal/dns and internal/edge each grew a full typed error — kind, op,
// remediation, missing_scope — and each grew its own private kind->HTTP-status
// switch to write it. internal/api itself had neither: 386 handlers hand-rolled
// `c.JSON(<status>, gin.H{"error": ...})`, and the two adapters that did know
// about typed errors (respond, edgeFail) covered 23 call sites between them.
//
// The visible damage was in respond(): it answered EVERY error with 400 and a
// bare string, so a Cloudflare "your token cannot read zones" arrived at the
// browser as a 400 with the remediation — the one sentence that says which
// checkbox to tick — thrown away. The operator saw "Bad Request".
//
// These two tests are the pair that keeps that fixed. The first proves the
// shared writer is wired into respond; the second proves it is wired into
// everything else, because a helper that only the two old adapters call is how
// this feature already got shipped twice without reaching the panel.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/gin-gonic/gin"
)

// TestRespondPreservesTypedErrorKind: a typed error handed to respond must keep
// its status, kind and remediation instead of being flattened to 400 + string.
func TestRespondPreservesTypedErrorKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respond(c, nil, &dns.Error{
		Op:          "resolve-zone",
		Kind:        dns.KindNotFound,
		Message:     "no such zone",
		Remediation: "add the domain in Cloudflare first",
	})

	if w.Code != http.StatusNotFound {
		t.Errorf("respond wrote status %d for a dns.KindNotFound, want %d — "+
			"a missing zone is being reported as a malformed request",
			w.Code, http.StatusNotFound)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (body %q)", err, w.Body.String())
	}
	if got, _ := body["kind"].(string); got != "not_found" {
		t.Errorf("body kind = %q, want %q — the UI cannot branch on a bare string",
			got, "not_found")
	}
	if got, _ := body["remediation"].(string); got == "" {
		t.Errorf("body carries no remediation; the provider told us exactly what to fix "+
			"and the panel dropped it (body %q)", w.Body.String())
	}
	if got, _ := body["error"].(string); got != "no such zone" {
		t.Errorf("body error = %q, want the typed message %q", got, "no such zone")
	}
}

// TestNoAdHocErrorBodies is the guard that distinguishes "the helper exists"
// from "the API uses it". Every error body in this package must go through the
// shared writer, so that adding a field to the envelope reaches all of them.
//
// It scans the source rather than the routes on purpose: a body written by hand
// is invisible to any test that does not already exercise that exact endpoint,
// and 386 of them accumulated behind exactly that blind spot. The pattern is
// matched against the whole file, not line by line — a third of them wrapped
// their gin.H onto the next line, and a per-line check would have declared the
// job finished with 35 still standing.
func TestNoAdHocErrorBodies(t *testing.T) {
	adHoc := regexp.MustCompile(`gin\.H\{\s*"error"\s*:`)

	files, err := filepath.Glob(filepath.Join(".", "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sort.Strings(files)

	hits := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(src)
		for _, loc := range adHoc.FindAllStringIndex(text, -1) {
			line := strings.Count(text[:loc[0]], "\n") + 1
			hits++
			t.Errorf("%s:%d: hand-rolled error body; write it with fail/failErr/apierr.Fail so it "+
				"carries kind and remediation", path, line)
		}
	}
	if hits > 0 {
		t.Logf("%d hand-rolled error bodies remain in internal/api", hits)
	}
}
