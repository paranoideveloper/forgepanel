package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// There must be exactly ONE panel UI.
//
// The tree carried two more beside the real one, both reachable and both wrong.
// /admin was a reduced copy — its own login form, its own sidebar, three tabs
// against the real panel's sixteen — that had drifted off the API it calls:
// PUT /admin/users/:id where the route is PATCH, POST /admin/nodes where the
// route is /nodes/enroll. Enable, disable and register-node could not work in
// it. /studio was a mock: it built a config object client-side and stringified
// it, never calling POST /api/studio/preview, and saved nothing. The REAL
// studio is a tab in the panel, and it is a different file.
//
// They were not merely dead weight. The root, the secret admin path and every
// client-side route were all served the /admin copy's shell, whose stylesheet
// opens with an unscoped body{} rule — so the duplicate's colours were applied
// over the real panel on every page load.
func TestNoParallelPanelUIs(t *testing.T) {
	// The root must serve the panel's own shell. adapter-static emits one shell
	// per prerendered route, and the two differ: index.html pulls the root
	// page's node bundle, admin.html the duplicate's.
	want, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("the panel's own shell is not embedded: %v", err)
	}
	s := testServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Errorf("GET / does not serve the panel's own shell (web/index.html); "+
			"it served %d bytes and the shell is %d", rec.Body.Len(), len(want))
	}

	// The parallel shells must be gone from the bundle. Leaving them embedded
	// keeps them reachable even with the source routes deleted.
	for _, p := range []string{"web/admin.html", "web/studio.html"} {
		if _, err := webFS.ReadFile(p); err == nil {
			t.Errorf("%s is still embedded: a parallel UI still ships in the binary", p)
		}
	}

	// And the sources must be gone, so a forgotten rebuild cannot hide it.
	for _, p := range []string{
		"../../frontend/src/routes/admin/+page.svelte",
		"../../frontend/src/routes/studio/+page.svelte",
	} {
		if _, err := os.Stat(filepath.FromSlash(p)); err == nil {
			t.Errorf("%s still exists — a second parallel UI", p)
		}
	}

	// The real studio is a TAB and must survive. Deleting the page next to it
	// is easy to overreach on, and presets_test.go reads this path literally
	// and only SKIPS when it is missing, so losing it would silently delete the
	// preset/description-key guard rather than fail.
	real := filepath.FromSlash("../../frontend/src/routes/studio/StudioView.svelte")
	if _, err := os.Stat(real); err != nil {
		t.Errorf("the real Config Studio was deleted along with the mock: %v", err)
	}
}
