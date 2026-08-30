package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The panel hands out the node agent from its own filesystem, so an image that
// does not ship forgenode answers every enrolment with a 503 that names a list
// of paths nobody can do anything about.
//
// This is a cross-file comparison rather than a unit test on purpose: the Go
// side is correct in isolation and the defect lives entirely in the gap between
// agentBinaryPath's candidate list and what a Dockerfile copies. Nothing in the
// Go suite can see that gap, and it is exactly the kind that gets found in
// production by someone trying to add their first node — the Railway image
// shipped without forgenode while every test here passed.
func TestEveryImageShipsTheAgentThePanelServes(t *testing.T) {
	// The candidate paths handleNodeAgent will actually try. Kept here in the
	// same file as the assertion so a change to agentBinaryPath that moves the
	// lookup shows up as a failing test rather than a silent 503.
	served := []string{"/usr/local/bin/forgenode", "/usr/bin/forgenode"}

	for _, df := range []string{
		filepath.Join("..", "..", "Dockerfile"),
		filepath.Join("..", "..", "deploy", "paas", "Dockerfile"),
	} {
		b, err := os.ReadFile(df)
		if err != nil {
			// A distribution that trims one of these is not a failure; only a
			// present-but-incomplete image is.
			continue
		}
		body := string(b)

		if !strings.Contains(body, "./cmd/forgenode") {
			t.Errorf("%s never builds ./cmd/forgenode, so this image cannot serve the node agent "+
				"and every enrolment against it fails at the download step", df)
			continue
		}

		// Built is not served. The binary has to land somewhere agentBinaryPath
		// looks, and "next to the panel" is the first candidate — so a COPY to
		// the same directory as forgepanel counts too.
		ok := false
		for _, p := range served {
			if strings.Contains(body, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s builds forgenode but copies it nowhere agentBinaryPath looks (%s); "+
				"the binary is in the image and the endpoint still 503s",
				df, strings.Join(served, ", "))
		}
	}
}

// A COPY whose source .dockerignore filtered out fails as "not found", which
// reads as a missing file rather than an excluded one — and the fix is in a
// different file from the error.
//
// It has happened once: .dockerignore excludes the whole deploy/ tree and
// re-includes the PaaS entrypoint by name, so renaming deploy/railway to
// deploy/paas left the negation pointing at a path that no longer existed. Both
// images then failed to build, and nothing in the Go suite could see it because
// nothing in the Go suite reads .dockerignore.
func TestEveryDockerfileCOPYSurvivesDockerignore(t *testing.T) {
	ignore, err := os.ReadFile(filepath.Join("..", "..", ".dockerignore"))
	if err != nil {
		t.Skipf("no .dockerignore: %v", err)
	}
	var excluded, included []string
	for _, ln := range strings.Split(string(ignore), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "!") {
			included = append(included, strings.TrimPrefix(ln, "!"))
			continue
		}
		excluded = append(excluded, ln)
	}

	for _, df := range []string{
		filepath.Join("..", "..", "Dockerfile"),
		filepath.Join("..", "..", "deploy", "paas", "Dockerfile"),
	} {
		b, err := os.ReadFile(df)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			// Only COPY from the build CONTEXT matters; --from=<stage> copies
			// out of an earlier image and .dockerignore has no say in it.
			if len(f) < 3 || !strings.EqualFold(f[0], "COPY") || strings.HasPrefix(f[1], "--from") {
				continue
			}
			src := strings.Trim(f[1], `"`)
			if src == "." {
				continue
			}
			for _, ex := range excluded {
				dir := strings.TrimSuffix(ex, "/")
				if dir == "" || !strings.HasPrefix(src, dir+"/") {
					continue
				}
				ok := false
				for _, in := range included {
					if in == src {
						ok = true
						break
					}
				}
				if !ok {
					t.Errorf("%s: COPY %s, but .dockerignore excludes %q and does not re-include it — "+
						"the build fails with %q not found, which names the file rather than the exclusion",
						df, src, ex, src)
				}
			}
		}
	}
}
