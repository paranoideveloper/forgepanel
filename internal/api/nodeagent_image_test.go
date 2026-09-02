package api

import (
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
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

// The PaaS image bakes the cores rather than letting the panel fetch them,
// because a platform deploy with no volume downloads them again on every
// restart and a restricted build network leaves the panel with no cores at all
// — the Dockerfile says exactly that, at the top of its cores stage.
//
// It baked two of the three. Brook was fetched from GitHub at first use, so on a
// host that sleeps and has no disk it was re-downloaded on every wake, and a
// failed or slow download left a Brook inbound configured, enabled, and dead
// with nothing in the panel to say why.
//
// This compares the versions too. The Dockerfile's own comment is right that a
// stale one here is not an error but a silent download at every boot: binmgr
// looks for <data>/bin/<engine>-<version>/<binary> and fetches when it is not
// there, so a version that does not match the constant stages a directory
// nothing will ever look in.
func TestThePaaSImageBakesEveryCoreThePanelSupervises(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "paas", "Dockerfile"))
	if err != nil {
		t.Skipf("no PaaS Dockerfile: %v", err)
	}
	body := string(b)

	// The staged directory names are built from ARG defaults, so resolve those
	// first — comparing against the literal version would only ever prove the
	// Dockerfile spells it inline.
	args := map[string]string{}
	for _, ln := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) < 2 || !strings.EqualFold(f[0], "ARG") {
			continue
		}
		k, v, ok := strings.Cut(f[1], "=")
		if ok {
			args[k] = v
		}
	}
	resolve := func(s string) string {
		for k, v := range args {
			s = strings.ReplaceAll(s, "${"+k+"}", v)
		}
		return s
	}

	for _, core := range []struct{ name, version string }{
		{"xray", binmgr.XrayVersion},
		{"sing-box", binmgr.SingboxVersion},
		{"brook", binmgr.BrookVersion},
	} {
		// The staged directory the entrypoint copies into place, in the exact
		// shape binmgr resolves: <engine>-<version>.
		want := core.name + "-" + core.version
		found := false
		for _, ln := range strings.Split(body, "\n") {
			if strings.Contains(resolve(ln), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the PaaS image does not stage %q: a %s inbound on a platform with no volume "+
				"downloads the core on every restart, and comes up dead when that download fails",
				want, core.name)
		}
	}
}
