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
