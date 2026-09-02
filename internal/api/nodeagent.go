package api

// Serving the node agent binary, and the enrollment script that installs it.
//
// The enrollment script used to carry a comment reading "placeholder URL — point
// at your release" and downloaded nothing. It wrote a systemd unit pointing at
// /usr/local/bin/forgenode and ran `systemctl enable --now`, so on a fresh node
// the unit referenced a file that did not exist and the service failed to start
// or crash-looped. Enrolling a node from the panel could not work; the only way
// through was to install the binary by hand first, which is how the gap stayed
// invisible.
//
// The agent is served BY THE PANEL rather than fetched from GitHub, for three
// reasons that all matter here:
//
//	version match   the node agent and the panel speak a private heartbeat and
//	                config schema. An agent from a different release can differ
//	                in ways neither side reports, so pinning the agent to the
//	                panel that will drive it removes a whole class of mismatch.
//	private repo    the release repository is private; a bare curl from a node
//	                gets 404, not a binary.
//	reachability    the node already has to reach the panel to work at all. It
//	                may well not reach GitHub.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/forgepanel/forgepanel/internal/apierr"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// agentBinary locates the forgenode executable this panel can hand out.
//
// Search order is "shipped with this panel" first: the release installs
// forgepanel and forgenode side by side, so the neighbour of the running
// executable is the copy guaranteed to match this build.
func agentBinaryPath(dataDir string) (string, error) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "forgenode"))
	}
	candidates = append(candidates,
		"/usr/local/bin/forgenode",
		"/usr/bin/forgenode",
	)
	if dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, "bin", "forgenode"))
	}
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("no forgenode executable found (looked in %s)", strings.Join(candidates, ", "))
}

// agentDigest caches the SHA-256 of the served binary, keyed by path+size+mtime
// so an upgraded binary is re-hashed rather than served under a stale digest.
var (
	agentDigestMu  sync.Mutex
	agentDigestKey string
	agentDigestVal string
)

func agentSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("%s|%d|%d", path, info.Size(), info.ModTime().UnixNano())

	agentDigestMu.Lock()
	if key == agentDigestKey && agentDigestVal != "" {
		v := agentDigestVal
		agentDigestMu.Unlock()
		return v, nil
	}
	agentDigestMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	agentDigestMu.Lock()
	agentDigestKey, agentDigestVal = key, sum
	agentDigestMu.Unlock()
	return sum, nil
}

// handleNodeAgent streams the forgenode executable.
//
// It refuses an architecture mismatch rather than serving a binary that cannot
// run. A node that downloads an amd64 agent onto arm64 gets "cannot execute
// binary file" from systemd, which reads like a corrupt download and sends the
// operator looking in the wrong place; naming the mismatch here points straight
// at it.
func (s *Server) handleNodeAgent(c *gin.Context) {
	want := strings.TrimSpace(c.Query("arch"))
	if want != "" && want != runtime.GOARCH {
		apierr.Fail(c, &apierr.Error{Op: "node-agent-download", Kind: apierr.KindConflict,
			Message: fmt.Sprintf(
				"this panel runs on %s and can only serve a %s agent, but the node reports %s. "+
					"Install the matching forgenode build on the node manually, then re-run enrollment.",
				runtime.GOARCH, runtime.GOARCH, want),
			Details: map[string]any{"panel_arch": runtime.GOARCH, "node_arch": want}})
		return
	}
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	path, err := agentBinaryPath(dataDir)
	if err != nil {
		// A 503 with the reason, not a 404: the endpoint exists, the panel just
		// has nothing to serve, and the operator needs to know which it is.
		apierr.Fail(c, &apierr.Error{Op: "node-agent-download", Kind: apierr.KindUnavailable,
			Message: "this panel has no forgenode executable to hand out: " + err.Error() +
				". Install the agent on the node manually, or place forgenode next to the panel binary.",
			Cause: err})
		return
	}
	if sum, err := agentSHA256(path); err == nil {
		// The script verifies this, so a truncated or intercepted download fails
		// loudly instead of being installed and crash-looping.
		c.Header("X-Forgenode-SHA256", sum)
	}
	c.Header("Content-Disposition", `attachment; filename="forgenode"`)
	c.File(path)
}

// handleNodeAgentDigest reports the SHA-256 of the agent this panel serves, so
// the install script can verify the download without needing to trust headers it
// already received over the same connection.
func (s *Server) handleNodeAgentDigest(c *gin.Context) {
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	path, err := agentBinaryPath(dataDir)
	if err != nil {
		failErr(c, http.StatusServiceUnavailable, err)
		return
	}
	sum, err := agentSHA256(path)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(200, gin.H{"sha256": sum, "arch": runtime.GOARCH})
}
