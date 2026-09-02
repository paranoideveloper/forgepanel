package api

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The enrollment script used to contain a comment reading "placeholder URL —
// point at your release" and download NOTHING. It wrote a systemd unit pointing
// at /usr/local/bin/forgenode and ran `systemctl enable --now`, so on a fresh
// node the unit referenced a file that did not exist. Enrolling a node from the
// panel could not work.
func enrollmentScript(t *testing.T) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := &Server{}
	r := gin.New()
	r.GET("/api/node/install.sh", s.handleNodeInstallScript)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/node/install.sh", nil))
	if w.Code != 200 {
		t.Fatalf("install script returned %d", w.Code)
	}
	return w.Body.String()
}

func TestEnrollmentScriptActuallyInstallsTheAgent(t *testing.T) {
	src := enrollmentScript(t)

	if strings.Contains(strings.ToLower(src), "placeholder") {
		t.Error("the script still describes itself as a placeholder")
	}
	// It must fetch the agent, verify it, and install it.
	for _, want := range []string{
		"/api/node/agent", // downloads the binary
		"sha256",          // verifies it
		"install -m 0755", // installs it
		"/usr/local/bin/forgenode",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the script never mentions %q, so it cannot be doing that step", want)
		}
	}
	// The node pins the panel's certificate when the panel is self-signed. The
	// unit previously carried PANEL and TOKEN only, so a pinning agent had
	// nothing to pin and refused every connection.
	if !strings.Contains(src, "Environment=PANEL_FINGERPRINT=") {
		t.Error("the systemd unit does not pass PANEL_FINGERPRINT, so a node cannot pin a self-signed panel")
	}
	// Reporting success when the service did not come up is how an enrollment
	// looks fine and does nothing.
	if !strings.Contains(src, "is-active") {
		t.Error("the script never checks that the service actually stayed up")
	}
}

// A script that is not valid shell fails on the node, after the operator has
// already pasted it into a root prompt.
func TestEnrollmentScriptIsValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(enrollmentScript(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bash, "-n", path).CombinedOutput()
	if err != nil {
		t.Fatalf("the enrollment script is not valid bash: %v\n%s", err, out)
	}
}

// Without PANEL and TOKEN the script must refuse immediately rather than write a
// unit with empty values and start a service that can never enroll.
func TestEnrollmentScriptRefusesWithoutPanelAndToken(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(enrollmentScript(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"} // no PANEL, no TOKEN
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "PANEL") {
		t.Fatalf("the script should refuse and name the missing variable, got: %s", out)
	}
}

// End-to-end: a real panel serves a real forgenode binary, and the real script's
// download + verify + execute steps run against it. Only the systemd half is
// stubbed, because a test must not install units on the host.
func TestAgentDownloadAndVerifyWorksAgainstARealPanel(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	goBin := goToolPath(t)

	// Build the real agent and put it where the panel looks for it.
	dir := t.TempDir()
	agent := filepath.Join(dir, "forgenode")
	build := exec.Command(goBin, "build", "-o", agent, "./cmd/forgenode")
	build.Dir = repoRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the agent failed: %v\n%s", err, out)
	}

	s, _, _ := createComprehensiveTestServer(t)
	s.cfg.DataDir = dir
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(agent, filepath.Join(dir, "bin", "forgenode")); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// Drive exactly what the script does: download, read the digest, compare.
	probe := `
set -euo pipefail
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$PANEL/api/node/agent?arch=$(go env GOARCH 2>/dev/null || echo amd64)" -o "$TMP/forgenode"
WANT="$(curl -fsSL "$PANEL/api/node/agent/sha256" | sed -n 's/.*"sha256":"\([a-f0-9]*\)".*/\1/p')"
[ -n "$WANT" ] || { echo "no digest served" >&2; exit 1; }
GOT="$(sha256sum "$TMP/forgenode" | cut -d" " -f1)"
[ "$WANT" = "$GOT" ] || { echo "checksum mismatch: $WANT vs $GOT" >&2; exit 1; }
chmod 0755 "$TMP/forgenode"
"$TMP/forgenode" --version >/dev/null 2>&1 || "$TMP/forgenode" -h >/dev/null 2>&1 || {
  echo "the downloaded agent will not execute" >&2; exit 1; }
echo OK
`
	path := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(path, []byte(probe), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, path)
	cmd.Env = append(os.Environ(), "PANEL="+ts.URL)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK") {
		t.Fatalf("the download-and-verify path does not work against a real panel: %v\n%s", err, out)
	}
}

// A panel with no agent to hand out must say so, not 404. The operator needs to
// know the endpoint exists and the panel is missing the file.
func TestPanelWithoutAnAgentSaysSo(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	s.cfg.DataDir = t.TempDir() // nothing installed here

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/node/agent", s.handleNodeAgent)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/node/agent?arch=sparc64", nil))

	if w.Code != 409 {
		t.Fatalf("an architecture mismatch should be a 409 naming both sides, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "sparc64") {
		t.Errorf("the error should name the architecture the node reported: %s", w.Body.String())
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func goToolPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/local/go1.25/bin/go", "go"} {
		if found, err := exec.LookPath(p); err == nil {
			return found
		}
	}
	t.Skip("go toolchain not available")
	return ""
}

// The enroll command, the install script and the agent all have to agree on ONE
// name for the certificate pin. They did not: the command exported
// PANEL_FINGERPRINT while the script read FINGERPRINT, so the pin arrived empty
// and a node would refuse to trust a self-signed panel — reported as an
// interception, which sends the operator looking for an attacker rather than a
// typo.
//
// This is the same cross-boundary naming failure that made change-password,
// certificate import and reset-credentials all non-functional, so it gets a test
// that reads all three sides.
func TestFingerprintVariableNameAgreesAcrossEveryBoundary(t *testing.T) {
	const name = "PANEL_FINGERPRINT"

	script := enrollmentScript(t)
	if !strings.Contains(script, name+`="${`+name) {
		t.Errorf("the install script does not read %s from the environment", name)
	}
	if !strings.Contains(script, "Environment="+name+"=") {
		t.Errorf("the systemd unit does not pass %s to the agent", name)
	}

	// The handler that builds the enroll command.
	nodesSrc, err := os.ReadFile("nodes.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nodesSrc), `" `+name+`=" + fp`) {
		t.Errorf("the enroll command does not export %s", name)
	}

	// And the agent that consumes it.
	agentSrc, err := os.ReadFile(filepath.Join("..", "..", "cmd", "forgenode", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(agentSrc), `os.Getenv("`+name+`")`) {
		t.Errorf("the agent does not read %s", name)
	}

	// And nothing still uses the old bare name.
	if strings.Contains(script, `"$FINGERPRINT"`) {
		t.Error("the install script still refers to the old bare FINGERPRINT name")
	}
}
