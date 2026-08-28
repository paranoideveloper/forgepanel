package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Xray infers a config's format from the file EXTENSION. The agent validated
// its temp file at configPath+".tmp" — node-xray.json.tmp — which Xray refuses
// outright:
//
//	core: Failed to get format of /var/lib/forgepanel/node-xray.json.tmp
//
// Validation happens before the commit, so EVERY config a node was sent was
// rejected whatever it contained. A node enrolled, heartbeated, reported
// healthy, received its config, refused it, and retried every ten seconds
// forever. The remote-node feature did not work at all.
//
// Found by enrolling a real node and reading its journal; nothing in the suite
// caught it because the agent's tests drive it against an httptest server and
// never run a real core.
func TestTempConfigKeepsTheExtensionXrayNeeds(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/var/lib/forgepanel/node-xray.json", "/var/lib/forgepanel/node-xray.tmp.json"},
		{"/var/lib/forgepanel/node-singbox.json", "/var/lib/forgepanel/node-singbox.tmp.json"},
		{"/tmp/noext", "/tmp/noext.tmp"},
	} {
		if got := tempConfigPath(c.in); got != c.want {
			t.Errorf("tempConfigPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A sibling, so the commit stays an atomic same-directory rename.
	in := "/var/lib/forgepanel/node-xray.json"
	if filepath.Dir(tempConfigPath(in)) != filepath.Dir(in) {
		t.Error("the temp file is not a sibling of the config; rename would cross filesystems")
	}
}

// The assertion that actually matters: a REAL Xray must accept the temp path.
// The unit test above encodes a belief about what Xray wants; only Xray knows.
func TestARealXrayAcceptsTheTempConfigPath(t *testing.T) {
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}
	const cfg = `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`

	dir := t.TempDir()
	good := tempConfigPath(filepath.Join(dir, "node-xray.json"))
	if err := os.WriteFile(good, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "run", "-test", "-c", good).CombinedOutput(); err != nil {
		t.Fatalf("xray refuses the temp path this agent writes (%s):\n%s", good, out)
	}

	// And the shape that caused the outage is genuinely refused, so this test
	// is not passing for some unrelated reason.
	bad := filepath.Join(dir, "node-xray.json.tmp")
	if err := os.WriteFile(bad, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", bad).CombinedOutput()
	if err == nil {
		t.Fatalf("xray accepted %s, so the extension is not what broke this — re-diagnose", bad)
	}
	if !strings.Contains(string(out), "format") {
		t.Logf("xray refused %s for a different reason than the format:\n%s", bad, out)
	}
}
