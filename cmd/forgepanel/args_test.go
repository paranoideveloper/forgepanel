package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The argv surface had one recognised flag (--version) and let EVERYTHING else
// fall through to start(), so `forgepanel --help` started a panel listening on
// :2053 — as did `forgepanel --port 8080`, `forgepanel --dry-run`, and every
// typo. An operator checking usage on a live box brought up a second panel
// instead of reading a help text, and a flag that looked accepted did nothing.
//
// Found by running the binary on a real server: nothing in the suite exercised
// argv, because every other test calls start() or the handlers directly.
//
// These build the binary and RUN it, because that is the only way to observe
// "did it exit or did it bind a port".
func buildPanel(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "forgepanel")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestHelpPrintsUsageAndExits(t *testing.T) {
	bin := buildPanel(t)
	for _, flag := range []string{"--help", "-h", "help"} {
		out, err := exec.Command(bin, flag).CombinedOutput()
		if err != nil {
			t.Errorf("%s exited with %v: %s", flag, err, out)
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("%s printed no usage: %s", flag, out)
		}
		// The one thing a reader most needs to know, since there are almost no
		// flags: configuration is not done here.
		if !strings.Contains(string(out), "FORGEPANEL_DATA") {
			t.Errorf("%s does not say where configuration comes from: %s", flag, out)
		}
	}
}

// An unrecognised flag must be REFUSED. Silently ignoring it and starting the
// server is how `--port 8080` becomes a panel on the wrong port that the
// operator believes is on 8080.
func TestAnUnknownFlagIsRefusedRatherThanIgnored(t *testing.T) {
	bin := buildPanel(t)
	for _, arg := range []string{"--port", "--dry-run", "-x", "serve"} {
		out, err := exec.Command(bin, arg).CombinedOutput()
		if err == nil {
			t.Errorf("%q was accepted; the panel started instead of refusing it: %s", arg, out)
			continue
		}
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 2 {
			t.Errorf("%q exited %d, want 2 (usage error)", arg, ee.ExitCode())
		}
		if !strings.Contains(string(out), arg) {
			t.Errorf("the error for %q does not name it: %s", arg, out)
		}
	}
}

func TestVersionStillShortCircuits(t *testing.T) {
	bin := buildPanel(t)
	for _, flag := range []string{"--version", "-version", "version"} {
		out, err := exec.Command(bin, flag).CombinedOutput()
		if err != nil {
			t.Errorf("%s exited with %v: %s", flag, err, out)
		}
		if !strings.Contains(string(out), "forgepanel") {
			t.Errorf("%s printed %q", flag, out)
		}
	}
}

// The usage text must name only variables the panel actually reads.
//
// The first version of it listed FORGEPANEL_DATA_DIR and FORGEPANEL_PORT.
// Neither exists — the real names are FORGEPANEL_DATA and
// FORGEPANEL_PANEL_PORT — and I found that out by putting the wrong one in a
// systemd unit and watching the panel write its database into the service's
// working directory instead. A help text that names variables that do nothing
// is worse than no help text, because it is believed.
func TestUsageNamesOnlyRealEnvironmentVariables(t *testing.T) {
	root := filepath.Join("..", "..")
	var read []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, m := range envCall.FindAllStringSubmatch(string(b), -1) {
			read = append(read, m[2])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(read) < 5 {
		t.Fatalf("only found %d env reads — the scan is broken, not the usage text", len(read))
	}
	known := map[string]bool{}
	for _, v := range read {
		known[v] = true
	}
	for _, m := range envMention.FindAllString(usageText, -1) {
		if !known[m] {
			t.Errorf("the usage text names %s, which nothing in the tree reads", m)
		}
	}
}

var (
	envCall    = regexp.MustCompile(`env(Str|Int|Bool)\("([A-Z_]+)"`)
	envMention = regexp.MustCompile(`FORGEPANEL_[A-Z_]+`)
)
