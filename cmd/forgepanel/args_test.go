package main

import (
	"os/exec"
	"path/filepath"
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
		if !strings.Contains(string(out), "FORGEPANEL_DATA_DIR") {
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
