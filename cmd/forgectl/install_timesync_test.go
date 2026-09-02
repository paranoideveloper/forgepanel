package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The installer's clock check is guarded here because a host whose clock has
// drifted does not look like a clock problem: VMess AEAD stamps a timestamp into
// every request and REALITY/TLS reject a skewed handshake, so the panel is
// healthy, the links are correct, and every client fails to connect. install.sh
// had no NTP/chrony/timesyncd check of any kind.

// runCheckTimeSync extracts check_time_sync() from install.sh and runs it alone,
// with a stub timedatectl on PATH and the installer's output helpers replaced by
// no-ops. Sourcing install.sh itself is not an option: it ends in `main "$@"`.
func runCheckTimeSync(t *testing.T, timedatectlBody string, env ...string) (state, stderr, calls string) {
	t.Helper()
	dir := t.TempDir()

	// PATH is the stub dir ALONE, so the "no timedatectl on this host" case
	// really has none — with /usr/bin still on PATH it silently found the real
	// binary and reported this machine's clock instead of the stub's.
	for _, tool := range []string{"sed", "head", "sleep", "touch"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available to build the shell harness", tool)
		}
		if err := os.Symlink(real, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}

	if timedatectlBody != "" {
		stub := filepath.Join(dir, "timedatectl")
		body := "#!/bin/bash\nCALLS=\"" + filepath.Join(dir, "calls") + "\"\n" + timedatectlBody
		if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// The helpers write to stdout/stderr; TIME_SYNC_STATE is the data the test
	// asserts on, so a reworded message cannot silently pass or fail the test.
	harness := `
set -uo pipefail
info() { printf 'INFO %s\n' "$*" >&2; }
ok()   { printf 'OK %s\n'   "$*" >&2; }
warn() { printf 'WARN %s\n' "$*" >&2; }
confirm() { return 0; }
` + extractShellFunc(t, "check_time_sync") + `
check_time_sync
printf 'STATE=%s\n' "$TIME_SYNC_STATE"
`
	cmd := exec.Command("bash", "-c", harness)
	cmd.Env = append(os.Environ(), "PATH="+dir)
	cmd.Env = append(cmd.Env, env...)
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("check_time_sync exited %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if v, found := strings.CutPrefix(strings.TrimSpace(line), "STATE="); found {
			state = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "calls")); err == nil {
		calls = string(b)
	}
	return state, errOut.String(), calls
}

// extractShellFunc pulls one top-level `name() { ... }` block out of install.sh.
func extractShellFunc(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(src), "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("install.sh has no %s() — the host clock is never checked at install time", name)
	}
	rest := string(src)[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("%s() is not closed at column 0", name)
	}
	return rest[:end+3]
}

func TestInstallReportsSynchronisedClock(t *testing.T) {
	state, out, _ := runCheckTimeSync(t, `
echo "$*" >>"$CALLS"
[[ "$1" == "show" ]] && echo "NTPSynchronized=yes"
exit 0
`, "DRY_RUN=0", "ASSUME_YES=1", "INTERACTIVE=0")
	if state != "synced" {
		t.Fatalf("a synchronised host reported %q\n%s", state, out)
	}
}

// The case that matters: no time daemon at all, so `set-ntp true` fails and the
// operator must be told, with the exact command to fix it.
func TestInstallWarnsWhenClockCannotSync(t *testing.T) {
	state, out, _ := runCheckTimeSync(t, `
echo "$*" >>"$CALLS"
if [[ "$1" == "show" ]]; then echo "NTPSynchronized=no"; exit 0; fi
exit 1
`, "DRY_RUN=0", "ASSUME_YES=1", "INTERACTIVE=0")
	if state != "unsynced" {
		t.Fatalf("an unsynchronised host reported %q\n%s", state, out)
	}
	if !strings.Contains(out, "timedatectl set-ntp true") {
		t.Errorf("the warning does not carry the command that fixes it:\n%s", out)
	}
	if !strings.Contains(out, "chrony") {
		t.Errorf("the warning does not say what to install when no time daemon exists:\n%s", out)
	}
}

// A host with a daemon installed but switched off is repaired in place rather
// than handed to the operator as a chore.
func TestInstallEnablesNTPWhenItCan(t *testing.T) {
	state, out, calls := runCheckTimeSync(t, `
echo "$*" >>"$CALLS"
if [[ "$1" == "show" ]]; then
  if [[ -f "${CALLS}.enabled" ]]; then echo "NTPSynchronized=yes"; else echo "NTPSynchronized=no"; fi
  exit 0
fi
if [[ "$1" == "set-ntp" ]]; then touch "${CALLS}.enabled"; exit 0; fi
exit 1
`, "DRY_RUN=0", "ASSUME_YES=1", "INTERACTIVE=0")
	if !strings.Contains(calls, "set-ntp true") {
		t.Fatalf("the installer never tried to enable NTP: %q", calls)
	}
	if state != "synced" {
		t.Fatalf("state after enabling NTP = %q\n%s", state, out)
	}
}

// --dry-run promises that no system state was changed, so the check may report
// but must never run set-ntp.
func TestInstallDryRunDoesNotTouchTheClock(t *testing.T) {
	state, out, calls := runCheckTimeSync(t, `
echo "$*" >>"$CALLS"
if [[ "$1" == "show" ]]; then echo "NTPSynchronized=no"; exit 0; fi
exit 0
`, "DRY_RUN=1", "ASSUME_YES=1", "INTERACTIVE=0")
	if strings.Contains(calls, "set-ntp") {
		t.Fatalf("a dry run changed the host's clock settings: %q", calls)
	}
	if state != "unsynced" {
		t.Fatalf("a dry run must still report the problem, got %q\n%s", state, out)
	}
}

// No timedatectl at all (a container, a non-systemd host): unknown is its own
// answer and must not be reported as either healthy or broken.
func TestInstallReportsUnknownWithoutTimedatectl(t *testing.T) {
	state, out, _ := runCheckTimeSync(t, "", "DRY_RUN=0", "ASSUME_YES=1", "INTERACTIVE=0")
	if state != "unknown" {
		t.Fatalf("a host without timedatectl reported %q\n%s", state, out)
	}
}

// A check nobody calls is a check that does not exist: the extraction tests
// above would all still pass if check_time_sync were defined and never run.
func TestInstallRunsTheClockCheck(t *testing.T) {
	src, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	step := extractShellFunc(t, "step_system")
	if !strings.Contains(step, "check_time_sync") {
		t.Fatalf("step_system never calls check_time_sync:\n%s", step)
	}
	if strings.Count(string(src), "check_time_sync") < 2 {
		t.Fatal("check_time_sync is defined but never called")
	}
}
