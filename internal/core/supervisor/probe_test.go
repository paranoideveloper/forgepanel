package supervisor

// A core that is UP but not answering is the failure the supervisor could not
// see. Everything here keyed off the process table: cmd.Wait() returns, so the
// process crashed. A core whose gRPC API has stopped scheduling — a wedged
// event loop, a config that made it stop accepting, an OOM-throttled box —
// never exits, so it stayed "running" forever while serving nobody, and the
// panel reported it green.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCore stands in for a real core: it answers `version`, accepts any config
// offered to `-test`, and then stays alive until it is signalled — which is
// exactly the shape of a wedged engine.
const fakeCore = `#!/bin/sh
case "$1" in
  version|-version) echo "fake-core 9.9.9"; exit 0 ;;
esac
for a in "$@"; do
  if [ "$a" = "-test" ] || [ "$a" = "check" ]; then exit 0; fi
done
echo "fake-core started" 1>&2
while true; do sleep 1; done
`

func writeFakeCore(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(fakeCore), 0o755); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestAWedgedCoreIsReportedUnresponsive(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakecore")
	writeFakeCore(t, bin)

	p := NewProcess(EngineSpec{
		Name:       "xray",
		BinPath:    bin,
		RunArgs:    []string{"run", "-c"},
		TestArgs:   []string{"run", "-test", "-c"},
		ConfigPath: filepath.Join(dir, "xray.json"),
		// The core is alive and answers nothing, which is the whole point.
		Probe:         func(context.Context) error { return errors.New("api not answering") },
		ProbeEvery:    20 * time.Millisecond,
		ProbeTimeout:  10 * time.Millisecond,
		ProbeFailures: 2,
	})
	t.Cleanup(p.Stop)
	if err := p.Apply([]byte("{}")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool { return p.Status().State == StateRunning },
		"the fake core never reached running")

	var seen Status
	waitUntil(t, 5*time.Second, func() bool {
		if st := p.Status(); st.State == StateUnresponsive {
			seen = st
			return true
		}
		return false
	}, "a core that never answered its probe stayed running: the supervisor only notices a core that EXITS")

	if !strings.Contains(seen.LastProbeError, "api not answering") {
		t.Errorf("LastProbeError = %q, want the probe's own error — an operator has to be told WHY it is wedged", seen.LastProbeError)
	}
	if seen.Responsive == nil || *seen.Responsive {
		t.Errorf("Responsive = %v, want a non-nil false", seen.Responsive)
	}
	// Relabelling it is not enough: a wedged core has to be restarted, or the
	// panel is merely a more accurate way of serving nobody.
	waitUntil(t, 5*time.Second, func() bool { return p.Status().Restarts >= 2 },
		"the wedged core was labelled unresponsive but never restarted")
}

// A core that answers must not be restarted, and must not be labelled: the
// probe's failure mode is a false positive that restarts a healthy core every
// ProbeEvery, which is worse than the bug it fixes.
func TestAHealthyCoreIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakecore")
	writeFakeCore(t, bin)

	p := NewProcess(EngineSpec{
		Name:          "xray",
		BinPath:       bin,
		RunArgs:       []string{"run", "-c"},
		TestArgs:      []string{"run", "-test", "-c"},
		ConfigPath:    filepath.Join(dir, "xray.json"),
		Probe:         func(context.Context) error { return nil },
		ProbeEvery:    20 * time.Millisecond,
		ProbeTimeout:  time.Second,
		ProbeFailures: 2,
	})
	t.Cleanup(p.Stop)
	if err := p.Apply([]byte("{}")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool { return p.Status().State == StateRunning },
		"the fake core never reached running")
	starts := p.Status().Restarts

	waitUntil(t, 5*time.Second, func() bool {
		st := p.Status()
		return st.Responsive != nil && *st.Responsive
	}, "a core answering its probe was never marked responsive")

	time.Sleep(300 * time.Millisecond) // ~15 probe ticks
	if st := p.Status(); st.State != StateRunning || st.Restarts != starts {
		t.Errorf("healthy core got state=%q restarts=%d (was %d): the probe is killing a core that answers",
			st.State, st.Restarts, starts)
	}
}

// No probe means exactly today's behaviour: every adapter that has not been
// given one must keep running untouched, and must report "never probed" rather
// than "not responsive".
func TestWithoutAProbeNothingChanges(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakecore")
	writeFakeCore(t, bin)

	p := NewProcess(EngineSpec{
		Name:       "xray",
		BinPath:    bin,
		RunArgs:    []string{"run", "-c"},
		TestArgs:   []string{"run", "-test", "-c"},
		ConfigPath: filepath.Join(dir, "xray.json"),
	})
	t.Cleanup(p.Stop)
	if err := p.Apply([]byte("{}")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool { return p.Status().State == StateRunning },
		"the fake core never reached running")
	time.Sleep(200 * time.Millisecond)
	st := p.Status()
	if st.State != StateRunning {
		t.Errorf("state = %q, want running: a core with no probe must be left exactly as it was", st.State)
	}
	if st.Responsive != nil {
		t.Errorf("Responsive = %v, want nil (never probed)", *st.Responsive)
	}
}
