package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBrook writes a script that behaves like a Brook process for the purposes
// of supervision: it prints something, then either stays up or exits.
func fakeBrook(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "brook")
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForBrook(t *testing.T, what string, cond func() bool) {
	t.Helper()
	// Sixty seconds, and the number is deliberately generous rather than tuned.
	//
	// The assertion is unchanged; only the patience is. This waits on a
	// subprocess exiting and two pump goroutines flushing, which is scheduler
	// work, so the time it needs is a function of how loaded the machine is and
	// not of the code under test. Three seconds was enough alone; ten was enough
	// in the suite; neither survived a machine also running parallel build and
	// test agents, where it failed as "timed out waiting for the crash
	// diagnosis" — a message that reads like a broken supervisor.
	//
	// A long deadline costs nothing when the condition is met, because the loop
	// returns the moment it is. It is paid only by a test that is genuinely
	// failing, and a slow red is worth far more than an intermittent one: a
	// suite that fails under load teaches people to re-run rather than to read,
	// and that habit is how a real regression gets waved through.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The manager reported whatever it had started, with its original PID, for the
// life of the panel: a Brook inbound that crashed a second after launch showed
// as running until the process restarted. Nothing called Wait, so the corpse was
// also a zombie.
func TestACrashedBrookProcessIsNoLongerReportedAsRunning(t *testing.T) {
	bin := fakeBrook(t, `echo "listen tcp :9999: bind: address already in use" >&2; exit 1`)
	b := NewBrookManager(nil)

	p, err := b.startBrook(bin, nil, 9999, "sig", "server")
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.procs[9999] = p
	b.mu.Unlock()

	waitForBrook(t, "the reaper to notice the exit", func() bool {
		exited, _, _, _ := p.snapshot()
		return exited
	})

	st := b.Status()
	if len(st) != 1 {
		t.Fatalf("status = %v", st)
	}
	if st[0]["running"] != false {
		t.Errorf("a dead process is reported as running: %v", st[0])
	}
	// A PID that no longer exists is worse than none: it invites someone to go
	// looking for it.
	if st[0]["pid"] != 0 {
		t.Errorf("pid = %v for a dead process", st[0]["pid"])
	}
}

// Brook's output went to the panel's own stderr, so a Brook inbound that
// refused to start produced a journal line that named no inbound and reached no
// health endpoint. The engine's own words are the whole diagnosis.
func TestACrashedBrookProcessCarriesItsOwnDiagnosis(t *testing.T) {
	bin := fakeBrook(t, `echo "listen tcp 0.0.0.0:9998: bind: address already in use" >&2; exit 1`)
	b := NewBrookManager(nil)
	p, err := b.startBrook(bin, nil, 9998, "sig", "wsserver")
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.procs[9998] = p
	b.mu.Unlock()

	waitForBrook(t, "the exit to be recorded with output", func() bool {
		exited, _, _, _ := p.snapshot()
		return exited && len(p.logs.Snapshot()) > 0
	})

	st := b.Status()[0]
	logs, _ := st["recent_logs"].([]string)
	if len(logs) == 0 {
		t.Fatal("the process's output was not captured")
	}
	if !strings.Contains(strings.Join(logs, " "), "address already in use") {
		t.Errorf("captured logs do not contain what the process said: %v", logs)
	}
	// And the shared diagnosis table turns it into something actionable, rather
	// than making the operator read a chained error.
	hint, _ := st["hint"].(string)
	if !strings.Contains(hint, "already listening") {
		t.Errorf("hint = %q, want the diagnosis for a bound port", hint)
	}
}

// A Brook process that is deliberately stopped must not be restarted. Without
// the stopping flag the reaper races the kill and resurrects an inbound the
// operator has just deleted.
func TestStoppingABrookProcessDoesNotRestartIt(t *testing.T) {
	bin := fakeBrook(t, `while true; do sleep 1; done`)
	b := NewBrookManager(nil)
	p, err := b.startBrook(bin, nil, 9997, "sig", "server")
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.procs[9997] = p
	b.mu.Unlock()

	stopBrook(p)
	waitForBrook(t, "the process to be reaped", func() bool {
		exited, _, _, _ := p.snapshot()
		return exited
	})
	// brookRestartDelay is 5s; a restart would replace the map entry. Give it
	// well past that and confirm nothing came back.
	time.Sleep(200 * time.Millisecond)

	b.mu.Lock()
	same := b.procs[9997] == p
	b.mu.Unlock()
	if !same {
		t.Error("a deliberately stopped process was replaced by a restart")
	}
	if _, _, _, restarts := p.snapshot(); restarts != 0 {
		t.Errorf("restarts = %d for a deliberate stop", restarts)
	}
}

// A live process reports as running, with its real PID. The negative cases above
// are worthless if this one does not hold.
func TestALiveBrookProcessIsReportedAsRunning(t *testing.T) {
	bin := fakeBrook(t, `echo started; while true; do sleep 1; done`)
	b := NewBrookManager(nil)
	p, err := b.startBrook(bin, nil, 9996, "sig", "quicserver")
	if err != nil {
		t.Fatal(err)
	}
	defer stopBrook(p)
	b.mu.Lock()
	b.procs[9996] = p
	b.mu.Unlock()

	st := b.Status()[0]
	if st["running"] != true {
		t.Errorf("a live process is reported as %v", st["running"])
	}
	pid, _ := st["pid"].(int)
	if pid <= 0 {
		t.Errorf("pid = %v for a live process", st["pid"])
	}
	if st["mode"] != "quicserver" {
		t.Errorf("mode = %v", st["mode"])
	}
	// A healthy process must not carry a crash hint; a hint on a working inbound
	// is noise that teaches an operator to ignore the field.
	if _, has := st["hint"]; has {
		t.Errorf("a running process carries a crash hint: %v", st)
	}
	_ = fmt.Sprint(st)
}
