package upstream

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// holderBinary returns a command that binds the UDP port given as its argument
// and then blocks, standing in for an upstream DNS server holding :53.
func holderBinary(t *testing.T, dir string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable; cannot stand up a port-holding child")
	}
	script := filepath.Join(dir, "hold.py")
	body := "import socket,sys,time\n" +
		"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n" +
		"s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n" +
		"s.bind(('127.0.0.1',int(sys.argv[1])))\n" +
		"while True: time.sleep(0.2)\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return py + " " + script
}

// The tests below drive the zone process supervisor with throwaway shell scripts
// standing in for a real upstream DNS binary, because every defect they cover is
// about process lifecycle rather than about DNS.

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// alive reports whether a pid still exists.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// launch starts a supervised proc running exe and waits for it to be running.
func launch(t *testing.T, dir, exe string) *proc {
	t.Helper()
	p := &proc{
		zone: "t.example.com", adapter: "test", exe: exe,
		cfgPath: filepath.Join(dir, "server_config.toml"),
		state:   StateStopped, logs: newRing(50),
	}
	if err := os.WriteFile(p.cfgPath, []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.start(dir)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.snapshotState() == StateRunning && p.snapshotPID() > 0 {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process never reached running state (state=%s)", p.snapshotState())
	return nil
}

// TestStopWaitsForProcessExit is the core regression: stop() must not return
// until the process is actually gone, because Manager.apply immediately starts a
// replacement that needs to bind the same UDP port.
func TestStopWaitsForProcessExit(t *testing.T) {
	dir := t.TempDir()
	exe := writeScript(t, dir, "slow.sh", `while :; do sleep 0.1; done`)
	p := launch(t, dir, exe)
	pid := p.snapshotPID()

	if err := p.stop(5 * time.Second); err != nil {
		t.Fatalf("graceful stop reported an error: %v", err)
	}
	if alive(pid) {
		t.Fatalf("stop() returned while pid %d was still running", pid)
	}
	if st := p.snapshotState(); st != StateStopped {
		t.Fatalf("state after stop = %s, want %s", st, StateStopped)
	}
}

// TestStopReleasesPortBeforeReturning proves the invariant Manager.apply relies
// on: once stop() returns, the port the child held can be bound again.
func TestStopReleasesPortBeforeReturning(t *testing.T) {
	// Pick a free UDP port, then have the child hold it.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	dir := t.TempDir()
	// `nc` is not guaranteed present; hold the socket with a tiny shell+exec on
	// /dev/udp is not possible either, so use a Go helper process instead.
	exe := writeScript(t, dir, "hold.sh",
		"exec "+holderBinary(t, dir)+" "+strconv.Itoa(port))
	p := launch(t, dir, exe)

	// Confirm the port really is taken while the child runs. The child needs a
	// moment after exec to reach its bind() call.
	bound := false
	for i := 0; i < 100; i++ {
		c, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			bound = true
			break
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if !bound {
		t.Skip("child never bound the port; environment-dependent")
	}

	if err := p.stop(5 * time.Second); err != nil {
		t.Fatalf("stop: %v", err)
	}
	c, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port still held after stop() returned: %v", err)
	}
	c.Close()
}

// TestSlowShutdownIsForceKilled: a process that ignores SIGTERM must still be
// reaped, within the timeout, and the outcome must be reported rather than
// silently swallowed.
func TestSlowShutdownIsForceKilled(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "stubborn.ready")
	exe := writeScript(t, dir, "stubborn.sh", "trap '' TERM\n: > "+ready+"\nwhile :; do sleep 0.1; done")
	p := launch(t, dir, exe)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("stubborn process never installed its SIGTERM trap: %v", err)
	}
	pid := p.snapshotPID()

	start := time.Now()
	err := p.stop(500 * time.Millisecond)
	elapsed := time.Since(start)

	if alive(pid) {
		t.Fatalf("pid %d survived a forced stop", pid)
	}
	if err == nil {
		t.Fatal("forced kill must be reported as an error, got nil")
	}
	if !strings.Contains(err.Error(), "force") && !strings.Contains(err.Error(), "kill") {
		t.Fatalf("unhelpful shutdown error: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("stop took %s, timeout was not enforced", elapsed)
	}
}

// TestConcurrentStopIsSafe: overlapping stop() calls must all block until the
// process is gone, and none may panic or return early.
func TestConcurrentStopIsSafe(t *testing.T) {
	dir := t.TempDir()
	exe := writeScript(t, dir, "slow.sh", `while :; do sleep 0.1; done`)
	p := launch(t, dir, exe)
	pid := p.snapshotPID()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.stop(5 * time.Second)
			if alive(pid) {
				t.Errorf("stop() returned while pid %d still alive", pid)
			}
		}()
	}
	wg.Wait()
}

// TestIntentionalStopDoesNotRestart: cancelling the supervisor must not be
// mistaken for a crash and trigger the restart loop.
func TestIntentionalStopDoesNotRestart(t *testing.T) {
	dir := t.TempDir()
	exe := writeScript(t, dir, "slow.sh", `while :; do sleep 0.1; done`)
	p := launch(t, dir, exe)

	p.mu.Lock()
	before := p.restarts
	p.mu.Unlock()

	if err := p.stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // longer than the initial 500ms backoff

	p.mu.Lock()
	after, state := p.restarts, p.state
	p.mu.Unlock()
	if after != before {
		t.Fatalf("intentional stop triggered %d restart(s)", after-before)
	}
	if state != StateStopped {
		t.Fatalf("state drifted after intentional stop: %s", state)
	}
}

// TestNoSupervisorGoroutineRemainsAfterStop: the supervise goroutine must have
// returned, which is what makes stop()'s wait meaningful.
func TestNoSupervisorGoroutineRemainsAfterStop(t *testing.T) {
	dir := t.TempDir()
	exe := writeScript(t, dir, "slow.sh", `while :; do sleep 0.1; done`)
	p := launch(t, dir, exe)
	if err := p.stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	select {
	case <-done:
	default:
		t.Fatal("supervise goroutine still running after stop() returned")
	}
}

// TestChildProcessGroupIsTerminated: upstream binaries fork helpers; stopping a
// zone must not leave orphans holding the port.
func TestChildProcessGroupIsTerminated(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	exe := writeScript(t, dir, "parent.sh",
		"sh -c 'while :; do sleep 0.2; done' &\n"+
			"echo $! > "+pidFile+"\n"+
			"while :; do sleep 0.2; done")
	p := launch(t, dir, exe)

	var childPID int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidFile); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				childPID = n
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPID == 0 {
		t.Skip("child pid never recorded; shell-dependent")
	}

	if err := p.stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	// Give the kernel a moment to deliver the group signal.
	for i := 0; i < 50 && alive(childPID); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if alive(childPID) {
		t.Fatalf("grandchild pid %d leaked after zone stop", childPID)
	}
}

// TestForeignPortHolderIsReportedNotKilled: when an unrelated process owns the
// port, the manager must report it and fail the reload — never signal a PID it
// did not spawn.
func TestForeignPortHolderIsReportedNotKilled(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	err = waitPortFree("127.0.0.1", port, 2, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected a bind failure while the port is held")
	}
	// The listener must be untouched: we can still use it.
	if _, werr := pc.WriteTo([]byte("x"), pc.LocalAddr()); werr != nil {
		t.Fatalf("foreign listener was disturbed: %v", werr)
	}
	hint := portHolderHint(port)
	t.Logf("holder hint: %q", hint)
}

// TestRepeatedRapidReloadsDoNotConflict: stop/start cycles in quick succession
// must never collide on the port.
func TestRepeatedRapidReloadsDoNotConflict(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	dir := t.TempDir()
	helper := holderBinary(t, dir)
	exe := writeScript(t, dir, "hold.sh", "exec "+helper+" "+strconv.Itoa(port))

	for i := 0; i < 5; i++ {
		p := launch(t, dir, exe)
		if err := p.stop(5 * time.Second); err != nil {
			t.Fatalf("cycle %d: stop: %v", i, err)
		}
		if err := waitPortFree("127.0.0.1", port, 10, 50*time.Millisecond); err != nil {
			t.Fatalf("cycle %d: port not free after stop: %v", i, err)
		}
	}
}

func TestIsWildcardHost(t *testing.T) {
	for _, h := range []string{"", "0.0.0.0", "::", "[::]", "*", "  0.0.0.0  "} {
		if !isWildcardHost(h) {
			t.Errorf("isWildcardHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "1.2.3.4", "192.168.1.1", "example.com"} {
		if isWildcardHost(h) {
			t.Errorf("isWildcardHost(%q) = true, want false", h)
		}
	}
}

func TestEffectiveBindHostHonorsExplicitHost(t *testing.T) {
	// A non-wildcard host is returned unchanged with no probing or fallback, so an
	// operator who deliberately pinned a bind address always gets exactly it.
	if got := effectiveBindHost("203.0.113.7", 53); got != "203.0.113.7" {
		t.Fatalf("effectiveBindHost(explicit) = %q, want 203.0.113.7", got)
	}
}
