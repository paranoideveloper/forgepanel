package upstream

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Lifecycle timings for a supervised zone.
const (
	// defaultStopTimeout is how long a zone gets to exit gracefully after
	// SIGTERM before the whole process group is SIGKILLed.
	defaultStopTimeout = 8 * time.Second
	// killGrace is the extra window allowed after SIGKILL for the kernel to
	// reap the group.
	killGrace = 3 * time.Second
	// waitDelay bounds cmd.Wait() when a grandchild keeps the log pipes open.
	waitDelay = 4 * time.Second
	// settleWindow is how long a freshly started zone is watched before it is
	// accepted; a binary that dies inside it is treated as a failed replacement.
	settleWindow = 900 * time.Millisecond
)

// This file holds the process half of the zone supervisor (§4c): the run/restart
// loop, the pre-start bind probe, and the small buffers the status view reads
// from. Manager.apply in manager.go decides WHAT should run; everything here is
// about keeping one already-decided process alive and observable.

// start launches the supervisor for this zone. It owns the cancel function and
// the done channel, so stop() can block until the process is genuinely gone.
func (p *proc) start(dir string) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.mu.Lock()
	p.cancel = cancel
	p.done = done
	p.stopping = false
	p.state = StateStarting
	p.mu.Unlock()
	go p.supervise(ctx, dir, done)
}

// supervise runs the binary and restarts it with exponential backoff until the
// context is cancelled. dir is both the config directory and the process CWD.
//
// It closes done when it returns, which is the contract stop() depends on: once
// done is closed the child has been reaped and its sockets released, so a
// replacement may safely bind the same port.
func (p *proc) supervise(ctx context.Context, dir string, done chan struct{}) {
	defer close(done)
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// Go's flag package treats -config and --config identically (§4c).
		cmd := exec.CommandContext(ctx, p.exe, "--config", p.cfgPath)
		cmd.Dir = dir
		// Own a process group so a binary that forks helpers cannot leave
		// orphans holding the zone's UDP port after the zone is stopped.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		// Graceful shutdown: SIGTERM the whole group on cancel, and let Go force
		// the issue if the child wedges or keeps the log pipes open.
		cmd.Cancel = func() error { return signalGroup(cmd.Process.Pid, syscall.SIGTERM) }
		cmd.WaitDelay = waitDelay
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			if ctx.Err() != nil {
				p.set(StateStopped, 0, "")
				return
			}
			p.set(StateCrashed, 0, err.Error())
			p.logf("zone=%s exe=%s state=crashed: start failed: %v", p.zone, p.exe, err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = minDur(backoff*2, maxBackoff)
			continue
		}
		pid := cmd.Process.Pid
		p.mu.Lock()
		p.state = StateRunning
		p.pid = pid
		p.pgid = pid
		p.restarts++
		p.lastErr = "" // recovered — clear any stale crash error
		p.mu.Unlock()
		p.logf("zone=%s exe=%s pid=%d state=running", p.zone, p.exe, pid)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.pump(stdout) }()
		go func() { defer wg.Done(); p.pump(stderr) }()

		err := cmd.Wait()
		wg.Wait() // drain the log pipes before looping or returning
		// Sweep any surviving group members; the leader is already reaped.
		_ = signalGroup(pid, syscall.SIGKILL)

		if ctx.Err() != nil {
			p.set(StateStopped, 0, "")
			p.logf("zone=%s pid=%d state=stopped: shutdown requested", p.zone, pid)
			return
		}
		msg := "exited"
		if err != nil {
			msg = err.Error()
		}
		if tail := p.logs.last(); tail != "" {
			msg += ": " + tail
		}
		p.set(StateCrashed, 0, msg)
		p.logf("zone=%s pid=%d state=crashed: %s", p.zone, pid, msg)
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = minDur(backoff*2, maxBackoff)
	}
}

func (p *proc) pump(r io.Reader) {
	if r == nil {
		return
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		p.logs.add(sc.Text())
	}
}

// stop shuts the zone down and does not return until the process is gone.
//
// This is load-bearing: Manager.apply starts a replacement immediately after,
// and a stop that returned early would race the old process for the zone's UDP
// port, producing "address already in use" crash-loops and orphaned children.
// Concurrent callers all wait on the same completion signal, and a process that
// ignores SIGTERM is escalated to a SIGKILL of its whole process group. The
// returned error describes an unclean shutdown; the zone is stopped either way.
func (p *proc) stop(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultStopTimeout
	}
	p.mu.Lock()
	cancel, done, pid, pgid := p.cancel, p.done, p.pid, p.pgid
	p.stopping = true
	if p.state == StateRunning || p.state == StateStarting {
		p.state = StateStopping
	}
	p.mu.Unlock()

	if cancel != nil {
		cancel() // triggers cmd.Cancel: SIGTERM to the process group
	}
	if done == nil {
		p.set(StateStopped, 0, "")
		return nil
	}

	var outcome error
	select {
	case <-done: // supervise returned => child reaped, sockets released
	case <-time.After(timeout):
		_ = signalGroup(pgid, syscall.SIGKILL)
		select {
		case <-done:
			outcome = fmt.Errorf("forgedns: zone %s (pid %d) ignored SIGTERM for %s and was force-killed",
				p.zone, pid, timeout)
		case <-time.After(killGrace):
			outcome = fmt.Errorf("forgedns: zone %s (pid %d) did not exit after SIGKILL", p.zone, pid)
		}
	}
	p.set(StateStopped, 0, "")
	if outcome != nil {
		p.logf("zone=%s pid=%d state=stopped: %v", p.zone, pid, outcome)
	} else {
		p.logf("zone=%s pid=%d state=stopped: clean shutdown", p.zone, pid)
	}
	return outcome
}

// waitSettled watches a freshly started zone for the settle window and reports
// an error if it never came up or died immediately, so a bad replacement can be
// rolled back instead of being left crash-looping.
func (p *proc) waitSettled(d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		switch p.snapshotState() {
		case StateRunning:
			// Keep watching for the rest of the window: a binary that rejects
			// its config often starts and then exits a few hundred ms later.
		case StateCrashed, StateError:
			p.mu.Lock()
			msg := p.lastErr
			p.mu.Unlock()
			if msg == "" {
				msg = "exited immediately after start"
			}
			return fmt.Errorf("%s", msg)
		}
		time.Sleep(30 * time.Millisecond)
	}
	if st := p.snapshotState(); st != StateRunning {
		p.mu.Lock()
		msg := p.lastErr
		p.mu.Unlock()
		if msg == "" {
			msg = fmt.Sprintf("did not reach running state within %s (state=%s)", d, st)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (p *proc) set(s State, pid int, err string) {
	p.mu.Lock()
	p.state = s
	p.pid = pid
	if err != "" {
		p.lastErr = err
	}
	p.mu.Unlock()
}

// logf records a lifecycle line in the zone's ring buffer, which is what the
// panel shows as RecentLogs.
func (p *proc) logf(format string, args ...any) {
	if p.logs != nil {
		p.logs.add(fmt.Sprintf(format, args...))
	}
}

func (p *proc) snapshotState() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *proc) snapshotPID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// signalGroup sends sig to the whole process group led by pgid. The manager only
// ever calls this with a pgid it started itself.
func signalGroup(pgid int, sig syscall.Signal) error {
	if pgid <= 0 {
		return nil
	}
	return syscall.Kill(-pgid, sig)
}

func (p *proc) status() ZoneStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := ZoneStatus{
		Zone: p.zone, Adapter: p.adapter, State: p.state, PID: p.pid,
		Tag: p.tag, Exe: p.exe, ConfigPath: p.cfgPath, Domains: p.domains,
		Listen: p.listen, DoTListen: p.dotListen, DoHListen: p.dohListen,
		HealthURL: p.healthURL, Restarts: p.restarts,
		LastError: p.lastErr,
	}
	if p.logs != nil {
		st.RecentLogs = p.logs.snapshot()
	}
	return st
}

// --- helpers --------------------------------------------------------------

// waitPortFree checks that the zone's UDP listen address can actually be bound,
// retrying briefly so a restart is not defeated by the old socket lingering.
// The two failure modes get their own message because the fixes differ (§4c).
func waitPortFree(host string, port int, attempts int, gap time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(gap)
		}
		last = probeUDP(host, port)
		if last == nil {
			return nil
		}
	}
	return last
}

// portHolderHint best-effort identifies which process holds udp/port, for the
// error message only.
//
// It is deliberately read-only. When the port is still busy after our own
// process has fully exited, the holder is by definition something this manager
// did not spawn, and signalling a PID we do not own could kill an unrelated
// service (systemd-resolved, another resolver, a second panel instance). The
// operator gets told what to look at instead.
func portHolderHint(port int) string {
	inodes := udpInodesForPort(port)
	if len(inodes) == 0 {
		return ""
	}
	pids, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, e := range pids {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue // not ours to inspect
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if !inodes[ino] {
				continue
			}
			name := "?"
			if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
				name = strings.TrimSpace(string(b))
			}
			return fmt.Sprintf(" — held by pid %d (%s), which ForgePanel did not start "+
				"and will not signal; stop it yourself or move this zone to another port", pid, name)
		}
	}
	return " — held by a process ForgePanel did not start and will not signal"
}

// udpInodesForPort returns the socket inodes bound to port from /proc/net/udp*.
func udpInodesForPort(port int) map[string]bool {
	out := map[string]bool{}
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			local := fields[1] // hex "ADDR:PORT"
			i := strings.LastIndex(local, ":")
			if i < 0 {
				continue
			}
			p, err := strconv.ParseInt(local[i+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			out[fields[9]] = true
		}
	}
	return out
}

// probeUDP binds and immediately releases the address. There is an unavoidable
// race between the probe and the child's own bind, but as a diagnostic it turns
// a silent crash-loop into an actionable message.
func probeUDP(host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	pc, err := net.ListenPacket("udp", addr)
	if err == nil {
		_ = pc.Close()
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return fmt.Errorf("cannot bind udp/%d: %v — ports below 1024 are privileged; "+
			"run the panel with CAP_NET_BIND_SERVICE or choose a high UDP port", port, err)
	case strings.Contains(msg, "address already in use"), strings.Contains(msg, "in use"):
		return fmt.Errorf("cannot bind %s: %v — something already holds this port. On a "+
			"systemd host that is usually systemd-resolved: set DNSStubListener=no in "+
			"/etc/systemd/resolved.conf, or bind this zone to the public IP instead of 0.0.0.0",
			addr, err)
	default:
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
}

// isWildcardHost reports whether host means "all interfaces", so a bind on it
// collides with any other listener already on the port — including a loopback
// stub resolver on 127.0.0.53:53.
func isWildcardHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0", "::", "[::]", "*":
		return true
	}
	return false
}

// loopbackStubHolds reports whether a loopback stub resolver — systemd-resolved
// on 127.0.0.53:port or 127.0.0.54:port — already holds the port. Such a listener
// makes a wildcard 0.0.0.0:port bind fail with "address already in use" even
// though the public address is free (this is the default state of a stock Ubuntu
// host). We probe the specific loopback stub addresses: "address already in use"
// means the stub is there; "cannot assign requested address" (the alias is not
// configured, i.e. no stub) or a clean bind means it is not.
func loopbackStubHolds(port int) bool {
	for _, ip := range []string{"127.0.0.53", "127.0.0.54"} {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			_ = pc.Close()
			continue
		}
		if strings.Contains(err.Error(), "in use") {
			return true
		}
	}
	return false
}

// primaryIPv4 returns the box's primary outbound IPv4 — the source address the
// kernel would use for a default-route connection. A UDP "dial" sends no packets;
// it only resolves the local address for that route, so it works even when the
// probed destination is unreachable or blocked.
func primaryIPv4() string {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// effectiveBindHost resolves the address a zone should actually bind. When the
// operator left the bind host as the wildcard but a loopback stub resolver
// (systemd-resolved) holds the port, binding the wildcard would fail; fall back
// to the primary public IPv4, which does not collide with the loopback listener.
// This lets the DNS tunnel come up on a stock systemd host without the operator
// having to set DNSStubListener=no. A non-wildcard host is always honored as-is,
// and a host with no stub conflict keeps the wildcard so the zone answers on
// every interface as before.
func effectiveBindHost(bindHost string, port int) string {
	if !isWildcardHost(bindHost) {
		return bindHost
	}
	if !loopbackStubHolds(port) {
		return bindHost
	}
	if ip := primaryIPv4(); ip != "" {
		return ip
	}
	return bindHost
}

// signature fingerprints the rendered config plus the binary path, so either a
// settings change or a version upgrade restarts the zone and nothing else does.
func signature(cfg, exe string) string {
	sum := sha256.Sum256([]byte(cfg + "\x00" + exe))
	return hex.EncodeToString(sum[:16])
}

// sanitize turns a zone name into a safe single path element.
func sanitize(zone string) string {
	z := normDomain(zone)
	var b strings.Builder
	for i := 0; i < len(z); i++ {
		c := z[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		out = "zone"
	}
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ring is a small fixed-size buffer of recent log lines.
type ring struct {
	mu   sync.Mutex
	buf  []string
	size int
}

func newRing(size int) *ring { return &ring{size: size} }

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, line)
	if len(r.buf) > r.size {
		r.buf = r.buf[len(r.buf)-r.size:]
	}
}

func (r *ring) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 20
	if len(r.buf) < n {
		n = len(r.buf)
	}
	out := make([]string, n)
	copy(out, r.buf[len(r.buf)-n:])
	return out
}

func (r *ring) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return ""
	}
	return r.buf[len(r.buf)-1]
}
