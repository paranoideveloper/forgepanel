package upstream

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file holds the process half of the zone supervisor (§4c): the run/restart
// loop, the pre-start bind probe, and the small buffers the status view reads
// from. Manager.apply in manager.go decides WHAT should run; everything here is
// about keeping one already-decided process alive and observable.

// supervise runs the binary and restarts it with exponential backoff until the
// context is cancelled. dir is both the config directory and the process CWD.
func (p *proc) supervise(ctx context.Context, dir string) {
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// Go's flag package treats -config and --config identically (§4c).
		cmd := exec.CommandContext(ctx, p.exe, "--config", p.cfgPath)
		cmd.Dir = dir
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			p.set(StateCrashed, 0, err.Error())
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = minDur(backoff*2, maxBackoff)
			continue
		}
		p.mu.Lock()
		p.state = StateRunning
		p.pid = cmd.Process.Pid
		p.restarts++
		p.mu.Unlock()
		go p.pump(stdout)
		go p.pump(stderr)

		err := cmd.Wait()
		if ctx.Err() != nil {
			p.set(StateStopped, 0, "")
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

func (p *proc) stop() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.set(StateStopped, 0, "")
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

func (p *proc) snapshotState() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *proc) status() ZoneStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := ZoneStatus{
		Zone: p.zone, Adapter: p.adapter, State: p.state, PID: p.pid,
		Tag: p.tag, Exe: p.exe, ConfigPath: p.cfgPath, Domains: p.domains,
		Listen: p.listen, HealthURL: p.healthURL, Restarts: p.restarts,
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
