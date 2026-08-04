// Package supervisor manages the proxy-core child processes (spec §6): it
// validates a generated config before applying it, launches the core, watches
// health, restarts with exponential backoff on crash, captures the last lines of
// stderr, and hot-reloads on config change. It never applies a config the core
// itself rejects, so a bad edit can never take the panel's traffic down.
package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// State is a supervised process's lifecycle state.
type State string

const (
	StateStopped State = "stopped"
	StateRunning State = "running"
	StateCrashed State = "crashed"
	StateInvalid State = "invalid_config"
)

// EngineSpec describes how to validate and run one core.
type EngineSpec struct {
	Name       string   // "xray" | "sing-box"
	BinPath    string   // resolved binary path
	RunArgs    []string // args to run with a config, e.g. ["run","-c"] or ["run","-c"]
	TestArgs   []string // args to validate a config, e.g. ["run","-test","-c"] / ["check","-c"]
	ConfigPath string   // where the config file is written
}

// Process supervises one EngineSpec.
type Process struct {
	spec EngineSpec

	mu       sync.Mutex
	cmd      *exec.Cmd
	state    State
	lastErr  string
	restarts int
	logs     *ring
	cancel   context.CancelFunc
	done     chan struct{} // closed when the current supervise goroutine exits
}

// NewProcess creates a supervised process (not started).
func NewProcess(spec EngineSpec) *Process {
	return &Process{spec: spec, state: StateStopped, logs: newRing(200)}
}

// Validate runs "<bin> <testArgs> <config>" against a candidate config file and
// returns the engine's own verdict. This is the §18 gate (`xray run -test`,
// `sing-box check`).
func (p *Process) Validate(configPath string) error {
	args := append(append([]string{}, p.spec.TestArgs...), configPath)
	out, err := exec.Command(p.spec.BinPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s rejected config: %s", p.spec.Name, tail(string(out)))
	}
	return nil
}

// Apply validates newConfig, and if valid writes it to the spec's ConfigPath and
// (re)starts the process. If validation fails the running process is untouched.
func (p *Process) Apply(newConfig []byte) error {
	// The candidate path must keep a .json extension: Xray infers the config
	// format from the file extension and rejects an unrecognised one.
	tmp := p.spec.ConfigPath + ".candidate.json"
	if err := os.MkdirAll(filepath.Dir(p.spec.ConfigPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, newConfig, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := p.Validate(tmp); err != nil {
		p.setState(StateInvalid, err.Error())
		return err
	}
	if err := os.Rename(tmp, p.spec.ConfigPath); err != nil {
		return err
	}
	return p.restart()
}

// Start launches the process using the already-written config.
func (p *Process) Start() error { return p.restart() }

func (p *Process) restart() error {
	p.Stop() // blocks until the previous process is fully reaped (port released)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.mu.Lock()
	p.cancel = cancel
	p.done = done
	p.mu.Unlock()
	go p.supervise(ctx, done)
	return nil
}

// supervise runs the process and restarts it with exponential backoff on crash,
// until the context is cancelled (Stop). It closes done when it returns so Stop
// can block until the process is fully reaped and its listening ports released.
func (p *Process) supervise(ctx context.Context, done chan struct{}) {
	defer close(done)
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		args := append(append([]string{}, p.spec.RunArgs...), p.spec.ConfigPath)
		cmd := exec.CommandContext(ctx, p.spec.BinPath, args...)
		// Graceful shutdown on ctx cancel: SIGTERM first, then Go force-kills after
		// WaitDelay if the core ignores it. Crucially, Wait() (below) does not
		// return until the process is reaped, so Stop() -> <-done guarantees the
		// old process released its sockets before the next start binds them.
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 4 * time.Second
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			p.setState(StateCrashed, err.Error())
			if !p.sleep(ctx, backoff) {
				return
			}
			backoff = min2(backoff*2, maxBackoff)
			continue
		}
		p.mu.Lock()
		p.cmd = cmd
		p.state = StateRunning
		p.lastErr = "" // recovered — clear any stale crash error
		p.restarts++
		p.mu.Unlock()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.pump(stderr) }()
		go func() { defer wg.Done(); p.pump(stdout) }()

		err := cmd.Wait()
		wg.Wait() // drain log pipes before looping/returning
		if ctx.Err() != nil {
			p.setState(StateStopped, "")
			return
		}
		msg := "exited"
		if err != nil {
			msg = err.Error() + logHint(p.logs)
		}
		p.setState(StateCrashed, msg)
		if !p.sleep(ctx, backoff) {
			return
		}
		backoff = min2(backoff*2, maxBackoff)
	}
}

// logHint appends the last stderr line to a crash error so the panel surfaces the
// engine's own reason (e.g. "address already in use") instead of a bare exit code.
func logHint(logs *ring) string {
	lines := logs.snapshot()
	for i := len(lines) - 1; i >= 0; i-- {
		if s := lines[i]; s != "" {
			return ": " + tail(s)
		}
	}
	return ""
}

func (p *Process) pump(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		p.logs.add(sc.Text())
	}
}

func (p *Process) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Stop terminates the process and stops supervising. It BLOCKS until the process
// is fully reaped so its listening ports are released before any subsequent
// start binds them — this is what makes hot-reload reliable (previously the new
// process raced the dying one for the port and failed with "address already in
// use", taking the whole engine down on every reload).
func (p *Process) Stop() {
	p.mu.Lock()
	cancel := p.cancel
	done := p.done
	p.cancel = nil
	p.done = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel() // triggers cmd.Cancel (SIGTERM) + WaitDelay force-kill in supervise
	}
	if done != nil {
		select {
		case <-done: // supervise returned => process reaped, sockets released
		case <-time.After(8 * time.Second):
			// Safety net: force-kill if graceful shutdown wedged, then wait.
			p.mu.Lock()
			cmd := p.cmd
			p.mu.Unlock()
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-done
		}
	}
	p.setState(StateStopped, "")
}

// Status snapshots the process state.
func (p *Process) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	pid := 0
	if p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	return Status{
		Engine: p.spec.Name, State: p.state, PID: pid,
		Restarts: p.restarts, LastError: p.lastErr, RecentLogs: p.logs.snapshot(),
	}
}

// Status is a snapshot of a supervised process.
type Status struct {
	Engine     string   `json:"engine"`
	State      State    `json:"state"`
	PID        int      `json:"pid"`
	Restarts   int      `json:"restarts"`
	LastError  string   `json:"last_error,omitempty"`
	RecentLogs []string `json:"recent_logs,omitempty"`
}

func (p *Process) setState(s State, err string) {
	p.mu.Lock()
	p.state = s
	if err != "" {
		p.lastErr = err
	}
	p.mu.Unlock()
}

func min2(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func tail(s string) string {
	const max = 400
	if len(s) > max {
		return "…" + s[len(s)-max:]
	}
	return s
}

// ring is a fixed-size ring buffer of recent log lines.
type ring struct {
	mu   sync.Mutex
	buf  []string
	n    int
	size int
}

func newRing(size int) *ring { return &ring{size: size} }

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < r.size {
		r.buf = append(r.buf, line)
	} else {
		r.buf[r.n%r.size] = line
	}
	r.n++
}

func (r *ring) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	last := 20
	if len(r.buf) < last {
		last = len(r.buf)
	}
	out := make([]string, 0, last)
	for i := len(r.buf) - last; i < len(r.buf); i++ {
		if i >= 0 {
			out = append(out, r.buf[i])
		}
	}
	return out
}

// ValidateBytes writes candidate config to path and runs the engine validator on
// it, without applying it. Used by Config Doctor.
func (p *Process) ValidateBytes(cfg []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	defer os.Remove(path)
	return p.Validate(path)
}
