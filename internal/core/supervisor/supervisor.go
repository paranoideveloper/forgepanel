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
	"sync/atomic"
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
	// StateUnresponsive means the process is ALIVE and no longer answering its
	// own API. Deliberately not StateCrashed: nothing exited, which is exactly
	// why the condition went unseen — every signal the supervisor had was
	// derived from the process table, and a wedged core keeps that happy while
	// it serves nobody.
	StateUnresponsive State = "unresponsive"
)

// Liveness-probe defaults, used when an EngineSpec leaves them at zero.
//
// 30s/5s/3 is chosen to be quiet: a probe is a question asked of a core that is
// carrying traffic, and three consecutive misses over a minute and a half is a
// wedged core, where one miss is a busy one.
const (
	probeDefaultEvery    = 30 * time.Second
	probeDefaultTimeout  = 5 * time.Second
	probeDefaultFailures = 3
)

// EngineSpec describes how to validate and run one core.
type EngineSpec struct {
	Name       string   // "xray" | "sing-box"
	BinPath    string   // resolved binary path
	RunArgs    []string // args to run with a config, e.g. ["run","-c"] or ["run","-c"]
	TestArgs   []string // args to validate a config, e.g. ["run","-test","-c"] / ["check","-c"]
	ConfigPath string   // where the config file is written

	// OnLine, if set, receives every line the engine writes.
	//
	// This is how connection metadata reaches the presence tracker without a
	// log file: Xray's access log is pointed at stdout, which this process
	// already reads, so there is nothing to rotate and nothing growing on disk.
	// It runs on the log-pump goroutine and MUST NOT block or panic — doing
	// either takes the engine's output, and therefore its crash diagnostics,
	// with it.
	OnLine func(string)

	// HotApply, if set, is offered the old and new configs before Apply falls
	// back to restarting the process. Returning true means the change was
	// applied to the RUNNING core and no restart is needed.
	//
	// This exists because every user mutation — creating one customer, disabling
	// one account — restarted every core and dropped every other user's
	// connections with it. On a panel with real traffic that is an outage per
	// edit.
	//
	// It is offered the raw configs rather than a diff so the decision of "is
	// this change hot-appliable" belongs to the engine that knows, and so a
	// change it does not understand can safely decline.
	HotApply func(oldCfg, newCfg []byte) (bool, error)

	// Probe, if set, is asked whether the RUNNING core is actually answering.
	//
	// Nil means no probe, which is precisely the behaviour this supervisor had
	// before: a core was healthy for as long as its process existed. That is not
	// the same question. A core with a wedged event loop, or one that came up
	// and never finished starting, never exits — so cmd.Wait() never returns,
	// the state stays "running", and the panel reports green for a box serving
	// nobody until an operator notices by hand.
	//
	// It is supplied by the caller rather than built here because only the
	// caller knows what "answering" means for its core: for Xray it is the local
	// gRPC stats API, for sing-box it is an API that may not exist in the
	// installed build at all. It runs on its own goroutine, under ProbeTimeout,
	// and a panic in it is contained.
	Probe func(ctx context.Context) error

	// ProbeEvery is the interval between probes (0 => probeDefaultEvery), and
	// ProbeTimeout how long one may take (0 => probeDefaultTimeout). The cadence
	// is INDEPENDENT of cmd.Wait(): the failure being watched for is a core that
	// never exits.
	ProbeEvery   time.Duration
	ProbeTimeout time.Duration

	// ProbeFailures is how many CONSECUTIVE probes must fail before the core is
	// declared unresponsive and restarted (0 => probeDefaultFailures). More than
	// one is required because the cost of a false positive is dropping every
	// live connection on the box.
	ProbeFailures int

	// Env is added to the engine process's environment.
	//
	// This is how XRAY_LOCATION_ASSET reaches the core. Without it, Xray falls
	// back to searching /usr/local/share/xray and /usr/share/xray, so a panel
	// whose own geodata is current would silently use whatever version an
	// unrelated system-wide install left behind — or find none at all and refuse
	// every config containing a geosite: rule.
	Env []string
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

	// Liveness-probe state, all under p.mu. probed distinguishes "never asked"
	// from "asked and it said no", which is the difference between a core with
	// no probe configured and a core that is failing one.
	probed       bool
	responsive   bool
	lastProbeErr string
	// probeKill records that the probe, not the core, ended the last run — so
	// the exit is reported as what it is rather than as a crash.
	probeKill bool

	done chan struct{} // closed when the current supervise goroutine exits

	// observerDead is set when the OnLine hook panics, retiring it for the life
	// of this Process rather than letting it panic on every subsequent line.
	observerDead atomic.Bool
}

// NewProcess creates a supervised process (not started).
func NewProcess(spec EngineSpec) *Process {
	return &Process{spec: spec, state: StateStopped, logs: newRing(200)}
}

// Validate runs "<bin> <testArgs> <config>" against a candidate config file and
// returns the engine's own verdict. This is the §18 gate (`xray run -test`,
// `sing-box check`).
// validateEnv mirrors the run environment. A config validated WITHOUT the
// geodata path and then run WITH it (or the reverse) would pass one and fail the
// other, which is the worst possible split: the panel says the config is good
// and the core refuses it.
func (p *Process) validateEnv() []string {
	if len(p.spec.Env) == 0 {
		return nil
	}
	return append(os.Environ(), p.spec.Env...)
}

func (p *Process) Validate(configPath string) error {
	args := append(append([]string{}, p.spec.TestArgs...), configPath)
	cmd := exec.Command(p.spec.BinPath, args...)
	cmd.Env = p.validateEnv()
	out, err := cmd.CombinedOutput()
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

	// Read the live config BEFORE it is replaced: it is the only record of what
	// the running process is actually serving, and the hot path needs both sides
	// to work out what changed. A read failure is not fatal — it just means no
	// hot apply, which is the behaviour that was there before.
	old, oldErr := os.ReadFile(p.spec.ConfigPath)

	// The config is written FIRST, so that whatever happens next the file on
	// disk matches what the core should be serving. If a hot apply succeeds and
	// the process later crashes, the supervisor restarts it from this file and
	// the users are still there; if the order were reversed, a crash between the
	// two would silently revert the change.
	if err := os.Rename(tmp, p.spec.ConfigPath); err != nil {
		return err
	}

	if p.spec.HotApply != nil && oldErr == nil && p.Status().State == StateRunning {
		applied, err := p.hotApply(old, newConfig)
		if err != nil {
			// Fall through to a restart: a hot apply that half-worked leaves the
			// core disagreeing with its own config, and a restart is the one
			// action that always reconciles them. Recorded so an operator can
			// see WHY the restart happened rather than wondering.
			p.logs.add("[forgepanel] hot apply failed, restarting: " + err.Error())
		} else if applied {
			return nil
		}
	}
	return p.restart()
}

// hotApply calls the engine's hook, containing any panic.
//
// A panic here would otherwise take down the goroutine applying a reload, and
// the panel would report neither success nor failure for the change.
func (p *Process) hotApply(old, next []byte) (applied bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			applied = false
			err = fmt.Errorf("hot apply panicked: %v", r)
		}
	}()
	return p.spec.HotApply(old, next)
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
		if len(p.spec.Env) > 0 {
			cmd.Env = append(os.Environ(), p.spec.Env...)
		}
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
		// procDone bounds the probe to THIS launch. Deliberately not part of wg:
		// wg is drained before the loop may iterate, and the probe loop is what
		// waits on the process rather than the other way round. Without a
		// per-launch signal every restart would leave a probe goroutine behind,
		// each of them signalling a process it no longer owns.
		procDone := make(chan struct{})
		go p.probeLoop(ctx, cmd, procDone)

		err := cmd.Wait()
		close(procDone)
		wg.Wait() // drain log pipes before looping/returning
		if ctx.Err() != nil {
			p.setState(StateStopped, "")
			return
		}
		msg := "exited"
		if err != nil {
			msg = err.Error() + logHint(p.logs)
		}
		next := StateCrashed
		p.mu.Lock()
		if p.probeKill {
			// The core did not fall over — the probe killed it because it had
			// stopped answering. Reporting "crashed: signal: terminated" here
			// would bury the actual fault under the supervisor's own signal, and
			// leave an operator chasing a crash that never happened. It also
			// keeps the state truthful across the backoff sleep below: the box
			// IS unresponsive until the replacement is up.
			next = StateUnresponsive
			msg = "not answering its API, restarted: " + p.lastProbeErr
			p.probeKill = false
		}
		p.mu.Unlock()
		p.setState(next, msg)
		if !p.sleep(ctx, backoff) {
			return
		}
		backoff = min2(backoff*2, maxBackoff)
	}
}

// logHint turns a crash into something an operator can act on.
//
// It prefers a DIAGNOSED cause over the raw output. Xray's errors are five
// clauses deep and end in the one phrase that matters, so the raw tail — which
// is what this used to return — made the operator do the reading. Falling back
// to that tail is still right when nothing matches: a real message beats a
// generic one.
func logHint(logs *ring) string {
	// A wider window than the crash line alone: the cause is often logged a few
	// lines before the process finally gives up.
	lines := logs.snapshotN(60)
	if d, ok := Diagnose(lines); ok {
		if d.Remedy != "" {
			return ": " + d.Cause + " — " + d.Remedy
		}
		return ": " + d.Cause
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if s := lines[i]; s != "" {
			return ": " + tail(s)
		}
	}
	return ""
}

func (p *Process) pump(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	// Access-log lines carry a full destination address and can be long; the
	// default 64KiB token limit is generous but a single overlong line would
	// otherwise stop the scanner and silently kill logging for the rest of the
	// process's life.
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for sc.Scan() {
		line := sc.Text()
		p.logs.add(line)
		if p.spec.OnLine != nil && !p.observerDead.Load() {
			p.observe(line)
		}
	}
}

// observe hands a line to the OnLine hook, containing any panic.
//
// The hook is supplied by another subsystem and runs on the goroutine that
// drains the engine's output pipe. A panic here would kill that pump, the
// process's logs would stop, and the crash reason for the NEXT failure would be
// missing — a diagnostic blackout caused by a bug in an unrelated feature.
func (p *Process) observe(line string) {
	defer func() {
		if r := recover(); r != nil {
			p.logs.add(fmt.Sprintf("[forgepanel] log observer panicked and was disabled: %v", r))
			// Atomic, not a nil assignment: stdout and stderr are pumped on two
			// goroutines at once, so writing to the shared spec here would be a
			// data race — and one that only fires while handling another bug.
			p.observerDead.Store(true)
		}
	}()
	p.spec.OnLine(line)
}

// probeLoop asks, on its own cadence, whether the running core is still
// answering — and restarts it when it is not.
//
// This is the half of "health" the supervisor never had. Everything else here
// keys off cmd.Wait(): the process died, so the core failed. A core that wedges
// does not die, so that signal never fires and the panel reports green forever.
//
// It SIGNALS rather than calling restart(). Letting the existing Wait + backoff
// loop reap and relaunch keeps process lifetime in exactly one place — the place
// that guarantees Stop() blocks until the sockets are released, which is what
// makes reloads reliable. A second restart path would race it.
func (p *Process) probeLoop(ctx context.Context, cmd *exec.Cmd, procDone <-chan struct{}) {
	if p.spec.Probe == nil {
		return // no probe configured: exactly the behaviour that was here before
	}
	every, timeout, failures := p.spec.ProbeEvery, p.spec.ProbeTimeout, p.spec.ProbeFailures
	if every <= 0 {
		every = probeDefaultEvery
	}
	if timeout <= 0 {
		timeout = probeDefaultTimeout
	}
	if failures <= 0 {
		failures = probeDefaultFailures
	}
	t := time.NewTicker(every)
	defer t.Stop()
	// Counted per LAUNCH rather than per Process: a relaunched core starts with
	// a clean slate, or the first missed probe after a restart would kill it
	// again immediately and the box would never come back.
	consecutive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-procDone:
			return // this process is gone; the next launch gets its own loop
		case <-t.C:
		}
		err := p.probe(ctx, timeout)
		select {
		case <-procDone:
			// The process went away while the probe was in flight, so whatever
			// the probe concluded is about a process that no longer exists.
			// Acting on it would stamp this launch's verdict onto the next one.
			return
		default:
		}
		if err != nil {
			p.recordProbe(false, err.Error())
			consecutive++
			if consecutive < failures {
				continue
			}
			p.mu.Lock()
			p.probeKill = true
			p.mu.Unlock()
			p.setState(StateUnresponsive, "not answering its API: "+err.Error())
			p.logs.add(fmt.Sprintf("[forgepanel] %s is running but failed %d liveness probes, restarting it: %v",
				p.spec.Name, consecutive, err))
			if cmd.Process != nil {
				// The error is ignored on purpose: the only one reachable is
				// "process already finished", which means the supervise loop is
				// restarting it anyway. Go marks a Process done when Wait
				// returns, so this can never signal a recycled PID.
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			return
		}
		p.recordProbe(true, "")
		consecutive = 0
	}
}

// probe runs the hook under a timeout, containing any panic.
//
// Same reasoning as observe: the hook belongs to another subsystem, and a panic
// on this goroutine would silently retire liveness checking for this core — the
// feature would look installed and watch nothing.
func (p *Process) probe(ctx context.Context, timeout time.Duration) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("liveness probe panicked: %v", r)
		}
	}()
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.spec.Probe(pctx)
}

func (p *Process) recordProbe(ok bool, errMsg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probed = true
	p.responsive = ok
	p.lastProbeErr = errMsg
	// A core that starts answering again is running, not unresponsive. Without
	// this the label would survive its own cause and stick until the next
	// restart, which is how a recovered engine keeps paging an operator.
	if ok && p.state == StateUnresponsive {
		p.state = StateRunning
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
// BinPath reports the executable this process will run.
//
// Exported because it is the one piece of the spec that can go stale: the spec
// is copied by value at construction, so a binary manager repointed later — an
// operator pinning a core version — moves what the ADAPTER resolves without
// moving what this process execs. A caller that memoises a Process has to be
// able to notice.
func (p *Process) BinPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.spec.BinPath
}

func (p *Process) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	pid := 0
	if p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	st := Status{
		Engine: p.spec.Name, State: p.state, PID: pid,
		Restarts: p.restarts, LastError: p.lastErr, RecentLogs: p.logs.snapshot(),
	}
	// A wider window than RecentLogs: the cause is often logged well before the
	// process finally gives up, and the panel showing "what it means" next to
	// "what it said" is the difference between a support ticket and a fix.
	if d, ok := Diagnose(p.logs.snapshotN(60)); ok {
		st.Diagnosis = &d
	}
	// Nil rather than false when nothing has probed yet: "we never asked" and
	// "we asked and it said no" are different facts, and collapsing them would
	// make every core with no probe configured look unhealthy.
	if p.probed {
		r := p.responsive
		st.Responsive = &r
		st.LastProbeError = p.lastProbeErr
	}
	return st
}

// Status is a snapshot of a supervised process.
type Status struct {
	Engine     string   `json:"engine"`
	State      State    `json:"state"`
	PID        int      `json:"pid"`
	Restarts   int      `json:"restarts"`
	LastError  string   `json:"last_error,omitempty"`
	RecentLogs []string `json:"recent_logs,omitempty"`
	// Diagnosis names the recognised cause of a failure, when there is one.
	//
	// Separate from LastError on purpose: LastError is what the engine said, and
	// this is what it means. Replacing one with the other would lose the exact
	// text an operator needs to search for when the diagnosis is not enough.
	Diagnosis *Diagnosis `json:"diagnosis,omitempty"`
	// Responsive is the verdict of the last liveness probe. Nil means no probe
	// is configured for this core, or none has run yet.
	Responsive     *bool  `json:"responsive,omitempty"`
	LastProbeError string `json:"last_probe_error,omitempty"`
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

func newRing(size int) *ring {
	if size <= 0 {
		// A zero size makes add's modulo divide by zero, on the goroutine that
		// drains the engine's output.
		size = 1
	}
	return &ring{size: size}
}

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

// since returns the lines at or after absolute position seq, oldest first, and
// the next position to ask for.
//
// r.n counts every line ever added, including the ones that have been
// overwritten, so it doubles as the absolute cursor. A caller behind the window
// is fast-forwarded to the oldest line still held; a caller ahead of it (a ring
// that was replaced under it) is given everything, which is the safe direction —
// repeating lines is recoverable, silently returning nothing forever is not.
func (r *ring) since(seq int) ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	held := r.n
	if held > r.size {
		held = r.size
	}
	if held > len(r.buf) {
		held = len(r.buf)
	}
	first := r.n - held
	if seq < first || seq > r.n {
		seq = first
	}
	out := make([]string, 0, r.n-seq)
	for i := seq; i < r.n; i++ {
		out = append(out, r.buf[i%r.size])
	}
	return out, r.n
}

// snapshotN returns the most recent n lines, OLDEST FIRST.
//
// The previous version sliced the backing array by index — buf[len-20:len] —
// which is only the newest 20 lines until the buffer wraps. After that, add
// overwrites from the start, so the newest entries live at the LOW indices and
// that slice returns a window from some arbitrary earlier moment. The visible
// symptom was a crash hint quoting a line that had nothing to do with the crash,
// which is worse than no hint: it sends the operator after the wrong problem.
func (r *ring) snapshotN(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	held := r.n
	if held > r.size {
		held = r.size
	}
	if held > len(r.buf) {
		held = len(r.buf)
	}
	if n > held {
		n = held
	}
	if n <= 0 {
		return nil
	}
	out := make([]string, 0, n)
	// Entry k counting from the oldest still held sits at (r.n-held+k) % size.
	for k := held - n; k < held; k++ {
		out = append(out, r.buf[(r.n-held+k)%r.size])
	}
	return out
}

func (r *ring) snapshot() []string { return r.snapshotN(20) }

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
