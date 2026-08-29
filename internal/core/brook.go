package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// BrookManager supervises Brook server processes (spec §3.1: Brook is an
// external process only — GPL, never linked). Brook takes CLI args rather than a
// config file, so it needs its own per-inbound runner. Each Brook inbound (mode
// server/wsserver/wssserver/quicserver) becomes one process keyed by port.
type BrookManager struct {
	bins *binmgr.Manager

	mu    sync.Mutex
	procs map[int]*brookProc
}

type brookProc struct {
	cmd  *exec.Cmd
	sig  string // args signature; a change triggers a restart
	mode string
	port int

	// logs is what this process last wrote. Brook's output used to go straight
	// to the panel's own stderr, so a Brook inbound that refused to start
	// produced a line in the journal that named no inbound, reached no health
	// endpoint, and could not be diagnosed from the panel at all.
	logs *supervisor.LogRing

	// The reaper's findings. A Brook process that died was never noticed: the
	// manager reported whatever it had started, with its old PID, indefinitely —
	// so the panel showed a dead inbound as running. Nothing called Wait either,
	// so the corpse stayed a zombie for the life of the panel.
	mu       sync.Mutex
	exited   bool
	exitErr  string
	exitedAt time.Time
	restarts int
	stopping bool
}

func (p *brookProc) markExited(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exited = true
	p.exitedAt = time.Now()
	if err != nil {
		p.exitErr = err.Error()
	}
}

func (p *brookProc) snapshot() (exited bool, exitErr string, at time.Time, restarts int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited, p.exitErr, p.exitedAt, p.restarts
}

func (p *brookProc) isStopping() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopping
}

// NewBrookManager builds a Brook manager sharing the binary manager.
func NewBrookManager(bins *binmgr.Manager) *BrookManager {
	return &BrookManager{bins: bins, procs: map[int]*brookProc{}}
}

// Sync reconciles running Brook processes with the desired Brook inbounds:
// starts new ones, restarts changed ones, and stops removed ones. certPath/
// keyPath are the (self-signed or imported) cert for wss/quic modes.
func (b *BrookManager) Sync(nodes []*model.Node, certPath, keyPath string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	want := map[int]string{} // port -> signature
	if len(nodes) > 0 {
		if _, err := b.bins.Ensure(binmgr.EngineBrook); err != nil {
			return fmt.Errorf("brook binary: %w", err)
		}
	}
	bin := b.bins.Path(binmgr.EngineBrook)

	for _, n := range nodes {
		args := brookArgs(n, certPath, keyPath)
		sig := fmt.Sprint(args)
		want[n.Port] = sig
		cur := b.procs[n.Port]
		// Liveness comes from the reaper's flag, not from cmd.ProcessState:
		// Wait() WRITES ProcessState from the reaper goroutine, so reading it
		// here is a data race the race detector flags, and the value it returns
		// is whatever the scheduler happened to leave.
		if cur != nil && cur.sig == sig {
			if exited, _, _, _ := cur.snapshot(); !exited {
				continue // already running with the same args
			}
		}
		if cur != nil {
			stopBrook(cur)
		}
		p, err := b.startBrook(bin, args, n.Port, sig, brookMode(n))
		if err != nil {
			return err
		}
		b.procs[n.Port] = p
	}
	// stop removed
	for port, p := range b.procs {
		if _, ok := want[port]; !ok {
			stopBrook(p)
			delete(b.procs, port)
		}
	}
	return nil
}

// StopAll terminates every Brook process.
func (b *BrookManager) StopAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for port, p := range b.procs {
		stopBrook(p)
		delete(b.procs, port)
	}
}

// Status returns a snapshot of Brook processes and whether each is alive.
//
// This used to list whatever had been started, with its original PID, forever:
// a Brook inbound that crashed a second after launch was reported as running
// until the panel restarted. "running" now means the reaper has not seen it
// exit, and a process that DID exit is reported with the reason and the crash
// hint from its own output rather than vanishing or lying.
func (b *BrookManager) Status() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []map[string]any{}
	for port, p := range b.procs {
		pid := 0
		if p.cmd != nil && p.cmd.Process != nil {
			pid = p.cmd.Process.Pid
		}
		exited, exitErr, at, restarts := p.snapshot()
		row := map[string]any{
			"engine": "brook", "mode": p.mode, "port": port, "pid": pid,
			"running": !exited, "restarts": restarts,
		}
		if exited {
			row["pid"] = 0
			if exitErr != "" {
				row["last_error"] = exitErr
			}
			if !at.IsZero() {
				row["exited_at"] = at.UTC().Format(time.RFC3339)
			}
			// The engine's own words. A Brook inbound that cannot bind its port
			// says so; without this the operator saw only "not running".
			if p.logs != nil {
				if hint := p.logs.Hint(); hint != "" {
					row["hint"] = hint
				}
				row["recent_logs"] = p.logs.SnapshotN(20)
			}
		}
		out = append(out, row)
	}
	return out
}

// brookRestartDelay is how long a crashed Brook process waits before being
// started again.
//
// Fixed rather than exponential, and deliberately slow: Brook takes CLI args,
// so a process that fails on its arguments fails identically every time, and a
// tight retry loop would be a fork bomb against a typo. Five seconds is fast
// enough that a transient failure (a port briefly held by something else)
// recovers on its own, and slow enough that a permanent one is visible in the
// status as a rising restart count rather than as a wedged panel.
const brookRestartDelay = 5 * time.Second

// brookMaxRestarts bounds automatic restarts per process.
//
// A Brook inbound whose args are wrong can never start. Retrying it forever
// would hide that behind an ever-growing counter; stopping leaves the failure
// visible in Status with the reason attached, which is what an operator can act
// on.
const brookMaxRestarts = 10

// startBrook launches one Brook process with its output captured and a reaper
// watching it.
func (b *BrookManager) startBrook(bin string, args []string, port int, sig, mode string) (*brookProc, error) {
	cmd := exec.Command(bin, args...)
	p := &brookProc{cmd: cmd, sig: sig, mode: mode, port: port, logs: supervisor.NewLogRing(200)}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("brook start :%d: %w", port, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("brook start :%d: %w", port, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("brook start :%d: %w", port, err)
	}
	go pumpBrook(p, stdout)
	go pumpBrook(p, stderr)
	go b.reap(p, bin, args)
	return p, nil
}

// pumpBrook copies one stream into the process's ring.
func pumpBrook(p *brookProc, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		p.logs.Add(sc.Text())
	}
}

// reap waits for a Brook process and restarts it if it died on its own.
//
// Waiting is the part that was missing entirely: without it the process stayed a
// zombie and the manager had no way to know it had gone. Restarting is what
// makes Brook behave like the supervised cores — a crashed xray comes back, and
// a crashed Brook inbound used to stay down until an unrelated edit happened to
// trigger a Sync.
func (b *BrookManager) reap(p *brookProc, bin string, args []string) {
	err := p.cmd.Wait()
	p.markExited(err)
	if p.isStopping() {
		return // asked to stop; not a crash
	}

	for attempt := 0; attempt < brookMaxRestarts; attempt++ {
		time.Sleep(brookRestartDelay)

		b.mu.Lock()
		// Still the current process for this port? A Sync may have replaced or
		// removed it while this goroutine was sleeping, and restarting then
		// would resurrect an inbound the operator deleted.
		if b.procs[p.port] != p || p.isStopping() {
			b.mu.Unlock()
			return
		}
		next, startErr := b.startBrook(bin, args, p.port, p.sig, p.mode)
		if startErr == nil {
			p.mu.Lock()
			restarts := p.restarts + 1
			p.mu.Unlock()
			next.mu.Lock()
			next.restarts = restarts
			next.mu.Unlock()
			b.procs[p.port] = next
			b.mu.Unlock()
			return
		}
		b.mu.Unlock()

		p.mu.Lock()
		p.restarts++
		p.exitErr = startErr.Error()
		p.mu.Unlock()
	}
}

func stopBrook(p *brookProc) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	// Tell the reaper this is deliberate BEFORE killing, or it races the kill
	// and restarts an inbound that was just removed.
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	_ = p.cmd.Process.Kill()
	// No Wait here: the reaper goroutine owns it, and a second Wait on the same
	// process returns "wait: no child processes" and can consume the reaper's.
}

func brookMode(n *model.Node) string {
	if n.Brook != nil && n.Brook.Mode != "" {
		return n.Brook.Mode
	}
	return "server"
}

// brookArgs builds the CLI args for a Brook inbound by mode (verified against
// `brook <mode> --help` for the pinned version).
func brookArgs(n *model.Node, certPath, keyPath string) []string {
	// Bind the node's own address when it is one this host can bind, so a Brook
	// inbound rewritten for a shared platform port listens on loopback rather
	// than on every interface in the container. A hostname is left as ":port":
	// brook cannot bind a name, and the wildcard is what every existing install
	// has always used.
	listen := ":" + strconv.Itoa(n.Port)
	if ip := net.ParseIP(strings.TrimSpace(n.Address)); ip != nil && !ip.IsUnspecified() {
		listen = net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	}
	pw := n.Password
	path := "/ws"
	if n.Brook != nil && n.Brook.Path != "" {
		path = n.Brook.Path
	}
	sni := n.Security.ServerName
	if sni == "" {
		sni = n.Address
	}
	switch brookMode(n) {
	case "wsserver":
		return []string{"wsserver", "-l", listen, "-p", pw, "--path", path}
	case "wssserver":
		return []string{"wssserver", "--domainaddress", sni + ":" + strconv.Itoa(n.Port),
			"-p", pw, "--path", path, "--cert", certPath, "--certkey", keyPath}
	case "quicserver":
		// brook quicserver takes --domainaddress (not -l), like wssserver: it does
		// QUIC+TLS and needs the cert's domain:port, verified against `brook
		// quicserver --help` for the pinned version.
		return []string{"quicserver", "--domainaddress", sni + ":" + strconv.Itoa(n.Port),
			"-p", pw, "--cert", certPath, "--certkey", keyPath}
	default: // server
		return []string{"server", "-l", listen, "-p", pw}
	}
}
