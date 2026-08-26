package bridge

// Running the exit half, and telling the operator exactly what to run on the
// other one.
//
// The panel only ever manages the EXIT. The bridge box is, by definition, a
// machine in Iran that the panel usually cannot reach — often bought in someone
// else's name, on an ISP that blocks inbound connections. Assuming the panel
// can log into it would make the whole feature unusable for the deployments it
// exists for, so the bridge half is delivered as a bundle a person pastes.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// State is what a supervised exit process is doing.
type State string

const (
	StateStopped State = "stopped"
	StateRunning State = "running"
	StateFailed  State = "failed"
)

// Status reports one bridge's exit process.
type Status struct {
	Name     string    `json:"name"`
	Backend  string    `json:"backend"`
	State    State     `json:"state"`
	PID      int       `json:"pid,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	LastErr  string    `json:"last_error,omitempty"`
	Restarts int       `json:"restarts"`
}

type proc struct {
	cmd      *exec.Cmd
	state    State
	since    time.Time
	lastErr  string
	restarts int
	stop     chan struct{}
}

// Manager supervises the exit half of every configured bridge.
type Manager struct {
	dataDir   string
	installer *Installer

	mu    sync.Mutex
	procs map[string]*proc
}

// NewManager roots a manager at dataDir.
func NewManager(dataDir string) *Manager {
	return &Manager{dataDir: dataDir, installer: NewInstaller(dataDir), procs: map[string]*proc{}}
}

// confDir is where a bridge's rendered exit config lives.
func (m *Manager) confDir(name string) string {
	return filepath.Join(m.dataDir, "bridge", name)
}

// Start brings up (or restarts) the exit half of one bridge.
func (m *Manager) Start(ctx context.Context, name string, spec Spec) error {
	b, err := Get(spec.Backend)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	rendered, err := Render(spec, RoleExit)
	if err != nil {
		return err
	}
	inst, err := m.installer.Ensure(b)
	if err != nil {
		return err
	}

	dir := m.confDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bridge: create %s: %w", dir, err)
	}
	var args []string
	if b.ConfigFormat == "args" {
		args = Args(rendered)
	} else {
		// 0600: the config carries the shared token, which is the whole of the
		// tunnel's authentication.
		cfgPath := filepath.Join(dir, "exit.toml")
		if err := os.WriteFile(cfgPath, []byte(rendered), 0o600); err != nil {
			return fmt.Errorf("bridge: write %s: %w", cfgPath, err)
		}
		args = []string{"-c", cfgPath}
	}

	exe := inst.Exe
	if b.Name == "frp" {
		exe = inst.Exe // frps is Exe; frpc is PeerExe and runs on the bridge
	}

	m.Stop(name)

	cmd := exec.CommandContext(context.WithoutCancel(ctx), exe, args...)
	cmd.Dir = dir
	logPath := filepath.Join(dir, "exit.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("bridge: open %s: %w", logPath, err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("bridge: start %s: %w", b.Title, err)
	}

	p := &proc{cmd: cmd, state: StateRunning, since: time.Now().UTC(), stop: make(chan struct{})}
	m.mu.Lock()
	if old := m.procs[name]; old != nil {
		p.restarts = old.restarts + 1
	}
	m.procs[name] = p
	m.mu.Unlock()

	go func() {
		err := cmd.Wait()
		logFile.Close()
		m.mu.Lock()
		defer m.mu.Unlock()
		cur := m.procs[name]
		if cur != p {
			return // superseded by a newer start
		}
		select {
		case <-p.stop:
			p.state = StateStopped
		default:
			p.state = StateFailed
			if err != nil {
				// Quote the tool's own last line: a bridge that will not start
				// is usually a port already bound or a token mismatch, and both
				// say so plainly in the log.
				p.lastErr = err.Error() + lastLogLine(logPath)
			}
		}
	}()
	return nil
}

// Stop tears down one bridge's exit process.
func (m *Manager) Stop(name string) {
	m.mu.Lock()
	p := m.procs[name]
	m.mu.Unlock()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	_ = p.cmd.Process.Kill()
}

// StopAll tears down every supervised bridge.
func (m *Manager) StopAll() {
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for n := range m.procs {
		names = append(names, n)
	}
	m.mu.Unlock()
	for _, n := range names {
		m.Stop(n)
	}
}

// Status reports every supervised bridge, sorted by name.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.procs))
	for name, p := range m.procs {
		s := Status{Name: name, State: p.state, Since: p.since,
			LastErr: p.lastErr, Restarts: p.restarts}
		if p.cmd != nil && p.cmd.Process != nil && p.state == StateRunning {
			s.PID = p.cmd.Process.Pid
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// lastLogLine returns the tool's final output, for a failure message that says
// something instead of "exit status 1".
func lastLogLine(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if v := strings.TrimSpace(lines[i]); v != "" {
			return " — " + v
		}
	}
	return ""
}

// PeerBundle is everything a person needs to bring up the bridge half on a
// machine the panel cannot reach.
type PeerBundle struct {
	Backend string `json:"backend"`
	// DownloadURL and SHA256 let the operator verify what they are about to run
	// as root, on a box that is by definition less trusted than the exit.
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	Exe         string `json:"exe"`
	// Config is the rendered bridge-side config, or the argument list for a
	// backend with no config file.
	Config string `json:"config"`
	// ConfigFormat is "toml" or "args".
	ConfigFormat string `json:"config_format"`
	// Command is what to run once the config is in place.
	Command string `json:"command"`
	// Warnings are things that will bite on the bridge machine.
	Warnings []string `json:"warnings,omitempty"`
}

// Bundle builds the bridge-side instructions for a spec.
func Bundle(spec Spec) (*PeerBundle, error) {
	b, err := Get(spec.Backend)
	if err != nil {
		return nil, err
	}
	cfg, err := Render(spec, RoleBridge)
	if err != nil {
		return nil, err
	}
	exe := b.Exe
	if b.PeerExe != "" {
		// frp's two halves are different programs, and running frps on the
		// bridge produces a process that starts, listens and never tunnels.
		exe = b.PeerExe
	}
	out := &PeerBundle{
		Backend: b.Name, DownloadURL: b.DownloadURL(), SHA256: b.SHA256,
		Exe: exe, Config: cfg, ConfigFormat: b.ConfigFormat,
	}
	if b.ConfigFormat == "args" {
		out.Command = "./" + exe + " " + strings.Join(Args(cfg), " ")
	} else {
		out.Command = "./" + exe + " -c bridge.toml"
	}
	if b.Name == "rathole" {
		out.Command = "./" + exe + " -c bridge.toml"
	}
	if b.MutatesSysctl {
		out.Warnings = append(out.Warnings,
			"This backend raises the host's rmem_max/wmem_max when it starts, which changes "+
				"networking for everything else on that machine — not just the tunnel.")
	}
	for _, svc := range spec.Services {
		if strings.EqualFold(svc.Protocol, "udp") {
			out.Warnings = append(out.Warnings,
				"UDP service \""+svc.Name+"\" needs UDP port "+fmt.Sprint(svc.BridgePort)+
					" open inbound on the bridge; a firewall that only allows TCP will make it "+
					"look connected and carry nothing.")
		}
	}
	return out, nil
}
