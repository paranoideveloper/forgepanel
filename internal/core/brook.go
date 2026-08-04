package core

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
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
		if cur != nil && cur.sig == sig && cur.cmd.ProcessState == nil {
			continue // already running with the same args
		}
		if cur != nil {
			stopBrook(cur)
		}
		cmd := exec.Command(bin, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("brook start :%d: %w", n.Port, err)
		}
		b.procs[n.Port] = &brookProc{cmd: cmd, sig: sig, mode: brookMode(n)}
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

// Status returns a snapshot of running Brook processes.
func (b *BrookManager) Status() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []map[string]any{}
	for port, p := range b.procs {
		pid := 0
		if p.cmd != nil && p.cmd.Process != nil {
			pid = p.cmd.Process.Pid
		}
		out = append(out, map[string]any{"engine": "brook", "mode": p.mode, "port": port, "pid": pid})
	}
	return out
}

func stopBrook(p *brookProc) {
	if p != nil && p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
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
	listen := ":" + strconv.Itoa(n.Port)
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
