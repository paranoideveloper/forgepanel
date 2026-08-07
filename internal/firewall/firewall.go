// Package firewall makes a best-effort attempt to keep the host firewall in sync
// with the panel's inbound ports, so a proxy inbound the panel creates is
// actually reachable from the internet — not just listening and passing a
// loopback Verify while ufw silently drops every external client.
//
// It is deliberately conservative: it only ADDS allow rules for the given ports,
// never removes rules, never changes the default policy, and never touches SSH.
// A missing firewall tool or a permission error is logged and ignored — the panel
// keeps working, the operator just has to open the port themselves.
package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu     sync.Mutex
	opened = map[int]bool{} // ports we have already ensured this process
)

// run executes a short command with a timeout, returning combined output.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		return buf.String(), fmt.Errorf("timeout")
	}
}

func have(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// ufwActive reports whether ufw is installed and its firewall is active — the
// only case where ufw's default-deny actually blocks our inbound ports.
func ufwActive() bool {
	if !have("ufw") {
		return false
	}
	out, _ := run("ufw", "status")
	return strings.Contains(strings.ToLower(out), "status: active")
}

// ufwAllowed parses `ufw status` into the set of already-allowed ports, so we
// skip the (slow) allow call for ports that are already open.
func ufwAllowed() map[int]bool {
	out, err := run("ufw", "status")
	if err != nil {
		return map[int]bool{}
	}
	return parseAllowed(out)
}

// parseAllowed extracts the set of ALLOW-ed numeric ports from `ufw status`
// output. Pure (no I/O) so it is unit-testable.
func parseAllowed(out string) map[int]bool {
	set := map[int]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) == 0 || !strings.Contains(strings.ToUpper(line), "ALLOW") {
			continue
		}
		// Rows look like: "3443/tcp   ALLOW   Anywhere" or "443 ALLOW Anywhere".
		spec := f[0]
		if i := strings.IndexByte(spec, '/'); i >= 0 {
			spec = spec[:i]
		}
		if p, err := strconv.Atoi(spec); err == nil {
			set[p] = true
		}
	}
	return set
}

// EnsureOpen best-effort opens each port (tcp+udp) in the host firewall. Safe to
// call on every engine reload: it is idempotent, caches within the process, and
// only runs when ufw is actually active.
func EnsureOpen(ports []int) {
	if len(ports) == 0 || !ufwActive() {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	allowed := ufwAllowed()
	for _, p := range ports {
		if p <= 0 || p > 65535 || opened[p] || allowed[p] {
			opened[p] = true
			continue
		}
		_, _ = run("ufw", "allow", fmt.Sprintf("%d/tcp", p))
		_, _ = run("ufw", "allow", fmt.Sprintf("%d/udp", p))
		opened[p] = true
	}
}

// Reachability returns a checker for the current firewall state, computed once,
// so a list handler can annotate many inbounds without re-shelling ufw per row.
// The checker reports whether an external client would be allowed to the port.
func Reachability() func(port int) bool {
	if !ufwActive() {
		return func(int) bool { return true }
	}
	allowed := ufwAllowed()
	return func(p int) bool { return allowed[p] }
}

// IsReachableLocally is a heuristic the UI can use to warn honestly: it reports
// whether the port is allowed by ufw (when ufw is active). A false here means an
// external client — a phone — will be dropped even though a loopback Verify is
// green. When ufw is not active it returns true (we cannot tell, and there is no
// ufw blocking).
func IsReachableLocally(port int) bool {
	if !ufwActive() {
		return true
	}
	return ufwAllowed()[port]
}
