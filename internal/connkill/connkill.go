// Package connkill closes established TCP connections on this host.
//
// Removing a user from a running core stops NEW connections and nothing else:
// measured on Xray, a download already in progress ran to completion after the
// user was removed. Disconnecting someone therefore has to close the sockets
// themselves. The kernel can do that (SOCK_DESTROY through inet_diag), and
// `ss -K` is its standard front end; it needs CAP_NET_ADMIN, which the panel's
// service already has for its firewall work.
//
// Only TCP: a UDP "connection" has no kernel state to destroy. Hysteria2, TUIC
// and WireGuard sessions end when the client's next handshake is refused, which
// the hold that accompanies a disconnect takes care of.
package connkill

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Target is the set of connections to close: those whose REMOTE end is one of
// IPs and whose LOCAL port is one of Ports.
//
// Both are required. Without the port filter, closing by address alone would
// also cut the administrator's own SSH or panel session whenever they share an
// address with the user — the usual case when testing from one machine.
type Target struct {
	IPs   []string
	Ports []int
}

// ErrUnsupported is returned when this host cannot close sockets: no `ss`, or a
// kernel without SOCK_DESTROY. The caller still holds the user, so their
// connections end at the client's next reconnect instead of immediately.
var ErrUnsupported = errors.New("this host cannot close established sockets (ss -K unavailable)")

// Args builds the `ss` invocation for t. Exposed so the exact command can be
// tested without root and without killing anything.
func Args(t Target) ([]string, error) {
	var ips []string
	for _, raw := range t.IPs {
		a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(raw), "[]"))
		if err != nil {
			return nil, fmt.Errorf("not an address: %q", raw)
		}
		ips = append(ips, a.Unmap().String())
	}
	ports := uniquePorts(t.Ports)
	if len(ips) == 0 || len(ports) == 0 {
		return nil, errors.New("nothing to close: need at least one address and one port")
	}
	sort.Strings(ips)

	// ss's filter language: state established ( dst A or dst B ) and ( sport = :P or sport = :Q )
	args := []string{"-K", "-t", "-n", "state", "established", "("}
	for i, ip := range ips {
		if i > 0 {
			args = append(args, "or")
		}
		args = append(args, "dst", ip)
	}
	args = append(args, ")", "and", "(")
	for i, p := range ports {
		if i > 0 {
			args = append(args, "or")
		}
		args = append(args, "sport", "=", ":"+strconv.Itoa(p))
	}
	args = append(args, ")")
	return args, nil
}

func uniquePorts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range in {
		if p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// Kill closes the matching connections and reports how many it closed.
func Kill(t Target) (int, error) {
	args, err := Args(t)
	if err != nil {
		return 0, err
	}
	ss, err := exec.LookPath("ss")
	if err != nil {
		return 0, ErrUnsupported
	}
	out, err := exec.Command(ss, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Operation not supported") || strings.Contains(msg, "SOCK_DESTROY") {
			return 0, ErrUnsupported
		}
		return 0, fmt.Errorf("ss -K: %v: %s", err, msg)
	}
	return countClosed(string(out)), nil
}

// countClosed counts the socket lines `ss -K` prints: one per socket it
// destroyed, after a header line.
func countClosed(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "Recv-Q" || f[0] == "State" {
			continue
		}
		n++
	}
	return n
}
