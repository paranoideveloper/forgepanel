// Package porthop implements the Hysteria2 port-hopping firewall runtime: a
// Hysteria2 server listens on ONE UDP port, and the client sprays packets across
// a UDP port RANGE; the server host must redirect that whole range to the real
// listener. This manager installs those redirects using nftables (preferred) or
// iptables (fallback), in a ForgePanel-OWNED table so cleanup never touches
// unrelated rules, and it falls back to printing copyable manual commands when
// the process lacks CAP_NET_ADMIN.
package porthop

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive UDP port range.
type PortRange struct{ Lo, Hi int }

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// ParseSpec parses a port-hopping spec: comma-separated single ports and ranges,
// e.g. "20000-50000,60000-61000". It rejects reversed and out-of-range values.
func ParseSpec(spec string) ([]PortRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("porthop: empty range spec")
	}
	var out []PortRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var lo, hi int
		var err error
		if i := strings.IndexAny(part, "-:"); i >= 0 {
			if lo, err = strconv.Atoi(strings.TrimSpace(part[:i])); err != nil {
				return nil, fmt.Errorf("porthop: bad range %q", part)
			}
			if hi, err = strconv.Atoi(strings.TrimSpace(part[i+1:])); err != nil {
				return nil, fmt.Errorf("porthop: bad range %q", part)
			}
		} else {
			if lo, err = strconv.Atoi(part); err != nil {
				return nil, fmt.Errorf("porthop: bad port %q", part)
			}
			hi = lo
		}
		if lo < 1 || hi > 65535 {
			return nil, fmt.Errorf("porthop: port %q out of range 1..65535", part)
		}
		if lo > hi {
			return nil, fmt.Errorf("porthop: reversed range %q (lo>hi)", part)
		}
		out = append(out, PortRange{lo, hi})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("porthop: no ranges parsed from %q", spec)
	}
	return out, nil
}

// Conflicts reports any listed used port that falls inside one of the ranges
// (excluding the listener port itself, which is where traffic is redirected).
func Conflicts(ranges []PortRange, listen int, used []int) []int {
	var bad []int
	for _, p := range used {
		if p == listen {
			continue
		}
		for _, r := range ranges {
			if p >= r.Lo && p <= r.Hi {
				bad = append(bad, p)
				break
			}
		}
	}
	sort.Ints(bad)
	return bad
}

// Backend is the firewall tool used.
type Backend string

const (
	BackendNFT      Backend = "nftables"
	BackendIptables Backend = "iptables"
	BackendNone     Backend = "none"
)

const nftTable = "forgepanel_porthop" // ForgePanel-owned table (inet family)

// Manager installs/removes port-hopping redirects.
type Manager struct{ backend Backend }

// New picks the best available backend (nftables > iptables > none).
func New() *Manager {
	b := BackendNone
	if _, err := exec.LookPath("nft"); err == nil {
		b = BackendNFT
	} else if _, err := exec.LookPath("iptables"); err == nil {
		b = BackendIptables
	}
	return &Manager{backend: b}
}

// Backend returns the detected backend.
func (m *Manager) Backend() Backend { return m.backend }

// HasNetAdmin reports whether the process can manage firewall rules. Root inside
// a container can still have CAP_NET_ADMIN removed, so use the effective
// capability set when the kernel exposes it and fall back to the UID only when
// that information cannot be read.
func HasNetAdmin() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return os.Geteuid() == 0
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, "CapEff:") {
			// CAP_NET_ADMIN = bit 12 (0x1000).
			hex := strings.TrimSpace(strings.TrimPrefix(ln, "CapEff:"))
			if v, err := strconv.ParseUint(hex, 16, 64); err == nil {
				return v&(1<<12) != 0
			}
		}
	}
	return os.Geteuid() == 0
}

// Apply installs redirects for the UDP ranges -> listen (IPv4+IPv6 via the inet
// family for nft, or both iptables/ip6tables). It first removes any existing
// ForgePanel rules for this listener, so it is idempotent.
func (m *Manager) Apply(listen int, spec string) error {
	ranges, err := ParseSpec(spec)
	if err != nil {
		return err
	}
	if !HasNetAdmin() {
		return fmt.Errorf("porthop: no CAP_NET_ADMIN; apply the manual commands instead")
	}
	switch m.backend {
	case BackendNFT:
		return m.applyNFT(listen, ranges)
	case BackendIptables:
		return m.applyIptables(listen, ranges)
	default:
		return fmt.Errorf("porthop: no nftables or iptables available")
	}
}

// Remove deletes only the ForgePanel rules for listen.
func (m *Manager) Remove(listen int) error {
	if !HasNetAdmin() {
		return fmt.Errorf("porthop: no CAP_NET_ADMIN")
	}
	switch m.backend {
	case BackendNFT:
		// Deleting the whole chain for this port is safe: it lives in our own table.
		run("nft", "delete", "chain", "inet", nftTable, chainName(listen))
		return nil
	case BackendIptables:
		return m.removeIptables(listen)
	default:
		return nil
	}
}

func chainName(listen int) string { return "hop_" + strconv.Itoa(listen) }

func (m *Manager) applyNFT(listen int, ranges []PortRange) error {
	_ = m.Remove(listen) // idempotent
	// Ensure our table + a nat prerouting chain dedicated to this listener.
	run("nft", "add", "table", "inet", nftTable)
	if err := run("nft", "add", "chain", "inet", nftTable, chainName(listen),
		"{ type nat hook prerouting priority dstnat ; }"); err != nil {
		return fmt.Errorf("porthop: create nft chain: %w", err)
	}
	for _, r := range ranges {
		// Redirect the UDP dport range to the real listener; comment marks ownership.
		if err := run("nft", "add", "rule", "inet", nftTable, chainName(listen),
			"udp", "dport", r.String(), "redirect", "to", ":"+strconv.Itoa(listen),
			"comment", fmt.Sprintf("\"forgepanel-porthop-%d\"", listen)); err != nil {
			return fmt.Errorf("porthop: add nft rule %s: %w", r, err)
		}
	}
	return nil
}

func (m *Manager) applyIptables(listen int, ranges []PortRange) error {
	_ = m.removeIptables(listen)
	comment := fmt.Sprintf("forgepanel-porthop-%d", listen)
	for _, r := range ranges {
		dport := fmt.Sprintf("%d:%d", r.Lo, r.Hi)
		for _, ipt := range []string{"iptables", "ip6tables"} {
			if _, err := exec.LookPath(ipt); err != nil {
				continue
			}
			run(ipt, "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", dport,
				"-m", "comment", "--comment", comment,
				"-j", "REDIRECT", "--to-ports", strconv.Itoa(listen))
		}
	}
	return nil
}

func (m *Manager) removeIptables(listen int) error {
	comment := fmt.Sprintf("forgepanel-porthop-%d", listen)
	for _, ipt := range []string{"iptables", "ip6tables"} {
		_ = removeIptablesRules(ipt, comment)
	}
	return nil
}

// CleanupOwned removes every rule marked with ForgePanel's exact comment prefix
// from IPv4 and IPv6 nat tables, plus the table that ForgePanel creates for
// nftables. It never flushes an existing table or executes reconstructed shell
// text: list output is parsed into argv only after the comment is validated.
func (m *Manager) CleanupOwned() error {
	if !HasNetAdmin() {
		return fmt.Errorf("porthop: no CAP_NET_ADMIN")
	}
	var firstErr error
	if _, err := exec.LookPath("nft"); err == nil {
		// A missing table means no ForgePanel nftables state remains. Do not turn
		// that normal condition into an uninstall failure.
		if _, err := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput(); err == nil {
			if err := run("nft", "delete", "table", "inet", nftTable); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if err := removeIptablesRules(ipt, "forgepanel-porthop-"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func removeIptablesRules(ipt, comment string) error {
	if _, err := exec.LookPath(ipt); err != nil {
		return nil
	}
	for i := 0; i < 128; i++ {
		out, err := exec.Command(ipt, "-t", "nat", "-S", "PREROUTING").CombinedOutput()
		if err != nil {
			return nil // no nat table is equivalent to no ForgePanel rule
		}
		args, ok := deleteArgs(string(out), comment)
		if !ok {
			return nil
		}
		if err := run(ipt, args...); err != nil {
			return err
		}
	}
	return fmt.Errorf("porthop: too many owned %s rules", ipt)
}

func findRule(dump, comment string) string {
	for _, ln := range strings.Split(dump, "\n") {
		if ruleHasOwnedComment(ln, comment) {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

func deleteArgs(dump, comment string) ([]string, bool) {
	line := findRule(dump, comment)
	if !strings.HasPrefix(line, "-A PREROUTING ") {
		return nil, false
	}
	return append([]string{"-t", "nat", "-D"}, strings.Fields(strings.TrimPrefix(line, "-A "))...), true
}

func ruleHasOwnedComment(line, prefix string) bool {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "--comment" {
			continue
		}
		comment := strings.Trim(fields[i+1], `"`)
		return strings.HasPrefix(comment, prefix) && strings.HasPrefix(comment, "forgepanel-porthop-")
	}
	return false
}

// Sync reconciles the installed redirects with the desired set (listenPort->spec):
// it removes rules for ports no longer wanted, (re)applies the wanted ones, and
// tears down the owned table entirely when nothing is wanted. Ports with an
// invalid spec are skipped (their error returned) rather than aborting the rest.
func (m *Manager) Sync(want map[int]string) error {
	if m.backend == BackendNone || !HasNetAdmin() {
		if len(want) == 0 {
			return nil
		}
		return fmt.Errorf("porthop: cannot manage rules (backend=%s, net_admin=%v)", m.backend, HasNetAdmin())
	}
	for _, p := range m.ownedPorts() {
		if _, ok := want[p]; !ok {
			_ = m.Remove(p)
		}
	}
	var firstErr error
	for p, spec := range want {
		if err := m.Apply(p, spec); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(want) == 0 && m.backend == BackendNFT {
		run("nft", "delete", "table", "inet", nftTable) // drop our now-empty table
	}
	return firstErr
}

// ownedPorts lists the listener ports we currently have chains/rules for.
func (m *Manager) ownedPorts() []int {
	seen := map[int]bool{}
	if m.backend == BackendNFT {
		b, _ := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
		for _, ln := range strings.Split(string(b), "\n") {
			if i := strings.Index(ln, "chain hop_"); i >= 0 {
				if p, err := strconv.Atoi(strings.Fields(ln[i+len("chain hop_"):])[0]); err == nil {
					seen[p] = true
				}
			}
		}
	} else if m.backend == BackendIptables {
		for _, ipt := range []string{"iptables", "ip6tables"} {
			b, _ := exec.Command(ipt, "-t", "nat", "-S", "PREROUTING").CombinedOutput()
			for _, ln := range strings.Split(string(b), "\n") {
				i := strings.Index(ln, "forgepanel-porthop-")
				if i < 0 {
					continue
				}
				fields := strings.Fields(ln[i+len("forgepanel-porthop-"):])
				if len(fields) == 0 {
					continue
				}
				if p, err := strconv.Atoi(strings.Trim(fields[0], `"`)); err == nil {
					seen[p] = true
				}
			}
		}
	}
	var out []int
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// Rules returns the effective ForgePanel port-hop rules (for the UI).
func (m *Manager) Rules() []string {
	var out []string
	switch m.backend {
	case BackendNFT:
		b, _ := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.Contains(ln, "redirect") || strings.Contains(ln, "chain hop_") {
				out = append(out, strings.TrimSpace(ln))
			}
		}
	case BackendIptables:
		for _, ipt := range []string{"iptables", "ip6tables"} {
			b, _ := exec.Command(ipt, "-t", "nat", "-S", "PREROUTING").CombinedOutput()
			for _, ln := range strings.Split(string(b), "\n") {
				if ruleHasOwnedComment(ln, "forgepanel-porthop-") {
					out = append(out, ipt+": "+strings.TrimSpace(ln))
				}
			}
		}
	}
	return out
}

// ManualCommands returns copyable shell commands to install the redirects when
// ForgePanel lacks permission to do it itself.
func ManualCommands(backend Backend, listen int, spec string) []string {
	ranges, err := ParseSpec(spec)
	if err != nil {
		return []string{"# invalid range: " + err.Error()}
	}
	var cmds []string
	if backend == BackendIptables {
		for _, r := range ranges {
			cmds = append(cmds, fmt.Sprintf("iptables -t nat -A PREROUTING -p udp --dport %d:%d -m comment --comment forgepanel-porthop-%d -j REDIRECT --to-ports %d", r.Lo, r.Hi, listen, listen))
			cmds = append(cmds, fmt.Sprintf("ip6tables -t nat -A PREROUTING -p udp --dport %d:%d -m comment --comment forgepanel-porthop-%d -j REDIRECT --to-ports %d", r.Lo, r.Hi, listen, listen))
		}
		return cmds
	}
	cmds = append(cmds, "nft add table inet "+nftTable)
	cmds = append(cmds, fmt.Sprintf("nft add chain inet %s %s '{ type nat hook prerouting priority dstnat ; }'", nftTable, chainName(listen)))
	for _, r := range ranges {
		cmds = append(cmds, fmt.Sprintf("nft add rule inet %s %s udp dport %s redirect to :%d", nftTable, chainName(listen), r.String(), listen))
	}
	return cmds
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
