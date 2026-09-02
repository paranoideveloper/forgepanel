// Package nettune puts the host's TCP congestion control on BBR with the fq
// queue discipline, on behalf of an operator toggle.
//
// This is the single cheapest thing that can be done to a proxy server. Every
// tunnel the panel serves is TCP or QUIC over a long, lossy, deliberately
// degraded path out of a censored network; cubic reads that loss as congestion
// and collapses the window, while BBR keeps the pipe full. The gain is routinely
// several times the throughput on exactly the links this panel exists to serve,
// and it is two sysctls.
//
// Two writes are needed and neither is optional. The /proc write takes effect on
// the next connection; the drop-in under /etc/sysctl.d is what survives a
// reboot. A panel that writes only /proc silently loses the setting the first
// time the host restarts — and a proxy host restarts.
//
// Like internal/firewall, this mutates the host on a best-effort basis: errors
// are returned and reported, never fatal. A panel that refuses to start because
// it could not set a sysctl would be worse than one running on cubic.
package nettune

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Host paths, as package vars so tests can retarget them at a temp directory
// instead of the machine running the suite.
var (
	procCongestion = "/proc/sys/net/ipv4/tcp_congestion_control"
	procQdisc      = "/proc/sys/net/core/default_qdisc"
	procAvailable  = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	procKernel     = "/proc/sys/kernel/osrelease"
	moduleRoot     = "/lib/modules"
	osReleasePath  = "/etc/os-release"
	dropInPath     = "/etc/sysctl.d/99-forgepanel-bbr.conf"
	modprobe       = loadModule
)

// What the host goes back to when the toggle is turned off: cubic has been the
// Linux default since 2.6.19 and fq_codel is what systemd sets on every distro
// this panel installs on.
const (
	defaultCongestion = "cubic"
	defaultQdisc      = "fq_codel"
)

// bbrSince is the first kernel with BBR (merged in 4.9). Below it, loading a
// module cannot help and the only honest advice is a newer kernel.
const (
	bbrSinceMajor = 4
	bbrSinceMinor = 9
)

const dropInBody = `# Managed by ForgePanel — see the network tuning toggle in the panel.
# Removing this file (or turning the toggle off) restores the kernel defaults at
# the next boot.
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
`

// Status is the host's live congestion-control state, read fresh every time.
// The panel renders this rather than the stored toggle: a host can be on BBR
// because somebody set it by hand, and it can be off BBR while the toggle says
// on because the write failed.
type Status struct {
	Congestion   string   `json:"congestion"`
	Qdisc        string   `json:"qdisc"`
	Available    []string `json:"available"`
	BBRAvailable bool     `json:"bbr_available"`
	Active       bool     `json:"active"`
	Persisted    bool     `json:"persisted"`
	Kernel       string   `json:"kernel"`
	Remediation  string   `json:"remediation,omitempty"`
}

// Current reads the host, not the toggle.
func Current() Status {
	st := Status{
		Congestion: readValue(procCongestion),
		Qdisc:      readValue(procQdisc),
		Kernel:     readValue(procKernel),
	}
	st.Available = strings.Fields(readValue(procAvailable))
	st.BBRAvailable = contains(st.Available, "bbr")
	st.Active = st.Congestion == "bbr" && st.Qdisc == "fq"
	st.Persisted = dropInInstalled()
	if !st.BBRAvailable {
		st.Remediation = remediation(st.Kernel)
	}
	return st
}

// Apply switches the host to bbr/fq and makes it stick across reboots.
//
// Idempotent by design: maintenance calls it every minute for the life of the
// process, and a host that is already tuned needs no writes at all — least of
// all a rename over /etc/sysctl.d once a minute.
func Apply() error {
	st := Current()
	if st.Active && st.Persisted {
		return nil
	}
	if !st.BBRAvailable {
		// On most distributions tcp_bbr is a module, and a module nobody has
		// asked for is not in tcp_available_congestion_control. That reads
		// identically to "this kernel cannot do BBR" until you try to load it,
		// so try first and re-read before giving up.
		if err := modprobe("tcp_bbr"); err != nil {
			st = Current()
			if !st.BBRAvailable {
				return fmt.Errorf("loading tcp_bbr: %w; %s", err, st.Remediation)
			}
		} else {
			st = Current()
		}
	}
	if !st.BBRAvailable {
		// Writing an algorithm the kernel does not have returns EINVAL, and the
		// operator would be told "enabled" over a host still running cubic.
		return fmt.Errorf("this kernel offers no BBR (available: %s); %s",
			strings.Join(st.Available, " "), st.Remediation)
	}
	return errors.Join(
		writeProc(procCongestion, "bbr"),
		writeProc(procQdisc, "fq"),
		writeDropIn(),
	)
}

// Revert removes the persistent drop-in and puts the live knobs back.
func Revert() error {
	var errs []error
	if err := os.Remove(dropInPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing %s: %w", dropInPath, err))
	}
	// Only undo what this package did. A host running some third algorithm got
	// there from someone else's sysctl file, and resetting it to cubic would be
	// the panel changing a setting it never made.
	if readValue(procCongestion) == "bbr" {
		errs = append(errs, writeProc(procCongestion, defaultCongestion))
	}
	if readValue(procQdisc) == "fq" {
		errs = append(errs, writeProc(procQdisc, defaultQdisc))
	}
	return errors.Join(errs...)
}

// writeDropIn drops the sysctl file that re-applies the setting at boot, before
// the panel itself is even started.
func writeDropIn() error {
	dir := filepath.Dir(dropInPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	// Written through a temp file in the same directory: a half-written file in
	// /etc/sysctl.d is read at every boot by sysctl(8), and an interrupted write
	// would leave the host with a parse error on a line it prints once, at boot,
	// where nobody is looking.
	tmp, err := os.CreateTemp(dir, ".forgepanel-bbr-*")
	if err != nil {
		return fmt.Errorf("creating the sysctl drop-in: %w (under systemd the unit needs /etc/sysctl.d in ReadWritePaths=)", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(dropInBody); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dropInPath)
}

func dropInInstalled() bool {
	b, err := os.ReadFile(dropInPath)
	return err == nil && strings.Contains(string(b), "tcp_congestion_control=bbr")
}

// writeProc sets one sysctl. The error names the cause an operator actually
// hits: under the panel's own systemd hardening /proc/sys is a read-only mount,
// and a bare "permission denied" on a path they can write as root by hand is
// the least useful message possible.
func writeProc(path, value string) error {
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("setting %s to %s: %w (if the panel runs under systemd, its unit needs ProtectKernelTunables=false)",
			filepath.Base(path), value, err)
	}
	return nil
}

func readValue(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// loadModule runs modprobe with a deadline. Bounded because Apply is called on
// the panel's boot path and from maintenance; a modprobe that hangs on a broken
// module tree must not take either with it.
func loadModule(name string) error {
	if _, err := exec.LookPath("modprobe"); err != nil {
		return fmt.Errorf("modprobe is not installed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "modprobe", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("modprobe %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// remediation is the kernel-upgrade tooling half of the feature: when BBR is
// genuinely unreachable, the operator is handed the exact command for the
// distribution they are on.
//
// The panel deliberately does NOT install a kernel itself. That is a
// reboot-required change to the machine every tunnel it serves runs on, and
// performing it unattended from a web toggle is how somebody loses a box they
// have no console for. It prints the command and lets a human decide.
func remediation(kernel string) string {
	if major, minor, ok := parseKernel(kernel); ok && (major < bbrSinceMajor || (major == bbrSinceMajor && minor < bbrSinceMinor)) {
		return fmt.Sprintf("This kernel (%s) predates TCP BBR, which needs Linux 4.9 or newer. "+
			"Install a newer kernel and reboot: %s", kernel, kernelUpgradeCommand())
	}
	if moduleOnDisk(kernel) {
		// The ordinary state of a fresh Debian or Ubuntu box: tcp_bbr is built
		// and simply has not been asked for. Sending that operator to install a
		// package is sending them after a problem they do not have.
		return "BBR is built for this kernel but not loaded yet; enabling the toggle loads it (modprobe tcp_bbr)."
	}
	return fmt.Sprintf("The tcp_bbr module is not present for this kernel (looked under %s). "+
		"Install the module package and try again: %s", filepath.Join(moduleRoot, kernel), moduleInstallCommand(kernel))
}

// moduleOnDisk reports whether tcp_bbr is shipped for this kernel. The suffix
// varies with the compressor the distribution uses (.ko, .ko.xz, .ko.zst), so
// the check is a glob rather than a stat.
func moduleOnDisk(kernel string) bool {
	if kernel == "" {
		return false
	}
	m, err := filepath.Glob(filepath.Join(moduleRoot, kernel, "kernel", "net", "ipv4", "tcp_bbr.ko*"))
	return err == nil && len(m) > 0
}

// kernelUpgradeCommand and moduleInstallCommand pick by distribution family.
// The generic fallback is a sentence rather than a wrong command: a command that
// does not exist on the host is worse than none, because it is tried first.
func kernelUpgradeCommand() string {
	switch family() {
	case "ubuntu":
		return "apt-get update && apt-get install --install-recommends linux-generic && reboot"
	case "debian":
		return "apt-get update && apt-get install linux-image-amd64 && reboot"
	case "rhel":
		return "dnf -y update kernel && reboot  (yum on older releases)"
	case "alpine":
		return "apk add linux-lts && reboot"
	case "arch":
		return "pacman -Syu linux && reboot"
	}
	return "install a Linux 4.9 or newer kernel from your distribution and reboot"
}

func moduleInstallCommand(kernel string) string {
	switch family() {
	case "ubuntu":
		return "apt-get install linux-modules-extra-" + kernel
	case "debian":
		return "apt-get install --reinstall linux-image-" + kernel
	case "rhel":
		return "dnf -y reinstall kernel-modules-" + kernel
	case "alpine":
		return "apk add linux-lts"
	case "arch":
		return "pacman -S linux"
	}
	return "install the kernel module package for " + kernel + " from your distribution"
}

// family collapses /etc/os-release to the package manager that matters. ID_LIKE
// is consulted so the derivatives — Rocky, Alma, Mint, Armbian, the Iranian
// respins these servers actually run — land on their parent's command rather
// than the generic sentence.
func family() string {
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return ""
	}
	ids := ""
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ID", "ID_LIKE":
			ids += " " + strings.Trim(v, `"'`)
		}
	}
	ids = strings.ToLower(ids)
	switch {
	case strings.Contains(ids, "ubuntu"):
		return "ubuntu"
	case strings.Contains(ids, "debian"):
		return "debian"
	case strings.Contains(ids, "rhel"), strings.Contains(ids, "fedora"), strings.Contains(ids, "centos"):
		return "rhel"
	case strings.Contains(ids, "alpine"):
		return "alpine"
	case strings.Contains(ids, "arch"):
		return "arch"
	}
	return ""
}

// parseKernel reads the leading major.minor out of a uname release string such
// as "6.8.0-31-generic" or "3.10.0-1160.el7.x86_64".
func parseKernel(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
