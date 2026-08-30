package nettune

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sandbox retargets every host path at files under t.TempDir(), so the tests
// exercise the real read/write logic without touching the machine running them.
func sandbox(t *testing.T, available string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oc, oq, oa, od, ok, om := procCongestion, procQdisc, procAvailable, dropInPath, procKernel, modprobe
	procCongestion = write("tcp_congestion_control", "cubic\n")
	procQdisc = write("default_qdisc", "fq_codel\n")
	procAvailable = write("tcp_available_congestion_control", available+"\n")
	procKernel = write("osrelease", "6.8.0-31-generic\n")
	dropInPath = filepath.Join(dir, "99-forgepanel-bbr.conf")
	modprobe = func(string) error { return nil }
	t.Cleanup(func() {
		procCongestion, procQdisc, procAvailable, dropInPath, procKernel, modprobe = oc, oq, oa, od, ok, om
	})
	return dir
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// Both halves or nothing: the /proc write is what takes effect now, the drop-in
// is what survives the next reboot. Shipping either alone is a feature that
// works exactly until the operator restarts the box, or one that appears to do
// nothing at all.
func TestApplyWritesTheLiveKnobsAndThePersistentDropIn(t *testing.T) {
	sandbox(t, "reno cubic bbr")
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := read(t, procCongestion); got != "bbr" {
		t.Errorf("tcp_congestion_control = %q, want bbr", got)
	}
	if got := read(t, procQdisc); got != "fq" {
		t.Errorf("default_qdisc = %q, want fq", got)
	}
	drop := read(t, dropInPath)
	for _, want := range []string{"net.core.default_qdisc=fq", "net.ipv4.tcp_congestion_control=bbr"} {
		if !strings.Contains(drop, want) {
			t.Errorf("drop-in is missing %q, so the setting is gone after a reboot:\n%s", want, drop)
		}
	}
	st := Current()
	if !st.Active || !st.Persisted {
		t.Errorf("Status after Apply = %+v, want active and persisted", st)
	}
}

// A kernel without BBR must fail loudly rather than write a value the kernel
// rejects: writing an unsupported algorithm to /proc returns EINVAL, and an
// operator who is told "enabled" learns otherwise from a throughput graph.
func TestApplyRefusesWhenTheKernelHasNoBBR(t *testing.T) {
	sandbox(t, "reno cubic")
	modprobe = func(string) error { return os.ErrNotExist }
	err := Apply()
	if err == nil {
		t.Fatal("Apply succeeded on a kernel with no bbr in tcp_available_congestion_control")
	}
	if got := read(t, procCongestion); got != "cubic" {
		t.Errorf("tcp_congestion_control = %q; Apply must not write an algorithm the kernel does not have", got)
	}
	st := Current()
	if st.BBRAvailable {
		t.Error("Status reports BBR available when it is not")
	}
	if st.Remediation == "" {
		t.Error("Status carries no remediation, leaving the operator with a failure and no next step")
	}
}

// modprobe is the difference between "BBR is unavailable" and "BBR is a module
// nobody has loaded yet", which is the normal state of a fresh Debian box.
func TestApplyLoadsTheModuleWhenBBRIsNotYetPresent(t *testing.T) {
	dir := sandbox(t, "reno cubic")
	loaded := ""
	modprobe = func(mod string) error {
		loaded = mod
		// Loading tcp_bbr is what adds it to the available list.
		return os.WriteFile(filepath.Join(dir, "tcp_available_congestion_control"), []byte("reno cubic bbr\n"), 0o644)
	}
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if loaded != "tcp_bbr" {
		t.Errorf("modprobe %q, want tcp_bbr", loaded)
	}
	if got := read(t, procCongestion); got != "bbr" {
		t.Errorf("tcp_congestion_control = %q, want bbr", got)
	}
}

func TestRevertUndoesBothHalves(t *testing.T) {
	sandbox(t, "reno cubic bbr")
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := Revert(); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if _, err := os.Stat(dropInPath); !os.IsNotExist(err) {
		t.Errorf("the drop-in survived Revert (%v), so the next reboot turns BBR back on", err)
	}
	if got := read(t, procCongestion); got != "cubic" {
		t.Errorf("tcp_congestion_control = %q, want cubic", got)
	}
	if got := read(t, procQdisc); got != "fq_codel" {
		t.Errorf("default_qdisc = %q, want fq_codel", got)
	}
}

// Turning the panel's toggle off must not stomp on a choice the operator made
// themselves. Reverting a host that is running some third algorithm — because
// somebody set it in their own sysctl file — to "cubic" would be the panel
// changing a setting it never made.
func TestRevertLeavesAThirdPartyChoiceAlone(t *testing.T) {
	sandbox(t, "reno cubic bbr")
	if err := os.WriteFile(procCongestion, []byte("reno\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Revert(); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if got := read(t, procCongestion); got != "reno" {
		t.Errorf("tcp_congestion_control = %q; Revert overwrote a setting the panel did not make", got)
	}
}

// Status is what the UI renders. A host already on BBR — set by hand or by
// another tool — must not read as "off", or the operator flips a toggle to fix
// something that is not broken.
func TestStatusReadsTheHostRatherThanTheToggle(t *testing.T) {
	sandbox(t, "reno cubic bbr")
	if err := os.WriteFile(procCongestion, []byte("bbr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(procQdisc, []byte("fq\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := Current()
	if !st.Active || !st.BBRAvailable {
		t.Errorf("Status = %+v, want active on a host already running bbr/fq", st)
	}
	if st.Persisted {
		t.Error("Status claims persistence with no drop-in on disk")
	}
	if st.Kernel == "" {
		t.Error("Status has no kernel version, which is the first thing asked when BBR is missing")
	}
}

// "Upgrade your kernel" is the right answer exactly once — when the kernel
// really is older than 4.9, where BBR was merged. Telling an operator on a 6.x
// kernel to replace it because a module is not loaded sends them to reboot a
// production box for nothing.
func TestRemediationDistinguishesAnOldKernelFromAnUnloadedModule(t *testing.T) {
	dir := sandbox(t, "reno cubic")
	osRelease := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=centos\nID_LIKE=\"rhel fedora\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := osReleasePath
	osReleasePath = osRelease
	t.Cleanup(func() { osReleasePath = old })

	if err := os.WriteFile(procKernel, []byte("3.10.0-1160.el7.x86_64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Current().Remediation
	if !strings.Contains(got, "4.9") || !strings.Contains(got, "kernel") {
		t.Errorf("remediation for a 3.10 kernel = %q, want the 4.9 requirement and a kernel upgrade", got)
	}
	if !strings.Contains(got, "dnf") && !strings.Contains(got, "yum") {
		t.Errorf("remediation for a CentOS host = %q, want a command that host can actually run", got)
	}

	if err := os.WriteFile(procKernel, []byte("6.8.0-31-generic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = Current().Remediation
	if strings.Contains(got, "4.9") {
		t.Errorf("remediation for a 6.8 kernel = %q, want the missing module rather than a kernel upgrade", got)
	}
}

// The common case on a fresh Debian/Ubuntu box: BBR is built, just not loaded.
// Telling that operator to install a package sends them looking for a problem
// they do not have — the toggle itself loads the module.
func TestRemediationSaysLoadWhenTheModuleIsMerelyUnloaded(t *testing.T) {
	dir := sandbox(t, "reno cubic")
	kernel := "6.8.0-31-generic"
	if err := os.WriteFile(procKernel, []byte(kernel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mods := filepath.Join(dir, "modules", kernel, "kernel", "net", "ipv4")
	if err := os.MkdirAll(mods, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mods, "tcp_bbr.ko.zst"), []byte("elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := moduleRoot
	moduleRoot = filepath.Join(dir, "modules")
	t.Cleanup(func() { moduleRoot = old })

	got := Current().Remediation
	if !strings.Contains(got, "modprobe tcp_bbr") {
		t.Errorf("remediation = %q, want it to say the module only needs loading", got)
	}
	if strings.Contains(got, "install") {
		t.Errorf("remediation = %q, want no package to install when the module is already on disk", got)
	}
}

// Maintenance calls Apply once a minute for as long as the panel runs. On a
// host that is already tuned there is nothing to do, and rewriting the drop-in
// anyway is a thousand pointless writes a day to /etc — plus a rename racing
// anything else reading the file.
func TestApplyIsIdempotentOnAnAlreadyTunedHost(t *testing.T) {
	sandbox(t, "reno cubic bbr")
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sentinel := dropInBody + "# left by the test\n"
	if err := os.WriteFile(dropInPath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if read(t, dropInPath) != strings.TrimSpace(sentinel) {
		t.Error("Apply rewrote the drop-in on a host that was already on bbr/fq")
	}
}
