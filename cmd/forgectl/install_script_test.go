package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallScriptUninstallTerminatesCleanly(t *testing.T) {
	// Test bash -n syntax check first
	out, err := exec.Command("bash", "-n", "../../install.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh syntax check failed: %v: %s", err, string(out))
	}

	// Verify --uninstall contains exit 0 and firewall cleanup logic
	cmd := exec.Command("grep", "-A", "35", "do_uninstall()", "../../install.sh")
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to inspect do_uninstall in install.sh: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "exit 0") {
		t.Fatal("do_uninstall in install.sh must end with exit 0 to prevent re-install loop")
	}
	if !strings.Contains(s, "forgepanel_porthop") {
		t.Fatal("do_uninstall in install.sh must clean up forgepanel_porthop firewall rules")
	}
}

// The systemd unit is where a host-tuning feature dies quietly.
//
// ProtectKernelTunables=true remounts /proc/sys read-only for the unit, and
// ProtectSystem=full does the same to everything under /etc that is not listed
// in ReadWritePaths=. A panel running under either cannot write
// net.ipv4.tcp_congestion_control, and cannot drop the sysctl.d file that makes
// the setting survive a reboot — so the BBR toggle flips green in the UI, the
// audit row is written, and the kernel never changes. Nothing fails loudly.
//
// Both unit sources are checked because there are two: the packaged one and the
// heredoc install.sh writes. install.sh says in so many words that they are
// kept in step, and a fix applied to only one means the feature works on a deb
// install and is dead on a curl install (or the reverse).
func TestServiceUnitPermitsSysctlPersistence(t *testing.T) {
	for _, f := range []string{"../../packaging/systemd/forgepanel.service", "../../install.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		// Directives only — a comment mentioning a setting is not that setting.
		var rwp string
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if line == "ProtectKernelTunables=true" {
				t.Errorf("%s sets ProtectKernelTunables=true, which makes /proc/sys read-only for the "+
					"unit: the panel cannot apply BBR and the toggle silently does nothing", f)
			}
			if strings.HasPrefix(line, "ReadWritePaths=") {
				rwp = line
			}
		}
		if rwp == "" {
			t.Fatalf("%s has no ReadWritePaths= line", f)
		}
		if !strings.Contains(rwp, "/etc/sysctl.d") {
			t.Errorf("%s does not grant /etc/sysctl.d in %q, so ProtectSystem=full makes the "+
				"persistent sysctl drop-in unwritable and BBR is lost at the next reboot", f, strings.TrimSpace(rwp))
		}
	}
}
