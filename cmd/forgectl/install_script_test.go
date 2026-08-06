package main

import (
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
