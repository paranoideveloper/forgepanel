package main

import (
	"crypto/sha256"
	"encoding/hex"
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

// An install with no domain should still end with a working padlock.
//
// A certificate authority will not issue for a bare IP on the ordinary profile,
// so "no domain" has always meant plain HTTP or a self-signed certificate and a
// browser warning — neither of which is something to hand someone who has just
// finished an install. sslip.io resolves <ip-with-dashes>.sslip.io back to that
// IP, which is a real hostname pointing at this server that Let's Encrypt will
// validate over HTTP-01.
//
// These assert on the SCRIPT because the behaviour is interactive and network
// dependent; what can be pinned here is that the path exists, that it is
// offered rather than imposed, and that the three ways it can go wrong are
// handled.
func TestInstallerOffersHTTPSWhenThereIsNoDomain(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	if !strings.Contains(s, "offer_magic_dns()") {
		t.Fatal("install.sh has no no-domain HTTPS path; an IP-only install ends on plain HTTP")
	}
	// It must be reachable from the branch that runs when the operator says they
	// have no domain — a helper nothing calls is the same as no helper.
	if !strings.Contains(s, "if offer_magic_dns; then") {
		t.Error("offer_magic_dns is never called from the no-domain branch")
	}

	// Offered, not imposed: it puts a third party in the panel's own resolution
	// path, and its certificate quota is shared globally.
	if !strings.Contains(s, `confirm "Use ${magic}`) {
		t.Error("the magic-DNS hostname is used without asking")
	}
	// The cost has to be on screen at the moment of the decision.
	if !strings.Contains(s, "shared globally") {
		t.Error("the shared certificate quota is not disclosed where the operator decides")
	}

	// Resolution is confirmed BEFORE a CA is asked to validate: a resolver that
	// answers with something else becomes an issuance failure several steps
	// later, with nothing connecting the two on screen.
	if !strings.Contains(s, `resolve_host "$magic"`) {
		t.Error("the hostname is not checked to resolve here before HTTPS is enabled")
	}
	if !strings.Contains(s, `"$resolved" != "$SERVER_IP"`) {
		t.Error("a hostname resolving elsewhere is not caught")
	}

	// IPv6 is excluded deliberately: sslip.io supports it, but not by simple
	// dot-to-dash substitution, and a wrong address is worse than plain HTTP.
	if !strings.Contains(s, "*:*) return 1 ;;") {
		t.Error("IPv6 addresses are not excluded from the dashed-IPv4 substitution")
	}

	// Every failure path must leave the previous behaviour intact rather than
	// half-enabling HTTPS.
	for _, guard := range []string{
		`[[ -n "$SERVER_IP" ]] || return 1`,
		"Falling back to plain HTTP.",
	} {
		if !strings.Contains(s, guard) {
			t.Errorf("missing fallback guard: %s", guard)
		}
	}
}

// The helper must not be able to enable HTTPS without also setting the domain
// it will be issued for: PANEL_HTTPS=1 with an empty PANEL_DOMAIN is the state
// the script elsewhere treats as a misconfiguration.
func TestTheNoDomainPathSetsDomainAndHTTPSTogether(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "offer_magic_dns() {")
	if i < 0 {
		t.Fatal("offer_magic_dns not found")
	}
	j := strings.Index(s[i:], "\n}\n")
	if j < 0 {
		t.Fatal("could not find the end of offer_magic_dns")
	}
	body := s[i : i+j]

	if !strings.Contains(body, `PANEL_DOMAIN="$magic"`) || !strings.Contains(body, `PANEL_HTTPS="1"`) {
		t.Error("the success path must set both the domain and the HTTPS flag")
	}
	// Success is the LAST thing it does; every earlier exit returns 1.
	if strings.Count(body, "return 1") < 4 {
		t.Errorf("expected every failure path to return 1, found %d", strings.Count(body, "return 1"))
	}
}

// The published checksum must match the published script.
//
// install.sh.sha256 is committed AND regenerated by a goreleaser before-hook, so
// the two can disagree the moment install.sh is edited without re-running it —
// which is exactly what happened: the committed digest was for the previous
// installer, so anyone following the documented
//
//	sha256sum -c install.sh.sha256
//
// would have been told the script they just downloaded was corrupt. That is the
// worst possible false alarm to ship, because the whole point of publishing the
// checksum is to distinguish a tampered download from a good one.
//
// It also failed the release: goreleaser refuses to build from a dirty tree, and
// the hook rewriting this file is what made it dirty.
func TestTheCommittedInstallerChecksumMatchesTheInstaller(t *testing.T) {
	script, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile("../../install.sh.sha256")
	if err != nil {
		t.Skipf("no committed checksum: %v", err)
	}

	sum := sha256.Sum256(script)
	want := hex.EncodeToString(sum[:])

	// The file is `sha256sum` output: "<hex>  install.sh".
	got := strings.Fields(string(recorded))
	if len(got) == 0 {
		t.Fatal("install.sh.sha256 is empty")
	}
	if got[0] != want {
		t.Errorf("install.sh.sha256 records %s but install.sh hashes to %s.\n"+
			"Run: sha256sum install.sh > install.sh.sha256\n"+
			"Until then `sha256sum -c install.sh.sha256` tells whoever downloads the installer "+
			"that it is corrupt.", got[0], want)
	}
}
