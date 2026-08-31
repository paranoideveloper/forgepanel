package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installerPath is the committed install.sh, which is what ships in a release.
func installerPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "install.sh")
}

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

// TestTheInstallerCanRunWithoutGitHub covers the offline path.
//
// The hosts this panel runs on are frequently the ones behind a restrictive
// egress filter, where every other part of the internet works and github.com
// does not. On such a box `forgectl update` failed at the first call and there
// was no supported way to update at all — only placing binaries by hand, which
// skips the checksums the online path enforces.
func TestTheInstallerCanRunWithoutGitHub(t *testing.T) {
	src, err := os.ReadFile(installerPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	for _, want := range []string{"--from-dir", "--mirror", "ASSET_DIR", "MIRROR"} {
		if !strings.Contains(s, want) {
			t.Errorf("installer does not accept %s", want)
		}
	}

	// download_to is the ONE place bytes enter the installer. If the offline
	// branch were added anywhere else, some assets would still be fetched from
	// GitHub and an offline install would fail halfway through — with the panel
	// binary already replaced.
	fn := s[strings.Index(s, "download_to() {"):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	if !strings.Contains(fn, "ASSET_DIR") {
		t.Error("download_to does not serve from the local asset directory, so an " +
			"offline install would still reach for the network")
	}
	if strings.Count(s, "curl -fsSL --retry") > 1 {
		t.Error("more than one download path exists; the offline branch would not cover them all")
	}

	// The offline mode changes WHERE the bytes come from, never whether they
	// are checked. An install that skipped verification because it was offline
	// would be a worse failure than not being able to update.
	if !strings.Contains(s, "verify_release_asset") {
		t.Error("installer no longer verifies release assets")
	}
}

// TestOfflineInstallServesAssetsFromTheDirectory runs the real download_to with
// ASSET_DIR set, so the branch is exercised rather than merely present.
func TestOfflineInstallServesAssetsFromTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "thing.bin"), []byte("local-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out.bin")

	// Source the installer's function in isolation: define the two variables it
	// reads, call it with a URL that must NOT be fetched, and check the file
	// came from disk.
	script := fmt.Sprintf(`
set -e
ASSET_DIR=%q
INTERACTIVE=0
UI=plain
%s
download_to "https://github.com/example/repo/releases/download/v1/thing.bin" %q
`, dir, extractShellFunc(t, "download_to"), dest)

	cmd := exec.Command("bash", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline download_to failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("nothing was written: %v", err)
	}
	if string(got) != "local-bytes" {
		t.Errorf("served %q, want the local file's contents", got)
	}
}

// TestUpgradeKeepsTheRunningPanelSettings pins the fix for a bug that made
// `forgectl update` fail on every box whose panel port was not the default.
//
// load_existing_config saw panel.json, set a flag and RETURNED — without
// reading the port. A non-interactive upgrade therefore ran the wizard
// defaults, replaced the binaries, health-checked port 2053, got nothing, and
// rolled back reporting only "Installation did not pass validation". Observed
// on a live panel running on 3443.
func TestUpgradeKeepsTheRunningPanelSettings(t *testing.T) {
	dir := t.TempDir()
	panelJSON := `{"domain":"panel.example.com","https_enabled":true,"port":3443,` +
		`"admin_path":"/panel/abc","bind_address":"0.0.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "panel.json"), []byte(panelJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`
set -e
%s
echo "port=$(json_scalar %q port)"
echo "domain=$(json_scalar %q domain)"
echo "https=$(json_scalar %q https_enabled)"
`, extractShellFunc(t, "json_scalar"),
		filepath.Join(dir, "panel.json"), filepath.Join(dir, "panel.json"), filepath.Join(dir, "panel.json"))

	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("json_scalar failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{"port=3443", "domain=panel.example.com", "https=true"} {
		if !strings.Contains(got, want) {
			t.Errorf("upgrade would not preserve %s; read back:\n%s", want, got)
		}
	}

	// The early return is the defect itself: if it comes back, the settings are
	// silently dropped again and the only symptom is a rollback.
	src, err := os.ReadFile(installerPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	block := s[strings.Index(s, "load_existing_config() {"):]
	block = block[:strings.Index(block, "\n}\n")]
	if !strings.Contains(block, "PANEL_PORT=$(json_scalar") {
		t.Error("load_existing_config no longer reads the live panel port, so an " +
			"upgrade on a non-default port will health-check the wrong one and roll back")
	}
}
