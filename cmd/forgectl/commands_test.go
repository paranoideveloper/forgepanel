package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/lifecycle"
	"github.com/forgepanel/forgepanel/internal/store"
)

func setupMockGlobals(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)

	origRequireAdmin := requireLocalAdmin
	origSystemctl := systemctl
	origSystemctlState := systemctlState
	origConfirmLocal := confirmLocal
	origPromptSecret := promptSecret
	origInteractiveTerminal := interactiveTerminal
	origLoadManifest := loadManifest
	origLatestRelease := latestRelease
	origVerifyHealth := verifyHealth

	requireLocalAdmin = func() error { return nil }
	systemctl = func(args ...string) error { return nil }
	systemctlState = func() string { return "active" }
	confirmLocal = func(prompt string) bool { return true }
	promptSecret = func(label string) (string, error) { return "secret123", nil }
	interactiveTerminal = func() bool { return true }
	loadManifest = func(path string) (*lifecycle.Manifest, error) {
		return lifecycle.NewManifest("verified", "1.0.0", dir), nil
	}
	latestRelease = func() (releaseMetadata, error) {
		return releaseMetadata{TagName: "v1.0.0"}, nil
	}
	verifyHealth = func(cfg *config.Config) error { return nil }

	t.Cleanup(func() {
		requireLocalAdmin = origRequireAdmin
		systemctl = origSystemctl
		systemctlState = origSystemctlState
		confirmLocal = origConfirmLocal
		promptSecret = origPromptSecret
		interactiveTerminal = origInteractiveTerminal
		loadManifest = origLoadManifest
		latestRelease = origLatestRelease
		verifyHealth = origVerifyHealth
	})

	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatalf("config.LoadFromDataDir: %v", err)
	}

	st, err := store.Open(filepath.Join(dir, "forgepanel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	if err := st.CreateAdmin(&store.Admin{Username: "admin", PasswordHash: "hash", Role: store.RoleOwner}); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	_ = cfg.SavePanel()
	return dir
}

func TestCmdKeygen(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"empty", []string{}, true},
		{"reality", []string{"reality"}, false},
		{"uuid", []string{"uuid"}, false},
		{"shortid", []string{"shortid"}, false},
		{"ss2022_missing_method", []string{"ss2022"}, true},
		{"ss2022_valid", []string{"ss2022", "2022-blake3-aes-256-gcm"}, false},
		{"wireguard", []string{"wireguard"}, false},
		{"ssh", []string{"ssh"}, false},
		{"password", []string{"password"}, false},
		{"mldsa65", []string{"mldsa65"}, false},
		{"unknown", []string{"unknown_kind"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdKeygen(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("cmdKeygen(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCmdConvert(t *testing.T) {
	validLink := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=tcp&security=reality&pbk=pk123&fp=chrome#test-node"

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"insufficient_args", []string{validLink}, true},
		{"convert_uri", []string{validLink, "uri"}, false},
		{"convert_xray", []string{validLink, "xray"}, false},
		{"convert_clash", []string{validLink, "clash"}, false},
		{"invalid_target", []string{validLink, "invalid_fmt"}, true},
		{"invalid_link", []string{"invalid-link", "uri"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdConvert(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("cmdConvert(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCmdRender(t *testing.T) {
	validLink := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=tcp&security=reality&pbk=pk123&fp=chrome#test-node"

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"insufficient_args", []string{validLink}, true},
		{"render_xray", []string{validLink, "xray"}, false},
		{"invalid_target", []string{validLink, "invalid_fmt"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdRender(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("cmdRender(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCmdVersion(t *testing.T) {
	if err := cmdVersion(nil); err != nil {
		t.Fatalf("cmdVersion error = %v", err)
	}
}

func TestCmdBackupAndRestore(t *testing.T) {
	dir := setupMockGlobals(t)
	backupFile := filepath.Join(dir, "backup.enc")

	if err := cmdBackup([]string{"create", "--data", dir, backupFile}); err != nil {
		t.Fatalf("cmdBackup create failed: %v", err)
	}
	if _, err := os.Stat(backupFile); err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	if err := cmdBackup([]string{"restore", "--data", dir, backupFile}); err != nil {
		t.Fatalf("cmdBackup restore failed: %v", err)
	}
}

func TestCmdStatusAndService(t *testing.T) {
	dir := setupMockGlobals(t)

	if err := cmdStatus([]string{"--data", dir, "--json"}); err != nil {
		t.Fatalf("cmdStatus failed: %v", err)
	}

	if err := cmdService([]string{"restart"}); err != nil {
		t.Fatalf("cmdService restart failed: %v", err)
	}
}

func TestCmdSettingsShowAndSet(t *testing.T) {
	dir := setupMockGlobals(t)

	if err := cmdSettingsShow([]string{"--data", dir, "--json"}); err != nil {
		t.Fatalf("cmdSettingsShow failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate test panel port: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := ln.Close(); err != nil {
		t.Fatalf("release test panel port: %v", err)
	}

	if err := cmdSettingsSet([]string{"--data", dir, "--panel-port", port, "--domain", "panel.local", "--defer-restart"}); err != nil {
		t.Fatalf("cmdSettingsSet failed: %v", err)
	}
}

func TestCmdCertAndAdmin(t *testing.T) {
	dir := setupMockGlobals(t)

	if err := cmdCert([]string{"status", "--data", dir}); err != nil {
		t.Fatalf("cmdCert status failed: %v", err)
	}

	if err := cmdAdmin([]string{"reset-password", "--data", dir, "--user", "admin"}); err != nil {
		t.Fatalf("cmdAdmin reset-password failed: %v", err)
	}

	if err := cmdAdmin([]string{"reset-2fa", "--data", dir, "--user", "admin"}); err != nil {
		t.Fatalf("cmdAdmin reset-2fa failed: %v", err)
	}

	if err := cmdAdmin([]string{"regenerate-path", "--data", dir}); err != nil {
		t.Fatalf("cmdAdmin regenerate-path failed: %v", err)
	}
}

func TestCmdFirewallAndRepairAndUninstall(t *testing.T) {
	dir := setupMockGlobals(t)

	if err := cmdFirewall([]string{"status", "--json"}); err != nil {
		t.Fatalf("cmdFirewall status failed: %v", err)
	}

	if err := cmdRepair([]string{"--data", dir}); err != nil {
		t.Fatalf("cmdRepair failed: %v", err)
	}

	if err := cmdUninstall([]string{"--dry-run", "--yes", "--keep-data"}); err != nil {
		t.Fatalf("cmdUninstall dry-run failed: %v", err)
	}
}

func TestLocalHelpers(t *testing.T) {
	if defaultDataDir() == "" {
		t.Error("defaultDataDir returned empty string")
	}

	actor := localActor()
	if actor == "" {
		t.Error("localActor returned empty string")
	}

	bArgs := boolArg("test", true)
	if len(bArgs) != 1 || bArgs[0] != "test" {
		t.Errorf("boolArg unexpected: %v", bArgs)
	}

	pURL := panelURL(&config.PanelSettings{Port: 2053, Domain: "example.com", HTTPSEnabled: true})
	if pURL != "https://example.com:2053" {
		t.Errorf("panelURL unexpected: %s", pURL)
	}

	var ms multiString
	if err := ms.Set("val1"); err != nil || len(ms) != 1 || ms[0] != "val1" {
		t.Errorf("multiString Set failed: %v, %v", ms, err)
	}
	if ms.String() != "val1" {
		t.Errorf("multiString String unexpected: %s", ms.String())
	}
}

func TestMenuAllChoices(t *testing.T) {
	dir := setupMockGlobals(t)
	_ = dir

	r := bufio.NewReader(strings.NewReader("val\n"))
	choices := []string{"0", "1", "2", "3", "4", "7", "14", "15", "16", "17", "18", "19", "20", "28", "29"}
	for _, choice := range choices {
		_ = runMenuChoice(choice, r)
	}

}

func TestCmdLogsAndSettingsAndDNSCheckAndUpdate(t *testing.T) {
	dir := setupMockGlobals(t)

	_ = cmdSettings([]string{"show", "--data", dir})
	_ = cmdSettings([]string{"set", "--data", dir, "--panel-port", "8443", "--defer-restart"})
	_ = cmdDNSCheck([]string{"example.com", "--json"})
	_ = cmdCert([]string{"renew", "--data", dir})
	_ = cmdFirewall([]string{"cleanup", "--json"})
	_ = cmdLifecycle([]string{"install", "--data", dir})
	_ = cmdLifecycle([]string{"remove", "--data", dir})
	_ = cmdUpdate([]string{"--check", "--data", dir})
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// printed. forgectl's local commands report through fmt.Println rather than an
// injectable writer, so this is the only way to assert on what an operator
// actually sees.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	out := <-done
	_ = r.Close()
	return out
}

func TestCmdCertResetRegeneratesTheSelfSignedCertificateAndRestartsThePanel(t *testing.T) {
	dir := setupMockGlobals(t)

	// setupMockGlobals already replaced systemctl and restores the original in
	// its own t.Cleanup, so recording over it here is undone automatically.
	var calls [][]string
	systemctl = func(args ...string) error {
		calls = append(calls, args)
		return nil
	}

	certDir := filepath.Join(dir, "certs")
	if _, _, err := cert.EnsureSelfSigned(certDir); err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	der := func() []byte {
		raw, err := os.ReadFile(filepath.Join(certDir, "self.crt"))
		if err != nil {
			t.Fatalf("read self.crt: %v", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("self.crt is not PEM")
		}
		return block.Bytes
	}
	before := sha256.Sum256(der())

	var out string
	var resetErr error
	out = captureStdout(t, func() {
		resetErr = cmdCert([]string{"reset", "--data", dir, "--yes"})
	})
	if resetErr != nil {
		t.Fatalf("cmdCert reset: %v", resetErr)
	}

	if after := sha256.Sum256(der()); after == before {
		t.Fatal("self.crt is byte-identical; EnsureSelfSigned's exists-check was never bypassed")
	}

	restarted := false
	for _, c := range calls {
		if reflect.DeepEqual(c, []string{"restart", "forgepanel"}) {
			restarted = true
		}
	}
	if !restarted {
		t.Fatal("no systemctl restart forgepanel; internal/cert/cert.go ssOnce memoizes the pair, so the live panel still serves the old cert")
	}

	// The whole point of the command is handing the operator the new pin to push
	// to every enrolled node; printing nothing makes the reset unusable.
	newPin := hex.EncodeToString(func() []byte { s := sha256.Sum256(der()); return s[:] }())
	if !strings.Contains(out, newPin) {
		t.Fatalf("new PANEL_FINGERPRINT %s not printed; output was:\n%s", newPin, out)
	}
}

func TestCmdCertResetRefusesOnADomainedPanel(t *testing.T) {
	dir := setupMockGlobals(t)

	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDataDir: %v", err)
	}
	cfg.Panel().Domain = "panel.example.com"
	if err := cfg.SavePanel(); err != nil {
		t.Fatalf("SavePanel: %v", err)
	}

	err = cmdCert([]string{"reset", "--data", dir, "--yes"})
	if err == nil {
		t.Fatal("cert reset was allowed on a panel with a domain; regenerating the self-signed pair there changes nothing the ACME/imported cert path uses")
	}
	if !strings.Contains(err.Error(), "panel.example.com") {
		t.Fatalf("refusal must name the domain it is protecting so the operator knows why; got %v", err)
	}
}

func TestCmdAdminListNamesTheAccountsWithoutLeakingSecrets(t *testing.T) {
	dir := setupMockGlobals(t)

	var listErr error
	out := captureStdout(t, func() {
		listErr = cmdAdmin([]string{"list", "--data", dir})
	})
	if listErr != nil {
		t.Fatalf("cmdAdmin list: %v", listErr)
	}
	if !strings.Contains(out, "admin") {
		t.Fatalf("admin list did not name the account an operator must pass to --user; output was:\n%s", out)
	}
	// setupMockGlobals stores the literal password hash "hash"; it must never
	// reach an operator's terminal or a pasted support thread.
	if strings.Contains(out, "hash") {
		t.Fatalf("admin list leaked credential material; output was:\n%s", out)
	}
}
