package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/core/porthop"
	"github.com/forgepanel/forgepanel/internal/lifecycle"
	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
)

var loadManifest = lifecycle.Load

const systemDataDir = "/var/lib/forgepanel"

const releaseAPI = "https://api.github.com/repos/paranoideveloper/forgepanel/releases/latest"

var interactiveTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

var requireLocalAdmin = func() error {
	if os.Geteuid() != 0 {
		return errors.New("this operation requires root; run it with sudo")
	}
	return nil
}

func defaultDataDir() string {
	if data := strings.TrimSpace(os.Getenv("FORGEPANEL_DATA")); data != "" {
		return data
	}
	if m, err := loadManifest(lifecycle.DefaultManifestPath); err == nil && m.DataDir != "" {
		return m.DataDir
	}
	return systemDataDir
}

func loadLocalConfig(data string) (*config.Config, error) {
	if data == "" {
		data = defaultDataDir()
	}
	if _, err := os.Stat(filepath.Join(data, "panel.json")); err != nil {
		return nil, fmt.Errorf("panel data at %s is not initialized: %w", data, err)
	}
	return config.LoadFromDataDir(data)
}

var systemctl = func(args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is unavailable")
	}
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

var systemctlState = func() string {
	cmd := exec.Command("systemctl", "is-active", "forgepanel")
	b, err := cmd.Output()
	if err != nil {
		return "inactive"
	}
	return strings.TrimSpace(string(b))
}

func jsonOutput(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// panelURL is the address forgectl uses to reach the panel — for `settings
// show`, and for the health check that decides whether a settings change is
// kept or rolled back.
//
// The scheme is ALWAYS https. The panel always serves TLS: self-signed when no
// domain is set, ACME once one is (see api.Server.PublicURL, which hardcodes
// the same thing). This function used to emit http:// unless BOTH HTTPSEnabled
// and Domain were set, which is exactly the state of a fresh install — so the
// post-change health probe hit http:// against a TLS listener, failed, and
// `forgectl settings set` rolled the change back every time. Setting a domain
// on a default install was therefore impossible, which also made it impossible
// to ever obtain an ACME certificate. Measured on a live host: the panel
// answered https 200 and http 400 while settings reported https_enabled=false.
//
// The probe itself already tolerates a self-signed certificate (see probe()),
// so https is safe here before a real certificate exists.
func panelURL(p *config.PanelSettings) string {
	host := p.Domain
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("https://%s:%d%s", host, p.Port, p.AdminPath)
}

func localActor() string {
	u, err := user.Current()
	if err != nil {
		return fmt.Sprintf("local uid=%d", os.Geteuid())
	}
	return fmt.Sprintf("local uid=%d user=%s", os.Geteuid(), u.Username)
}

func auditLocal(cfg *config.Config, action, target, result string) {
	db, err := store.Open(filepath.Join(cfg.DataDir, "forgepanel.db"))
	if err != nil {
		return
	}
	db.Audit(&store.AuditLog{Actor: localActor(), IP: "local", Action: action, Target: target, Diff: result})
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	jsonMode := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil {
		return err
	}
	p := cfg.Panel()
	out := map[string]any{
		"service":       systemctlState(),
		"data_dir":      cfg.DataDir,
		"panel_url":     panelURL(p),
		"admin_path":    p.AdminPath,
		"port":          p.Port,
		"bind_address":  p.BindAddress,
		"domain":        p.Domain,
		"https_enabled": p.HTTPSEnabled,
	}
	if *jsonMode {
		return jsonOutput(out)
	}
	for _, k := range []string{"service", "panel_url", "data_dir", "bind_address", "port", "domain", "https_enabled"} {
		fmt.Printf("%-15s %v\n", k+":", out[k])
	}
	return nil
}

func cmdService(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: forgectl service <start|stop|restart>")
	}
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	switch args[0] {
	case "start", "stop", "restart":
		if err := systemctl(args[0], "forgepanel"); err != nil {
			return err
		}
		if cfg, err := loadLocalConfig(defaultDataDir()); err == nil {
			auditLocal(cfg, "service."+args[0], "forgepanel", "ok")
		}
		return nil
	default:
		return errors.New("usage: forgectl service <start|stop|restart>")
	}
}

func cmdLogs(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	follow := fs.Bool("follow", false, "follow new log entries")
	lines := fs.Int("lines", 100, "number of recent log entries")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *lines < 1 {
		return errors.New("usage: forgectl logs [--follow] [--lines <n>]")
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return errors.New("journalctl is unavailable")
	}
	command := []string{"-u", "forgepanel", "-n", strconv.Itoa(*lines)}
	if *follow {
		command = append(command, "-f")
	} else {
		command = append(command, "--no-pager")
	}
	cmd := exec.Command("journalctl", command...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func cmdSettings(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: forgectl settings <show|set>")
	}
	switch args[0] {
	case "show":
		return cmdSettingsShow(args[1:])
	case "set":
		return cmdSettingsSet(args[1:])
	default:
		return errors.New("usage: forgectl settings <show|set>")
	}
}

func cmdSettingsShow(args []string) error {
	fs := flag.NewFlagSet("settings show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	jsonMode := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return cmdStatus(append([]string{"--data", *data}, boolArg("--json", *jsonMode)...))
}

func boolArg(name string, enabled bool) []string {
	if enabled {
		return []string{name}
	}
	return nil
}

func cmdSettingsSet(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("settings set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	port := fs.Int("panel-port", 0, "panel TCP port")
	domain := fs.String("domain", "", "panel domain")
	bind := fs.String("bind-address", "", "bind IP address")
	https := fs.String("https", "", "true or false")
	email := fs.String("acme-email", "", "ACME contact email")
	verifyDNS := fs.Bool("verify-dns", false, "require A/AAAA to point to this host")
	bootstrap := fs.Bool("bootstrap", false, "initialize a missing panel.json before applying settings")
	deferRestart := fs.Bool("defer-restart", false, "persist settings without restarting the service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	settingCount := 0
	for name := range seen {
		if name != "data" && name != "bootstrap" && name != "defer-restart" && name != "verify-dns" {
			settingCount++
		}
	}
	if settingCount == 0 {
		return errors.New("settings set needs at least one setting")
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil && *bootstrap {
		cfg, err = config.LoadFromDataDir(*data)
	}
	if err != nil {
		return err
	}
	change := settings.Change{VerifyDNS: *verifyDNS}
	if seen["panel-port"] {
		change.Port = port
	}
	if seen["domain"] {
		change.Domain = domain
	}
	if seen["bind-address"] {
		change.BindAddress = bind
	}
	if seen["acme-email"] {
		change.ACMEEmail = email
	}
	if seen["https"] {
		v, err := strconv.ParseBool(*https)
		if err != nil {
			return errors.New("--https must be true or false")
		}
		change.HTTPSEnabled = &v
	}
	result, err := settings.New(cfg).Apply(change)
	if err != nil {
		return err
	}
	if result.RestartRequired && !*deferRestart {
		if err := restartAndVerify(cfg); err != nil {
			if config.RestoreRollback(cfg.DataDir) {
				_ = systemctl("restart", "forgepanel")
			}
			return fmt.Errorf("settings rolled back after failed restart: %w", err)
		}
	}
	config.ClearRollback(cfg.DataDir)
	auditLocal(cfg, "settings.set", "panel", "ok")
	fmt.Printf("panel URL: %s\n", panelURL(cfg.Panel()))
	return nil
}

// verifyHealthDeadline bounds how long a settings change waits for the panel to
// come back before deciding the change broke it.
//
// It is generous on purpose. The cost of waiting too long is a slow command;
// the cost of waiting too little is rolling back a change that was perfectly
// good, which is far worse and much harder for an operator to diagnose.
const verifyHealthDeadline = 45 * time.Second

var verifyHealth = func(cfg *config.Config) error {
	// systemctl restart returns once systemd has forked the unit, NOT once the
	// panel has bound its port. Probing immediately therefore raced the restart
	// and reported "connection refused" for a panel that was about to come up
	// perfectly — and because a failed probe rolls the change back, setting a
	// domain failed every time on a real host even though the panel was healthy
	// seconds later. Measured: `forgectl settings set --domain ...` rolled back
	// while the panel was `active` and answering immediately afterwards.
	//
	// The first boot after enabling a domain is also the slowest one, because
	// that is when ACME runs, so this is exactly the change most likely to be
	// rolled back by an impatient probe.
	port := strconv.Itoa(cfg.Panel().Port)
	deadline := time.Now().Add(verifyHealthDeadline)
	var err error
	for {
		if err = cmdHealth([]string{port}); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Second)
	}
}

func restartAndVerify(cfg *config.Config) error {
	if err := systemctl("restart", "forgepanel"); err != nil {
		return err
	}
	return verifyHealth(cfg)
}

func cmdDNSCheck(args []string) error {
	fs := flag.NewFlagSet("dns-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonMode := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: forgectl dns-check <domain> [--json]")
	}
	domain := settings.NormalizeDomain(fs.Arg(0))
	if !settings.ValidDomain(domain) {
		return errors.New("invalid domain")
	}
	v4, v6, err := settings.ResolveDomain(domain)
	out := map[string]any{"domain": domain, "a": v4, "aaaa": v6, "resolves": err == nil}
	if err != nil {
		out["error"] = err.Error()
	}
	if *jsonMode {
		return jsonOutput(out)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s\nA: %s\nAAAA: %s\n", domain, strings.Join(v4, ", "), strings.Join(v6, ", "))
	return nil
}

func cmdCert(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: forgectl cert <status|renew|reset> [--yes] [--data <dir>]")
	}
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (reset only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return certStatus(cfg)
	case "renew":
		if err := requireLocalAdmin(); err != nil {
			return err
		}
		return renewCert(cfg)
	case "reset":
		if err := requireLocalAdmin(); err != nil {
			return err
		}
		return resetCert(cfg, *yes)
	default:
		return errors.New("usage: forgectl cert <status|renew|reset> [--yes] [--data <dir>]")
	}
}

func certStatus(cfg *config.Config) error {
	p := cfg.Panel()
	out := map[string]any{"domain": p.Domain, "https_enabled": p.HTTPSEnabled, "acme_enabled": p.ACME.Enabled, "certificate_path": p.ACME.CertPath, "renewal_error": p.ACME.RenewalError}
	if p.ACME.CertPath != "" {
		if raw, err := os.ReadFile(p.ACME.CertPath); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					out["not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
					out["days_remaining"] = int(time.Until(cert.NotAfter).Hours() / 24)
				}
			}
		}
	}
	return jsonOutput(out)
}

func renewCert(cfg *config.Config) error {
	p := cfg.Panel()
	if !p.HTTPSEnabled || p.Domain == "" {
		return errors.New("configure a domain and HTTPS before renewing a certificate")
	}
	if err := systemctl("restart", "forgepanel"); err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port)), 10*time.Second)
	if err != nil {
		return err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: p.Domain, InsecureSkipVerify: true}) //nolint:gosec // local ACME trigger
	err = tlsConn.Handshake()
	_ = tlsConn.Close()
	if err != nil {
		return fmt.Errorf("certificate trigger handshake: %w", err)
	}
	auditLocal(cfg, "cert.renew", p.Domain, "triggered")
	return certStatus(cfg)
}

// selfSignedPins derives the two pins that everything downstream of the panel's
// self-signed certificate depends on: hex(SHA-256(DER)), which the panel bakes
// into each node unit as PANEL_FINGERPRINT, and base64(SHA-256(SPKI)), which the
// enrol one-liner passes to curl as --pinnedpubkey. Both derivations are
// deliberately identical to api.Server.panelCertFingerprint and
// api.Server.panelCertPubkeyPin — a pin computed any other way would not match
// the one the panel hands out at enrolment, and the node would read the
// mismatch as interception.
//
// An unreadable or corrupt certificate yields empty strings rather than an
// error: a panel whose certificate cannot be parsed is the one that needs a
// reset most, so the caller reports "(none)" and carries on.
func selfSignedPins(certPath string) (fingerprint, pubkeyPin string) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return "", ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", ""
	}
	sum := sha256.Sum256(block.Bytes)
	fingerprint = hex.EncodeToString(sum[:])
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fingerprint, ""
	}
	spki := sha256.Sum256(crt.RawSubjectPublicKeyInfo)
	return fingerprint, base64.StdEncoding.EncodeToString(spki[:])
}

// resetCert regenerates the panel's self-signed certificate.
//
// cert.EnsureSelfSigned is create-once and nothing in the panel ever reissued
// the pair, while the certificate bakes in the host's routable addresses as IP
// SANs. So after a server IP change the certificate is permanently wrong for the
// address nodes dial: enrolment dies with "doesn't contain any IP SANs" and
// there was no supported way to fix it short of deleting files by hand and
// guessing at the consequences. This is that fix, with the consequences printed.
func resetCert(cfg *config.Config, assumeYes bool) error {
	p := cfg.Panel()
	// With a domain configured the panel serves an ACME/imported certificate and
	// neither pin is even computed (both panelCertFingerprint and the export
	// defaults short-circuit on a real cert), so regenerating the self-signed
	// pair would destroy node trust to fix nothing.
	if d := strings.TrimSpace(p.Domain); d != "" {
		return fmt.Errorf("this panel serves an ACME/imported certificate for %s; use `forgectl cert renew`", d)
	}
	certDir := filepath.Join(cfg.DataDir, "certs")
	certFile := filepath.Join(certDir, "self.crt")
	// Read the outgoing pins BEFORE the file is replaced; an operator who has to
	// hand-edit node units needs to recognise the old value there.
	oldFP, oldPub := selfSignedPins(certFile)
	if !assumeYes && !confirmLocal("This invalidates every node pin and every issued xray client link. Continue? [y/N]") {
		return errors.New("aborted")
	}
	if _, _, err := cert.ResetSelfSigned(certDir); err != nil {
		return err
	}
	newFP, newPub := selfSignedPins(certFile)
	// Mandatory, not tidiness: cert.Store.selfSignedCert memoizes the pair behind
	// a sync.Once for the life of the process. Without the restart the file on disk
	// is new and the panel still presents the old certificate, so the operator
	// pins a fingerprint the panel does not serve and every node refuses to
	// connect as if intercepted — strictly worse than before the reset.
	if err := systemctl("restart", "forgepanel"); err != nil {
		return err
	}
	// A plain restart plus health probe, never restartAndVerify wrapped in the
	// rollback pattern cmdSettingsSet uses: there is nothing to roll back to, and
	// reverting a rescue is the bug.
	if err := verifyHealth(cfg); err != nil {
		return err
	}
	auditLocal(cfg, "cert.reset", "panel", "ok")
	// A cert that could not be read or parsed is reported, not hidden: the
	// operator still needs the new pin, and the missing old one explains why the
	// panel was broken.
	shown := func(prefix, v string) string {
		if v == "" {
			return "(none)"
		}
		return prefix + v
	}
	fmt.Println("panel self-signed certificate regenerated")
	fmt.Println("old PANEL_FINGERPRINT:", shown("", oldFP))
	fmt.Println("new PANEL_FINGERPRINT:", shown("", newFP))
	fmt.Println("old --pinnedpubkey:   ", shown("sha256//", oldPub))
	fmt.Println("new --pinnedpubkey:   ", shown("sha256//", newPub))
	fmt.Println()
	fmt.Println("Every enrolled node still pins the old certificate. Remediation:")
	fmt.Println("  1. on each node, set Environment=PANEL_FINGERPRINT=" + newFP)
	fmt.Println("     in /etc/systemd/system/forgenode.service, then")
	fmt.Println("     systemctl daemon-reload && systemctl restart forgenode")
	fmt.Println("  2. re-export and redistribute subscriptions: xray client links carry the")
	fmt.Println("     old certificate hash as pinnedPeerCertSha256 and will not connect")
	fmt.Println("     until each user re-fetches their subscription")
	fmt.Println("  3. sing-box-rendered protocols need no action; they use insecure, not a pin")
	return nil
}

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: forgectl admin <list|reset-password|reset-2fa|regenerate-path>")
	}
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	username := fs.String("user", "", "administrator username")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return cmdAdminList(cfg)
	case "reset-password":
		if *username == "" {
			return errors.New("--user is required")
		}
		return resetPassword(cfg, *username)
	case "reset-2fa":
		if *username == "" {
			return errors.New("--user is required")
		}
		return reset2FA(cfg, *username)
	case "regenerate-path":
		return regeneratePath(cfg)
	default:
		return errors.New("usage: forgectl admin <list|reset-password|reset-2fa|regenerate-path>")
	}
}

// cmdAdminList prints the administrator accounts.
//
// reset-password and reset-2fa both demand --user, and the only place a username
// could be read was the web UI — precisely what an operator reaching for
// forgectl admin has lost. Store.ListAdmins already existed; its sole caller was
// the HTTP handler behind that login.
func cmdAdminList(cfg *config.Config) error {
	db, err := store.Open(filepath.Join(cfg.DataDir, "forgepanel.db"))
	if err != nil {
		return err
	}
	admins, err := db.ListAdmins()
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(admins))
	for _, a := range admins {
		// Assembled field by field rather than marshalling store.Admin: the
		// record carries PasswordHash, TOTPSecret and RecoveryCodes, and rescue
		// output is exactly the sort of thing that gets pasted into a support
		// thread. Whether 2FA is on is all an operator needs to know about it.
		out = append(out, map[string]any{
			"id":           a.ID,
			"username":     a.Username,
			"role":         a.Role,
			"enabled":      !a.Disabled,
			"totp_enabled": a.TOTPSecret != "",
		})
	}
	return jsonOutput(out)
}

var promptSecret = func(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("a terminal is required for secret input")
	}
	fmt.Fprint(os.Stderr, label+": ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func resetPassword(cfg *config.Config, username string) error {
	first, err := promptSecret("New password")
	if err != nil {
		return err
	}
	second, err := promptSecret("Confirm new password")
	if err != nil {
		return err
	}
	if len(first) < 8 || first != second {
		return errors.New("passwords must match and be at least 8 characters")
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "forgepanel.db"))
	if err != nil {
		return err
	}
	admin, err := db.AdminByUsername(username)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(first)
	if err != nil {
		return err
	}
	admin.PasswordHash = hash
	if err := db.SaveAdmin(admin); err != nil {
		return err
	}
	if err := db.BumpAdminSessionEpoch(admin.ID); err != nil {
		return err
	}
	auditLocal(cfg, "admin.reset_password", username, "ok")
	fmt.Println("password reset; all existing sessions were revoked")
	return nil
}

func reset2FA(cfg *config.Config, username string) error {
	db, err := store.Open(filepath.Join(cfg.DataDir, "forgepanel.db"))
	if err != nil {
		return err
	}
	admin, err := db.AdminByUsername(username)
	if err != nil {
		return err
	}
	admin.TOTPSecret, admin.RecoveryCodes, admin.LastTOTPStep = "", "", 0
	if err := db.SaveAdmin(admin); err != nil {
		return err
	}
	if err := db.BumpAdminSessionEpoch(admin.ID); err != nil {
		return err
	}
	auditLocal(cfg, "admin.reset_2fa", username, "ok")
	fmt.Println("2FA reset; all existing sessions were revoked")
	return nil
}

func regeneratePath(cfg *config.Config) error {
	release, err := config.LockSettings(cfg.DataDir)
	if err != nil {
		return err
	}
	defer release()
	if err := cfg.ReloadPanel(); err != nil {
		return err
	}
	old := config.ClonePanel(cfg.Panel())
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	cfg.Panel().AdminPath = "/panel/" + hex.EncodeToString(b)
	if err := cfg.WriteRollback(&old); err != nil {
		return err
	}
	if err := cfg.SavePanel(); err != nil {
		return err
	}
	if err := restartAndVerify(cfg); err != nil {
		if config.RestoreRollback(cfg.DataDir) {
			_ = systemctl("restart", "forgepanel")
		}
		return fmt.Errorf("admin path rolled back after failed restart: %w", err)
	}
	config.ClearRollback(cfg.DataDir)
	auditLocal(cfg, "admin.regenerate_path", "panel", "ok")
	fmt.Println("new panel URL:", panelURL(cfg.Panel()))
	return nil
}

func cmdFirewall(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: forgectl firewall <status|cleanup> [--json]")
	}
	fs := flag.NewFlagSet("firewall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonMode := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	mgr := porthop.New()
	switch args[0] {
	case "status":
		out := map[string]any{"backend": mgr.Backend(), "net_admin": porthop.HasNetAdmin(), "rules": mgr.Rules()}
		if *jsonMode {
			return jsonOutput(out)
		}
		fmt.Printf("backend: %s\nnet_admin: %t\n", mgr.Backend(), porthop.HasNetAdmin())
		for _, rule := range mgr.Rules() {
			fmt.Println(rule)
		}
		return nil
	case "cleanup":
		if err := requireLocalAdmin(); err != nil {
			return err
		}
		if err := mgr.CleanupOwned(); err != nil {
			return err
		}
		if cfg, err := loadLocalConfig(defaultDataDir()); err == nil {
			auditLocal(cfg, "firewall.cleanup", "porthop", "ok")
		}
		fmt.Println("removed ForgePanel-owned port-hopping firewall rules")
		return nil
	default:
		return errors.New("usage: forgectl firewall <status|cleanup> [--json]")
	}
}

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// cmdLifecycle is intentionally small and machine-oriented. It is used by the
// canonical installer and package hooks after their transaction has succeeded.
func cmdLifecycle(args []string) error {
	if len(args) == 0 || args[0] != "record-install" {
		return errors.New("usage: forgectl lifecycle record-install [flags]")
	}
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("lifecycle record-install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	method := fs.String("method", "curl", "installation method")
	versionValue := fs.String("version", version, "installed version")
	data := fs.String("data", systemDataDir, "data directory")
	manifestPath := fs.String("manifest", lifecycle.DefaultManifestPath, "manifest path")
	var resources, backups multiString
	fs.Var(&resources, "resource", "kind:path:created (repeatable)")
	fs.Var(&backups, "backup", "path=backup-path (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backupFor := map[string]string{}
	for _, value := range backups {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid --backup %q", value)
		}
		backupFor[parts[0]] = parts[1]
	}
	m, err := loadManifest(*manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		m = lifecycle.NewManifest(*method, *versionValue, *data)
	} else if err != nil {
		return err
	} else {
		m.InstallMethod = *method
		m.Version = *versionValue
		m.InstalledAt = time.Now().UTC()
		m.DataDir = filepath.Clean(*data)
	}
	m.InstallerVersion = version
	m.Firewall = []string{"nftables:inet forgepanel_porthop", "iptables:forgepanel-porthop-*", "ip6tables:forgepanel-porthop-*"}
	m.SystemChanges = []string{"systemd:forgepanel.service", "systemctl:daemon-reload", "systemctl:enable forgepanel"}
	for _, value := range resources {
		parts := strings.SplitN(value, ":", 3)
		if len(parts) != 3 {
			return fmt.Errorf("invalid --resource %q", value)
		}
		created, err := strconv.ParseBool(parts[2])
		if err != nil {
			return fmt.Errorf("invalid created flag in %q", value)
		}
		if err := m.AddOrUpdateResource(parts[0], parts[1], created, backupFor[parts[1]]); err != nil {
			return err
		}
	}
	if err := m.Save(*manifestPath); err != nil {
		return err
	}
	fmt.Println("wrote installation manifest:", *manifestPath)
	return nil
}

func cmdUninstall(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	purge := fs.Bool("purge", false, "remove manifest-owned data")
	keepData := fs.Bool("keep-data", false, "explicitly preserve data")
	dryRun := fs.Bool("dry-run", false, "report actions without changing the system")
	yes := fs.Bool("yes", false, "confirm destructive purge")
	force := fs.Bool("force", false, "remove changed manifest-owned files")
	jsonMode := fs.Bool("json", false, "JSON output")
	data := fs.String("data", defaultDataDir(), "panel data directory")
	manifestPath := fs.String("manifest", lifecycle.DefaultManifestPath, "manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *purge && *keepData {
		return errors.New("--purge and --keep-data cannot be used together")
	}
	if *purge && !*yes {
		if !interactiveTerminal() {
			return errors.New("--purge requires --yes when no terminal is available")
		}
		if !confirmLocal("Permanently remove ForgePanel data and certificates? [y/N]") {
			fmt.Println("uninstall cancelled")
			return nil
		}
	}
	m, err := loadManifest(*manifestPath)
	legacy := false
	if errors.Is(err, os.ErrNotExist) {
		m, legacy = lifecycle.LegacyInventory(*data), true
	} else if err != nil {
		return err
	}
	if !*dryRun {
		_ = systemctl("stop", "forgepanel")
		_ = systemctl("kill", "--kill-who=all", "forgepanel")
		_ = systemctl("disable", "forgepanel")
		_ = systemctl("reset-failed", "forgepanel")
		_ = systemctl("daemon-reload")
	}
	summary, cleanErr := m.CleanupFiles(*purge, *dryRun, *force)
	if !*dryRun {
		mgr := porthop.New()
		if err := mgr.CleanupOwned(); err != nil {
			summary.Incomplete = true
			summary.Actions = append(summary.Actions, lifecycle.Action{Path: "firewall", Action: "kept", Reason: err.Error()})
		} else {
			summary.Actions = append(summary.Actions, lifecycle.Action{Path: "firewall", Action: "removed", Reason: "ForgePanel-owned rules"})
		}
	}
	if *purge && !summary.Incomplete && !legacy && !*dryRun {
		if err := os.Remove(*manifestPath); err != nil && !os.IsNotExist(err) {
			summary.Incomplete = true
			summary.Actions = append(summary.Actions, lifecycle.Action{Path: *manifestPath, Action: "kept", Reason: err.Error()})
		} else {
			summary.Actions = append(summary.Actions, lifecycle.Action{Path: *manifestPath, Action: "removed", Reason: "purge"})
		}
	}
	result := map[string]any{"legacy_inventory": legacy, "purge": *purge, "dry_run": *dryRun, "summary": summary}
	if *jsonMode {
		_ = jsonOutput(result)
	} else {
		for _, action := range summary.Actions {
			fmt.Printf("%-14s %s", action.Action, action.Path)
			if action.Reason != "" {
				fmt.Printf(" (%s)", action.Reason)
			}
			fmt.Println()
		}
	}
	if cleanErr != nil {
		return cleanErr
	}
	if summary.Incomplete {
		return errors.New("uninstall incomplete; retained resources are listed above")
	}
	return nil
}

var confirmLocal = func(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt+" ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func cmdRepair(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil {
		return err
	}
	if _, err := loadManifest(lifecycle.DefaultManifestPath); err != nil {
		return errors.New("installation manifest is missing; run the verified installer to repair a legacy installation")
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "forgepanel"); err != nil {
		return err
	}
	if err := restartAndVerify(cfg); err != nil {
		return err
	}
	auditLocal(cfg, "installation.repair", "forgepanel", "ok")
	fmt.Println("ForgePanel service repaired and healthy")
	return nil
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type releaseMetadata struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

var latestRelease = func() (releaseMetadata, error) {
	req, err := http.NewRequest(http.MethodGet, releaseAPI, nil)
	if err != nil {
		return releaseMetadata{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "forgectl")
	// GitHub, not the local panel: this has to honour the configured egress
	// proxy, because the network that cannot reach api.github.com directly is
	// exactly the one an operator runs `forgectl update` on.
	client := netegress.Client(20 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return releaseMetadata{}, fmt.Errorf("check latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return releaseMetadata{}, fmt.Errorf("check latest release: GitHub returned %s", resp.Status)
	}
	var metadata releaseMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&metadata); err != nil {
		return releaseMetadata{}, fmt.Errorf("decode latest release: %w", err)
	}
	if metadata.TagName == "" {
		return releaseMetadata{}, errors.New("latest release did not include a tag")
	}
	return metadata, nil
}

func releaseAssetURL(metadata releaseMetadata, name string) (string, error) {
	for _, asset := range metadata.Assets {
		if asset.Name == name && asset.URL != "" {
			return asset.URL, nil
		}
	}
	return "", fmt.Errorf("release %s does not contain %s", metadata.TagName, name)
}

var downloadReleaseAsset = func(client *http.Client, metadata releaseMetadata, name string) ([]byte, error) {
	url, err := releaseAssetURL(metadata, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "forgectl")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download %s: GitHub returned %s", name, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func installerChecksum(checksums []byte) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != "install.sh" {
			continue
		}
		if len(fields[0]) != 64 {
			break
		}
		for _, c := range fields[0] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return "", errors.New("install.sh checksum is not hexadecimal")
			}
		}
		return strings.ToLower(fields[0]), nil
	}
	return "", errors.New("release did not provide an install.sh checksum")
}

func cmdUpdate(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	checkOnly := fs.Bool("check", false, "only check for a newer release")
	yes := fs.Bool("yes", false, "install the update without another confirmation")
	data := fs.String("data", defaultDataDir(), "panel data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: forgectl update [--check] [--yes] [--data <dir>]")
	}
	metadata, err := latestRelease()
	if err != nil {
		return err
	}
	result := map[string]any{"installed": version, "latest": metadata.TagName, "update_available": version != metadata.TagName}
	if *checkOnly {
		return jsonOutput(result)
	}
	if version == metadata.TagName {
		fmt.Printf("ForgePanel is already at %s\n", metadata.TagName)
		return nil
	}
	if !*yes {
		if !interactiveTerminal() {
			return errors.New("non-interactive update requires --yes")
		}
		if !confirmLocal(fmt.Sprintf("Install ForgePanel %s? [y/N]", metadata.TagName)) {
			fmt.Println("update cancelled")
			return nil
		}
	}
	client := netegress.Client(60 * time.Second)
	script, err := downloadReleaseAsset(client, metadata, "install.sh")
	if err != nil {
		return err
	}
	checksumFile, err := downloadReleaseAsset(client, metadata, "install.sh.sha256")
	if err != nil {
		return err
	}
	expected, err := installerChecksum(checksumFile)
	if err != nil {
		return err
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(script))
	if actual != expected {
		return errors.New("install.sh checksum verification failed")
	}
	tmpDir, err := os.MkdirTemp("", "forgepanel-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	installer := filepath.Join(tmpDir, "install.sh")
	if err := os.WriteFile(installer, script, 0o700); err != nil {
		return err
	}
	cmd := exec.Command("bash", installer, "--yes", "--version", metadata.TagName, "--data", *data)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verified installer failed: %w", err)
	}
	if cfg, err := loadLocalConfig(*data); err == nil {
		auditLocal(cfg, "installation.update", metadata.TagName, "ok")
	}
	return nil
}

func cmdMenu([]string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	if !interactiveTerminal() {
		return errors.New("forgectl menu requires an interactive terminal")
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nForgePanel local management\n\n")
		for _, line := range []string{
			" 1) Status and panel URL", " 2) Start panel", " 3) Stop panel", " 4) Restart panel", " 5) Recent logs", " 6) Follow logs",
			" 7) Show settings", " 8) Change panel port", " 9) Change domain", "10) Change bind address", "11) Enable/disable HTTPS", "12) Change ACME email",
			"13) Check domain DNS", "14) Certificate status", "15) Request/renew certificate", "16) Regenerate admin path", "17) Reset administrator password", "18) Reset administrator 2FA",
			"19) Create encrypted backup", "20) Restore encrypted backup", "21) Check firewall", "22) Clean firewall", "23) Repair installation", "24) Uninstall", "25) Purge uninstall", "26) Check for updates", "27) Install update",
			"28) Reset panel self-signed certificate", "29) List administrator accounts", " 0) Exit",
		} {
			fmt.Println(line)
		}
		fmt.Print("\nChoice: ")
		choice, _ := reader.ReadString('\n')
		if err := runMenuChoice(strings.TrimSpace(choice), reader); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		if strings.TrimSpace(choice) == "0" {
			return nil
		}
	}
}

func menuPrompt(reader *bufio.Reader, label string) string {
	fmt.Print(label + ": ")
	value, _ := reader.ReadString('\n')
	return strings.TrimSpace(value)
}

func runMenuChoice(choice string, reader *bufio.Reader) error {
	switch choice {
	case "0":
		return nil
	case "1":
		return cmdStatus(nil)
	case "2":
		return cmdService([]string{"start"})
	case "3":
		return cmdService([]string{"stop"})
	case "4":
		return cmdService([]string{"restart"})
	case "5":
		return cmdLogs(nil)
	case "6":
		return cmdLogs([]string{"--follow"})
	case "7":
		return cmdSettingsShow(nil)
	case "8":
		return cmdSettingsSet([]string{"--panel-port", menuPrompt(reader, "Panel port")})
	case "9":
		return cmdSettingsSet([]string{"--domain", menuPrompt(reader, "Panel domain")})
	case "10":
		return cmdSettingsSet([]string{"--bind-address", menuPrompt(reader, "Bind address")})
	case "11":
		return cmdSettingsSet([]string{"--https", menuPrompt(reader, "Enable HTTPS (true/false)")})
	case "12":
		return cmdSettingsSet([]string{"--acme-email", menuPrompt(reader, "ACME email")})
	case "13":
		return cmdDNSCheck([]string{menuPrompt(reader, "Domain")})
	case "14":
		return cmdCert([]string{"status"})
	case "15":
		return cmdCert([]string{"renew"})
	case "16":
		return cmdAdmin([]string{"regenerate-path"})
	case "17":
		return cmdAdmin([]string{"reset-password", "--user", menuPrompt(reader, "Administrator username")})
	case "18":
		return cmdAdmin([]string{"reset-2fa", "--user", menuPrompt(reader, "Administrator username")})
	case "19":
		return cmdBackup([]string{"create", menuPrompt(reader, "Backup output path")})
	case "20":
		return cmdBackup([]string{"restore", menuPrompt(reader, "Backup input path")})
	case "21":
		return cmdFirewall([]string{"status"})
	case "22":
		return cmdFirewall([]string{"cleanup"})
	case "23":
		return cmdRepair(nil)
	case "24":
		return cmdUninstall(nil)
	case "25":
		return cmdUninstall([]string{"--purge"})
	case "26":
		return cmdUpdate([]string{"--check"})
	case "27":
		return cmdUpdate([]string{"--yes"})
	case "28":
		return cmdCert([]string{"reset"})
	case "29":
		return cmdAdmin([]string{"list"})
	default:
		return errors.New("unknown choice")
	}
}
