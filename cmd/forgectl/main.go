// Command forgectl is the ForgePanel CLI admin tool (spec §13). This core build
// ships the offline, engine-facing subcommands: keygen, convert (any link -> any
// format), and render (link -> engine config). The full build adds user/inbound
// management, migrate-from, backup/restore and node enroll against a running
// panel API.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/migrate"
	"github.com/forgepanel/forgepanel/internal/store"
	fpversion "github.com/forgepanel/forgepanel/internal/version"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/parse"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

func main() {
	if len(os.Args) < 2 {
		if interactiveTerminal() {
			if err := cmdMenu(nil); err != nil {
				fmt.Fprintln(os.Stderr, "forgectl:", err)
				os.Exit(1)
			}
			return
		}
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "provision":
		err = cmdProvision(os.Args[2:])
	case "edge":
		err = cmdEdge(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "convert":
		err = cmdConvert(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdBackup(append([]string{"restore"}, os.Args[2:]...))
	case "migrate":
		err = cmdMigrate(os.Args[2:])
	case "healthcheck":
		err = cmdHealth(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	case "logs":
		err = cmdLogs(os.Args[2:])
	case "settings":
		err = cmdSettings(os.Args[2:])
	case "dns-check":
		err = cmdDNSCheck(os.Args[2:])
	case "cert":
		err = cmdCert(os.Args[2:])
	case "admin":
		err = cmdAdmin(os.Args[2:])
	case "firewall":
		err = cmdFirewall(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "repair":
		err = cmdRepair(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "menu":
		err = cmdMenu(os.Args[2:])
	case "lifecycle":
		err = cmdLifecycle(os.Args[2:])
	case "version", "--version", "-v":
		err = cmdVersion(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "forgectl: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgectl:", err)
		printRemediation(os.Stderr, err)
		// Most commands are pass/fail; `edge` classifies its failures (auth,
		// name taken, not found, feed rejected) so a script can tell them apart.
		os.Exit(exitCodeFor(err))
	}
}

func usage() {
	fmt.Print(`forgectl — ForgePanel CLI

Usage:
  forgectl [menu]
  forgectl status [--json] [--data <dir>]
  forgectl service <start|stop|restart>
  forgectl logs [--follow] [--lines <n>]
  forgectl settings show [--json] [--data <dir>]
  forgectl settings set [--panel-port <n>] [--domain <host>] [--bind-address <ip>] [--https=<bool>] [--acme-email <email>] [--verify-dns]
  forgectl dns-check <domain> [--json]
  forgectl cert <status|renew|reset> [--yes] [--data <dir>]
  forgectl admin <list|reset-password|reset-2fa|regenerate-path> [--user <name>] [--data <dir>]
  forgectl backup <create|restore> <path> [--data <dir>]
  forgectl firewall <status|cleanup> [--json]
  forgectl uninstall [--keep-data|--purge] [--dry-run] [--yes] [--force] [--json]
  forgectl repair [--data <dir>]
  forgectl update [--check] [--yes] [--data <dir>]
  forgectl keygen <reality|uuid|shortid|ss2022|wireguard|ssh|password|mldsa65> [method]
  forgectl convert <link> <uri|xray|singbox|clash>
  forgectl render <link> <xray|singbox>
  forgectl edge <deploy|update|delete|status|push|rotate-path|token-url> [flags]
  forgectl healthcheck [port|url]   probe the running panel (container HEALTHCHECK)
  forgectl version

Examples:
  forgectl keygen reality
  forgectl keygen ss2022 2022-blake3-aes-256-gcm
  forgectl convert 'vless://uuid@host:443?security=reality&pbk=..#node' clash
  forgectl render  'vless://uuid@host:443?...' xray
`)
}

func cmdKeygen(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("keygen needs a kind")
	}
	var (
		v   any
		err error
	)
	switch strings.ToLower(args[0]) {
	case "reality":
		v, err = keygen.RealityKeys()
	case "uuid":
		v = map[string]string{"uuid": keygen.UUID()}
	case "shortid":
		sid, e := keygen.ShortID(8)
		v, err = map[string]string{"short_id": sid}, e
	case "ss2022":
		if len(args) < 2 {
			return fmt.Errorf("ss2022 needs a method, e.g. 2022-blake3-aes-256-gcm")
		}
		psk, e := keygen.SS2022PSK(args[1])
		v, err = map[string]string{"method": args[1], "psk": psk}, e
	case "wireguard":
		v, err = keygen.WireGuardKeys()
	case "ssh":
		v, err = keygen.SSHKeys()
	case "password":
		pw, e := keygen.Password(16)
		v, err = map[string]string{"password": pw}, e
	case "mldsa65":
		seed, e := keygen.MLDSA65Seed()
		v, err = map[string]string{"seed": seed}, e
	default:
		return fmt.Errorf("unknown keygen kind %q", args[0])
	}
	if err != nil {
		return err
	}
	return printJSON(v)
}

func cmdConvert(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("convert needs <link> <format>")
	}
	n, err := parse.URI(args[0])
	if err != nil {
		return err
	}
	switch strings.ToLower(args[1]) {
	case "uri":
		uri, err := export.URI(n)
		if err != nil {
			return err
		}
		fmt.Println(uri)
	case "clash":
		y, err := export.ClashYAML([]*model.Node{n})
		if err != nil {
			return err
		}
		fmt.Print(y)
	case "xray":
		return cmdRender([]string{args[0], "xray"})
	case "singbox", "sing-box":
		return cmdRender([]string{args[0], "singbox"})
	default:
		return fmt.Errorf("unknown format %q", args[1])
	}
	return nil
}

func cmdRender(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("render needs <link> <xray|singbox>")
	}
	n, err := parse.URI(args[0])
	if err != nil {
		return err
	}
	var b []byte
	switch strings.ToLower(args[1]) {
	case "xray":
		b, err = render.RenderXrayJSON(n)
	case "singbox", "sing-box":
		b, err = render.RenderSingboxJSON(n)
	default:
		return fmt.Errorf("unknown engine %q", args[1])
	}
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func cmdBackup(args []string) error {
	if err := requireLocalAdmin(); err != nil {
		return err
	}
	if len(args) == 0 || (args[0] != "create" && args[0] != "restore") {
		return fmt.Errorf("usage: forgectl backup <create|restore> <path> [--data <dir>]")
	}
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", defaultDataDir(), "panel data directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("backup %s needs exactly one file path", args[0])
	}
	cfg, err := loadLocalConfig(*data)
	if err != nil {
		return err
	}
	if cfg.MasterKey == "" {
		return fmt.Errorf("backup: data directory has no master key")
	}
	path := fs.Arg(0)
	switch args[0] {
	case "create":
		// One list, shared with the panel's own backup endpoint. Hardcoding it
		// here is why the certificates were outside every CLI backup while the
		// package doc claimed otherwise.
		files := backup.PanelFiles(cfg.DataDir)
		blob, err := backup.CreateWithManifest(cfg.MasterKey, cfg.DataDir, files, backupManifest(cfg.DataDir))
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			return err
		}
		auditLocal(cfg, "backup.create", path, "ok")
		fmt.Printf("wrote encrypted backup: %s (%d bytes)\n", path, len(blob))
		return nil
	case "restore":
		blob, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Check BEFORE stopping the panel. A backup this build cannot migrate is
		// refused either way; doing it first means a refused restore costs no
		// downtime at all instead of taking the panel down to say no.
		m, err := backup.ReadManifest(cfg.MasterKey, blob)
		if err != nil {
			return err
		}
		if err := backup.CheckRestorable(m, store.LatestSchemaVersion()); err != nil {
			return err
		}
		if m != nil {
			fmt.Printf("backup: written %s by panel %s at schema version %d (%d files)\n",
				m.CreatedAt.UTC().Format(time.RFC3339), orUnknown(m.PanelVersion), m.SchemaVersion, m.Files)
		}
		if err := systemctl("stop", "forgepanel"); err != nil {
			return err
		}
		files, err := backup.Restore(cfg.MasterKey, blob, cfg.DataDir)
		if err != nil {
			// Start it again. Leaving the panel stopped because a restore failed
			// turns a failed restore into an outage, and the data directory is
			// either untouched or half-written — in both cases the running panel
			// is what the operator needs in order to do anything next.
			if startErr := systemctl("start", "forgepanel"); startErr != nil {
				return fmt.Errorf("%w (and the panel could not be restarted: %v)", err, startErr)
			}
			return err
		}
		if err := systemctl("start", "forgepanel"); err != nil {
			return err
		}
		auditLocal(cfg, "backup.restore", path, "ok")
		fmt.Printf("restored %d files to %s\n", len(files), cfg.DataDir)
		return nil
	}
	return nil
}

func cmdMigrate(args []string) error {
	if len(args) < 2 || args[0] != "from-db" {
		return fmt.Errorf("usage: forgectl migrate from-db <panel.db>")
	}
	res, err := migrate.ImportPanelDB(args[1])
	if err != nil {
		return err
	}
	fmt.Printf("imported %d inbounds", len(res.Inbounds))
	users := 0
	for _, in := range res.Inbounds {
		users += len(in.Users)
	}
	fmt.Printf(" and %d users from an existing panel\n", users)
	for _, w := range res.Warnings {
		fmt.Println("  warning:", w)
	}
	return printJSON(res)
}

// backupManifest describes the database being backed up. Every field is
// best-effort: a manifest that cannot be filled in completely is still worth
// more than none, and a backup must never fail because the schema version could
// not be read.
func backupManifest(dataDir string) backup.Manifest {
	m := backup.Manifest{CreatedAt: time.Now().UTC(), PanelVersion: fpversion.Version}
	db, err := store.Open(filepath.Join(dataDir, "forgepanel.db"))
	if err != nil {
		return m
	}
	defer db.Close()
	if v, err := db.SchemaVersion(); err == nil {
		m.SchemaVersion = v
	}
	return m
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown version)"
	}
	return s
}
