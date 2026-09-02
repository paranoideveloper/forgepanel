// Command forgepanel is the ForgePanel server binary (spec §1). It resolves its
// panel-address/ACME configuration, serves the panel over HTTP (IP-based) or
// HTTPS (when a domain + automatic TLS are configured), and — on a fresh
// install — prints a one-time setup token instead of a random admin password.
// A failed bind after a settings change is rolled back automatically so the
// administrator can never be locked out.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/forgepanel/forgepanel/internal/api"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/version"
)

// usageText is the whole command-line surface.
//
// The variable list is checked against the tree by
// TestUsageNamesOnlyRealEnvironmentVariables, because the first version of it
// named FORGEPANEL_DATA_DIR and FORGEPANEL_PORT and neither exists — the real
// names are FORGEPANEL_DATA and FORGEPANEL_PANEL_PORT. That was found by
// putting the wrong one in a systemd unit and watching the panel write its
// database into the service's working directory instead. A help text that names
// variables which do nothing is worse than none, because it is believed.
// The panel takes its
// configuration from the data directory and the environment, not from flags, so
// this is short by design — but it has to SAY that, or the absence of options
// reads as a missing help text rather than as the design.
const usageText = `forgepanel — proxy panel server

Usage:
  forgepanel              run the panel
  forgepanel --version    print the version and exit
  forgepanel --help       print this message and exit

Configuration comes from the data directory and the environment, not from
flags. Every variable the panel reads:

  FORGEPANEL_DATA          data directory: database, secrets, certificates
  FORGEPANEL_PANEL_PORT    panel listen port
  FORGEPANEL_API_PORT      internal API port
  FORGEPANEL_SUB_PORT      subscription listen port
  FORGEPANEL_DNS_PORT      ForgeDNS listen port
  FORGEPANEL_DOMAIN        panel domain (implies HTTPS/ACME)
  FORGEPANEL_HTTPS         serve HTTPS
  FORGEPANEL_ACME_EMAIL    contact address for certificate expiry notices
  FORGEPANEL_ADMIN_USER    first administrator's username
  FORGEPANEL_TELEGRAM_TOKEN, FORGEPANEL_TELEGRAM_ADMINS
                           bot credentials; both are also settable in the panel

The ports and the domain are settable in the panel too, which persists them to
panel.json; the environment is read on start and the stored value wins after.

Administration is forgectl, not this binary: forgectl --help
`

func main() {
	// --version before anything else: it must work without a data directory,
	// a config, or the ability to bind a port, because it is what a package
	// smoke test and the release pipeline's metadata check call.
	for _, a := range os.Args[1:] {
		if a == "--version" || a == "-version" || a == "version" {
			fmt.Println(version.String("forgepanel"))
			return
		}
		if a == "--help" || a == "-help" || a == "-h" || a == "help" {
			fmt.Print(usageText)
			return
		}
		// Anything else is REFUSED rather than ignored.
		//
		// This loop used to recognise --version and let everything else fall
		// through to start(), so `forgepanel --help` started a panel listening
		// on :2053 — as did `forgepanel --port 8080`, `forgepanel --dry-run`,
		// and every typo. An operator checking usage on a live box brought up a
		// second panel instead, and a flag that looked accepted did nothing.
		// Found by running the binary on a real server; nothing in the test
		// suite exercised argv.
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "forgepanel: unknown option %q\n\n%s", a, usageText)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "forgepanel: unexpected argument %q\n\n%s", a, usageText)
		os.Exit(2)
	}
	cfg, srv, ln, err := start()
	if err != nil {
		// A bind failure after a settings change: restore the last-known-good
		// panel.json and try once more so a bad port/domain can't lock us out.
		if cfg != nil && config.RestoreRollback(cfg.DataDir) {
			fmt.Fprintln(os.Stderr, "forgepanel: new settings failed to bind — rolled back to previous configuration")
			releaseDataLock() // the retry re-takes it; do not block on ourselves
			cfg, srv, ln, err = start()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "forgepanel:", err)
			os.Exit(1)
		}
	}
	// Bound successfully — drop any stale rollback snapshot.
	config.ClearRollback(cfg.DataDir)

	banner(cfg, srv)

	p := cfg.Panel()
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		var serveErr error
		// Behind a platform edge, serve PLAIN HTTP.
		//
		// The edge already terminated TLS for the client and forwards the
		// decrypted request inward over http. Answering that with a TLS
		// handshake fails every request — and it fails in the least helpful
		// way, because the platform reports it as the app being unhealthy
		// rather than as a protocol mismatch. There is nothing to secure on
		// this hop: it is a loopback-equivalent link inside the platform, and
		// the certificate the client verified is the edge's.
		if cfg.PaaS().Enabled {
			serveErr = httpSrv.Serve(ln)
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, "forgepanel: serve:", serveErr)
				os.Exit(1)
			}
			return
		}
		// HTTPS by default: the panel always serves TLS. With a domain it uses the
		// ACME/imported certificate; with no domain it falls back to a self-signed
		// cert (browser warning, but the admin session and every config secret are
		// still encrypted rather than crossing the wire in cleartext).
		httpSrv.TLSConfig = srv.CertTLSConfig()
		if p.Domain != "" {
			// :80 helper answers ACME HTTP-01 challenges; the same managed helper is
			// (re)started from the address handler when a domain is saved at runtime,
			// so TLS never needs a restart to come up.
			srv.StartACMEHelper()
			// Issue/renew the domain's cert ahead of the first visit so the panel is
			// browser-trusted from the start instead of on the first domain handshake.
			srv.PrimePanelCert()
			// Bring every enabled reverse-tunnel bridge back up. The rows survive
			// a restart; without this the tunnels do not, and every inbound
			// reached through one goes dark until somebody notices.
			srv.StartBridges()
		}
		serveErr = httpSrv.ServeTLS(ln, "", "")
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "forgepanel: serve:", serveErr)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Println("\nforgepanel: shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = srv.Close()
	releaseDataLock()
}

// start loads config, builds the server, and opens the panel listener. Splitting
// this out lets main retry once after a rollback.
// dataUnlock releases the data-directory lock taken in start(). A failed bind
// re-runs start(), so it is released before retrying rather than deadlocking
// against ourselves.
var dataUnlock func() error

func releaseDataLock() {
	if dataUnlock != nil {
		_ = dataUnlock()
		dataUnlock = nil
	}
}

func start() (*config.Config, *api.Server, net.Listener, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("config: %w", err)
	}
	// Refuse to share a data directory with another running instance. The
	// systemd→Docker migration makes this easy to get wrong, and two panels on
	// one SQLite file corrupt traffic accounting in ways that are painful to
	// diagnose after the fact. The lock is advisory and released on exit.
	unlock, err := config.LockDataDir(cfg.DataDir)
	if err != nil {
		return cfg, nil, nil, err
	}
	dataUnlock = unlock
	srv, err := api.NewWithStore(cfg)
	if err != nil {
		releaseDataLock()
		return cfg, nil, nil, fmt.Errorf("store: %w", err)
	}
	p := cfg.Panel()
	bind := p.BindAddress
	if bind == "0.0.0.0" {
		bind = ""
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(p.Port)))
	if err != nil {
		_ = srv.Close()
		releaseDataLock()
		return cfg, srv, nil, fmt.Errorf("listen on %s:%d: %w", p.BindAddress, p.Port, err)
	}
	return cfg, srv, ln, nil
}

func banner(cfg *config.Config, srv *api.Server) {
	p := cfg.Panel()
	scheme := "https" // the panel always serves TLS (self-signed without a domain)
	pa := cfg.PaaS()
	if pa.Enabled {
		scheme = "http"
	}
	fmt.Println("┌─────────────────────────────────────────────┐")
	fmt.Println("│  ⚡ ForgePanel                               │")
	fmt.Println("└─────────────────────────────────────────────┘")
	// The build identity goes in the startup log so a support conversation can
	// start from what is actually running rather than what was meant to be.
	fmt.Printf("  %s\n", version.String("forgepanel"))
	if srv != nil {
		fmt.Printf("  Panel:  %s\n", srv.PublicURL())
	}
	fmt.Printf("  Listen: %s://%s:%d  (data: %s)\n", scheme, orAll(p.BindAddress), p.Port, cfg.DataDir)
	if pa.Enabled && pa.Domain == "" {
		// The single most common first-boot state on Railway, and the one that
		// looks most like a broken deploy: the service is up, the logs are
		// clean, and there is no address anywhere to open. Railway does not
		// create a hostname on its own — somebody has to ask for one — and
		// until they do there is no RAILWAY_PUBLIC_DOMAIN, so the panel cannot
		// print a URL and cannot put a working address in a client link either.
		// Say what to do, not just what is missing.
		fmt.Printf("  PaaS:   %s detected, but this service has NO PUBLIC DOMAIN yet.\n", pa.Platform)
		fmt.Println("          Railway does not create one automatically:")
		fmt.Println("            Settings → Networking → Public Networking → Generate Domain")
		fmt.Println("          The panel has no reachable address until then, and any inbound created")
		fmt.Println("          now gets a placeholder one. Both are corrected on the restart that")
		fmt.Println("          follows — generating a domain restarts the service by itself.")
	} else if pa.Enabled {
		// Say plainly what was detected and what it changed. A platform's log is
		// often the only diagnostic surface an operator has there — no shell, no
		// journal — so the mode being on has to be visible in it, or an inbound
		// that quietly went loopback-only looks like a bug in the panel.
		fmt.Printf("  PaaS:   %s — the edge terminates TLS on %s:443 and forwards plain HTTP here;\n",
			pa.Platform, pa.Domain)
		fmt.Println("          inbounds share this one port and are told apart by their transport path.")
	}
	if srv.SetupToken != "" {
		fmt.Println("  ── FIRST RUN — create your administrator account ──")
		fmt.Println("  Open the panel URL above and complete setup with this one-time token:")
		fmt.Printf("  Setup token:  %s\n", srv.SetupToken)
		fmt.Println("  (No admin password is generated — you choose it during setup.)")
	}
	fmt.Println()
}

func orAll(bind string) string {
	if bind == "" || bind == "0.0.0.0" {
		return "0.0.0.0"
	}
	return bind
}
