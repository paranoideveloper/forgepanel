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
	"syscall"
	"time"

	"github.com/forgepanel/forgepanel/internal/api"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/version"
)

func main() {
	// --version before anything else: it must work without a data directory,
	// a config, or the ability to bind a port, because it is what a package
	// smoke test and the release pipeline's metadata check call.
	for _, a := range os.Args[1:] {
		if a == "--version" || a == "-version" || a == "version" {
			fmt.Println(version.String("forgepanel"))
			return
		}
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
		// HTTPS by default: the panel always serves TLS. With a domain it uses the
		// ACME/imported certificate; with no domain it falls back to a self-signed
		// cert (browser warning, but the admin session and every config secret are
		// still encrypted rather than crossing the wire in cleartext).
		httpSrv.TLSConfig = srv.CertTLSConfig()
		if p.Domain != "" {
			// :80 helper answers ACME HTTP-01 challenges and redirects to HTTPS.
			go func() {
				h := &http.Server{Addr: ":80", Handler: srv.ACMEHTTPHandler(), ReadHeaderTimeout: 10 * time.Second}
				if e := h.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
					fmt.Fprintln(os.Stderr, "forgepanel: :80 ACME helper:", e)
				}
			}()
			// Issue/renew the domain's cert ahead of the first visit so the panel is
			// browser-trusted from the start instead of on the first domain handshake.
			srv.PrimePanelCert()
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
