// Command forgepanel is the ForgePanel server binary (spec §1). On first boot it
// generates secrets and a randomized admin path, prints them once, then serves
// the Config Studio + API.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forgepanel/forgepanel/internal/api"
	"github.com/forgepanel/forgepanel/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: config:", err)
		os.Exit(1)
	}

	srv, err := api.NewWithStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: store:", err)
		os.Exit(1)
	}
	addr := fmt.Sprintf(":%d", cfg.PanelPort)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	banner(cfg, srv.FirstAdminPassword)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "forgepanel: listen:", err)
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
}

func banner(cfg *config.Config, firstAdminPw string) {
	fmt.Println("┌─────────────────────────────────────────────┐")
	fmt.Println("│  ⚡ ForgePanel                               │")
	fmt.Println("└─────────────────────────────────────────────┘")
	fmt.Printf("  Panel:  http://127.0.0.1:%d%s\n", cfg.PanelPort, cfg.AdminPath)
	fmt.Printf("  Data:   %s\n", cfg.DataDir)
	if firstAdminPw != "" {
		fmt.Println("  ── FIRST BOOT — save these, shown once ──")
		fmt.Printf("  Admin user:      %s\n", cfg.AdminUser)
		fmt.Printf("  Admin password:  %s\n", firstAdminPw)
		fmt.Printf("  Admin path:      %s\n", cfg.AdminPath)
	}
	fmt.Println()
}
