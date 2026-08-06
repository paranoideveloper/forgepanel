package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
)

func TestForgepanelVersionFlag(t *testing.T) {
	// Verify data directory locking and release
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("FORGEPANEL_PANEL_PORT", "0") // Dynamic port

	cfg, srv, ln, err := start()
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if cfg == nil || srv == nil || ln == nil {
		t.Fatal("expected non-nil config, server, and listener")
	}

	banner(cfg, srv)

	ln.Close()
	srv.Close()
	releaseDataLock()
}

func TestBannerOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatalf("config.LoadFromDataDir: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	banner(cfg, nil)
}
