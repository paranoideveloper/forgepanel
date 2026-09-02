package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/forgepanel/forgepanel/internal/api"
	"github.com/forgepanel/forgepanel/internal/config"
)

func TestForgepanelVersionFlag(t *testing.T) {
	// Verify data directory locking and release
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate test panel port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release test panel port: %v", err)
	}
	t.Setenv("FORGEPANEL_PANEL_PORT", strconv.Itoa(port))

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

	srv := api.New(cfg)
	banner(cfg, srv)
}
