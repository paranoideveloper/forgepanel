package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestForgectl_HealthURLs(t *testing.T) {
	urls := healthURLs("https://example.com:2053")
	if len(urls) != 1 || urls[0] != "https://example.com:2053/healthz" {
		t.Fatalf("unexpected healthURLs: %v", urls)
	}

	urls = healthURLs("8080")
	if len(urls) != 2 || urls[0] != "https://127.0.0.1:8080/healthz" {
		t.Fatalf("unexpected healthURLs for port: %v", urls)
	}
}

func TestForgectl_HealthPort(t *testing.T) {
	// Explicit arg
	if port := healthPort("9090"); port != 9090 {
		t.Fatalf("expected 9090, got %d", port)
	}

	// Legacy bootstrap env var
	t.Setenv("FORGEPANEL_PANEL_PORT", "3000")
	if port := healthPort(""); port != 3000 {
		t.Fatalf("expected 3000, got %d", port)
	}

	// Persisted panel settings override an old environment value.
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	os.WriteFile(filepath.Join(dir, "panel.json"), []byte(`{"port": 4000}`), 0644)
	if port := healthPort(""); port != 4000 {
		t.Fatalf("expected 4000, got %d", port)
	}
}

func TestForgectl_CmdHealthServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	if err := cmdHealth([]string{ts.URL}); err != nil {
		t.Fatalf("cmdHealth failed for mock server: %v", err)
	}

	if err := cmdHealth([]string{"http://127.0.0.1:1"}); err == nil {
		t.Fatalf("cmdHealth expected error for invalid port")
	}
}
