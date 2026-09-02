package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readPanelJSON(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "panel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// PORT is set by plenty of ordinary hosts for unrelated reasons. Treating it as
// the signal would take TLS off a normal install and serve the admin panel in
// cleartext — a silent downgrade nobody asked for.
func TestPORTAloneDoesNotPutThePanelBehindAnEdge(t *testing.T) {
	t.Setenv("PORT", "8080")
	if p := DetectPaaS(); p.Enabled {
		t.Fatalf("PORT alone enabled PaaS mode: %+v", p)
	}
}

// The platform's own variable is the signal.
func TestARailwayContainerIsDetected(t *testing.T) {
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("PORT", "8080")
	p := DetectPaaS()
	if !p.Enabled || p.Platform != "railway" {
		t.Fatalf("not detected: %+v", p)
	}
	if p.Domain != "app.up.railway.app" || p.Port != 8080 || p.PublicPort != 443 {
		t.Fatalf("wrong shape: %+v", p)
	}
}

// An explicit off must win, so an operator running ForgePanel on a platform in
// a way this code did not anticipate can always get the normal behaviour back.
func TestPaaSModeCanBeForcedOff(t *testing.T) {
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("FORGEPANEL_PAAS", "0")
	if p := DetectPaaS(); p.Enabled {
		t.Fatal("FORGEPANEL_PAAS=0 did not turn the mode off")
	}
}

// A custom domain attached at the platform's edge is what the links must say.
func TestAnOperatorsDomainWinsOverThePlatformHostname(t *testing.T) {
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("FORGEPANEL_DOMAIN", "vpn.example.com")
	if got := DetectPaaS().Domain; got != "vpn.example.com" {
		t.Fatalf("domain %q, want the operator's", got)
	}
}

// The platform's port is this deploy's accident, not a setting. Persisting it
// would leave a wrong port behind in the operator's saved configuration — and
// on a move off the platform, a panel that binds a port nothing routes to.
func TestThePlatformsPortIsNotWrittenIntoPanelJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("PORT", "8080")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Panel().Port != 8080 {
		t.Fatalf("running panel bound %d, want the platform's 8080", cfg.Panel().Port)
	}
	if got := readPanelJSON(t, dir)["port"]; got != float64(2053) {
		t.Fatalf("panel.json persisted port %v; the platform's port must not be saved", got)
	}
	if got := readPanelJSON(t, dir)["https_enabled"]; got == true {
		t.Fatal("panel.json persisted https_enabled from the platform override")
	}
}

// TLS is the edge's. Serving it here answers the platform's plaintext proxy
// request with a handshake, which the platform reports as an unhealthy app
// rather than as a protocol mismatch.
func TestBehindAnEdgeThePanelDoesNotServeItsOwnTLS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("FORGEPANEL_DOMAIN", "vpn.example.com")
	t.Setenv("FORGEPANEL_HTTPS", "1")
	t.Setenv("PORT", "8080")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Panel()
	if p.HTTPSEnabled {
		t.Error("the panel would serve TLS behind an edge that already terminated it")
	}
	if p.ACME.Enabled {
		t.Error("ACME is enabled for a hostname that resolves to the platform, not to us")
	}
	if p.Domain != "vpn.example.com" {
		t.Errorf("panel domain %q", p.Domain)
	}
}

// A settings save in the UI reloads panel.json. If the platform's port were not
// re-imposed on that reload, the next restart would bind the saved port, the
// platform would route to nothing, and the operator who saved it would have no
// way back in to undo it.
func TestASavedPortCannotTakeThePanelOffTheAirOnAPlatform(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("PORT", "8080")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the operator saving a port from the settings page.
	p := cfg.Panel()
	p.Port = 2053
	if err := savePanel(filepath.Join(dir, "panel.json"), p); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ReloadPanel(); err != nil {
		t.Fatal(err)
	}
	if cfg.Panel().Port != 8080 {
		t.Fatalf("after a settings save the panel would bind %d, which the platform does not route to", cfg.Panel().Port)
	}
}

// The local administration tools read the installation as configured, not as
// coloured by whatever environment they happen to be run from.
func TestTheAdminToolsViewIsNotColouredByThePlatformEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("PORT", "8080")
	cfg, err := LoadFromDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PaaS().Enabled || cfg.Panel().Port != 2053 {
		t.Fatalf("LoadFromDataDir picked up the ambient platform environment: paas=%v port=%d",
			cfg.PaaS().Enabled, cfg.Panel().Port)
	}
}
