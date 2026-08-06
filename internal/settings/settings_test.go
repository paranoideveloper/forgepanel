package settings

import (
	"net"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
)

func TestNormalizeAndValidateDomain(t *testing.T) {
	if got := NormalizeDomain("HTTPS://Panel.Example.com:8443/path"); got != "panel.example.com" {
		t.Fatalf("normalized domain = %q", got)
	}
	if !ValidDomain("panel.example.com") || ValidDomain("localhost") || ValidDomain("bad_name.example.com") {
		t.Fatal("domain validation mismatch")
	}
}

func TestApplyPersistsAndIgnoresFutureEnvironmentOverrides(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	port := 24053
	domain := "panel.example.com"
	https := true
	svc := New(cfg)
	svc.PortOK = func(string, int) bool { return true }
	svc.Lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	svc.IPv4 = func() string { return "203.0.113.10" }
	if _, err := svc.Apply(Change{Port: &port, Domain: &domain, HTTPSEnabled: &https, VerifyDNS: true}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("FORGEPANEL_PANEL_PORT", "25053")
	check, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if check.Panel().Port != port || check.Panel().Domain != domain || !check.Panel().HTTPSEnabled {
		t.Fatalf("settings did not persist: %+v", check.Panel())
	}
}
