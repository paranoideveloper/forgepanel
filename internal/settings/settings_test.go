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

func TestSettingsService_ValidationAndErrors(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	svc := New(cfg)
	svc.PortOK = func(string, int) bool { return false } // Port in use

	// Test nil config error
	nilSvc := &Service{}
	if _, err := nilSvc.Apply(Change{}); err == nil {
		t.Fatal("expected error for nil config Service")
	}

	// Test invalid domain error
	invalidDomain := "invalid_domain_name!"
	if _, err := svc.Apply(Change{Domain: &invalidDomain}); err == nil {
		t.Fatal("expected error for invalid domain")
	}

	// Test port in use error
	port := 80
	if _, err := svc.Apply(Change{Port: &port}); err == nil {
		t.Fatal("expected error when port is not free")
	}
}

func TestSettingsHelpers(t *testing.T) {
	// PortFree test
	_ = PortFree("127.0.0.1", 0)

	// ResolveDomain test (localhost or invalid)
	_, _, _ = ResolveDomain("127.0.0.1")

	// Outbound IP helpers
	_ = outboundIP4()
	_ = outboundIP6()
}

func TestValidEmailAndApplyDetails(t *testing.T) {
	if !ValidEmail("admin@example.com") || ValidEmail("invalid-email") {
		t.Fatal("ValidEmail failed")
	}

	dir := t.TempDir()
	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	svc := New(cfg)
	svc.PortOK = func(string, int) bool { return true }

	email := "operator@domain.com"
	bind := "127.0.0.1"
	https := false

	res, err := svc.Apply(Change{
		ACMEEmail:    &email,
		BindAddress:  &bind,
		HTTPSEnabled: &https,
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if res.New.ACME.Email != email || res.New.BindAddress != bind {
		t.Fatalf("Apply result mismatch: %+v", res.New)
	}
}

func TestSettingsAllEdgeCases(t *testing.T) {
	// NormalizeDomain empty
	if NormalizeDomain("") != "" {
		t.Fatal("NormalizeDomain(\"\") should be empty")
	}

	// ValidEmail edge cases
	if !ValidEmail("") {
		t.Fatal("empty email should be valid (cleared)")
	}
	if ValidEmail("invalid space@domain.com") || ValidEmail("user@") || ValidEmail("user@bad_domain") {
		t.Fatal("ValidEmail invalid cases failed")
	}

	// PortFree out of bounds
	if PortFree("127.0.0.1", 0) || PortFree("127.0.0.1", 70000) {
		t.Fatal("PortFree out of bounds should return false")
	}

	dir := t.TempDir()
	cfg, err := config.LoadFromDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	svc := New(cfg)
	svc.PortOK = func(string, int) bool { return true }

	// Invalid BindAddress
	badBind := "not-an-ip"
	if _, err := svc.Apply(Change{BindAddress: &badBind}); err == nil {
		t.Fatal("expected error for invalid BindAddress")
	}

	// Port out of range
	badPort := 99999
	if _, err := svc.Apply(Change{Port: &badPort}); err == nil {
		t.Fatal("expected error for invalid port range")
	}

	// HTTPS enabled without domain
	httpsTrue := true
	if _, err := svc.Apply(Change{HTTPSEnabled: &httpsTrue}); err == nil {
		t.Fatal("expected error enabling HTTPS without domain")
	}

	// Invalid ACME email
	badEmail := "bad email"
	if _, err := svc.Apply(Change{ACMEEmail: &badEmail}); err == nil {
		t.Fatal("expected error for invalid ACME email")
	}

	// Clear domain disables HTTPS
	dom := "panel.example.com"
	svc.Apply(Change{Domain: &dom})
	emptyDom := ""
	res, err := svc.Apply(Change{Domain: &emptyDom})
	if err != nil || res.New.HTTPSEnabled || res.New.ACME.Enabled {
		t.Fatalf("clearing domain should disable HTTPS: %+v", res.New)
	}

	// verifyDNS matching and non-matching tests
	svc.Lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.1")}, nil }
	svc.IPv4 = func() string { return "192.0.2.1" }
	if err := svc.verifyDNS("panel.example.com"); err != nil {
		t.Fatalf("verifyDNS matching IPv4 failed: %v", err)
	}

	svc.IPv4 = func() string { return "198.51.100.1" }
	if err := svc.verifyDNS("panel.example.com"); err == nil {
		t.Fatal("verifyDNS non-matching expected error")
	}
}
