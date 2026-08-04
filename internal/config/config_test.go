package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// freshLoad points FORGEPANEL_DATA at a temp dir and loads config there.
func freshLoad(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoadFreshMintsPanel(t *testing.T) {
	cfg := freshLoad(t)
	if !cfg.FirstBoot() {
		t.Fatal("fresh data dir should be FirstBoot")
	}
	p := cfg.Panel()
	if p.AdminPath == "" || p.Port != 2053 || p.BindAddress != "0.0.0.0" {
		t.Fatalf("panel defaults wrong: %+v", p)
	}
	if p.SetupCompleted {
		t.Fatal("fresh install must not be setup-completed")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "panel.json")); err != nil {
		t.Fatalf("panel.json not written: %v", err)
	}
}

func TestMigrateFromLegacySecrets(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	// Simulate an existing install: secrets.json with an admin path, no panel.json.
	legacy := map[string]string{"admin_path": "/panel/legacy123", "master_key": "abc", "admin_user": "admin"}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "secrets.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FirstBoot() {
		t.Fatal("an upgrade (legacy admin path present) must not report FirstBoot")
	}
	if cfg.Panel().AdminPath != "/panel/legacy123" {
		t.Fatalf("admin path not migrated: %q", cfg.Panel().AdminPath)
	}
	if cfg.AdminPath != "/panel/legacy123" {
		t.Fatalf("cfg.AdminPath not synced: %q", cfg.AdminPath)
	}
}

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	t.Setenv("FORGEPANEL_PANEL_PORT", "3100")
	t.Setenv("FORGEPANEL_DOMAIN", "panel.example.com")
	t.Setenv("FORGEPANEL_HTTPS", "1")
	t.Setenv("FORGEPANEL_ACME_EMAIL", "ops@example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Panel()
	if p.Port != 3100 || p.Domain != "panel.example.com" || !p.HTTPSEnabled || p.ACME.Email != "ops@example.com" {
		t.Fatalf("env overrides not applied: %+v", p)
	}
}

func TestUnknownKeysPreserved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	// A newer binary wrote a key this version doesn't know about.
	seed := `{"port":2053,"admin_path":"/panel/x","future_flag":{"a":1},"acme":{}}`
	if err := os.WriteFile(filepath.Join(dir, "panel.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Force a rewrite and confirm the unknown key survived.
	cfg.Panel().Port = 2054
	if err := cfg.SavePanel(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "panel.json"))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["future_flag"]; !ok {
		t.Fatalf("unknown key dropped on rewrite: %s", raw)
	}
	if string(m["port"]) != "2054" {
		t.Fatalf("port not updated: %s", m["port"])
	}
}

func TestRollbackRestoreAndClear(t *testing.T) {
	dir := t.TempDir()
	good := `{"port":2222}`
	bad := `{"port":9999}`
	if err := os.WriteFile(filepath.Join(dir, "panel.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "panel.json.bak"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if !RestoreRollback(dir) {
		t.Fatal("RestoreRollback should report true when a .bak exists")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "panel.json"))
	if string(raw) != good {
		t.Fatalf("panel.json not restored from bak: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "panel.json.bak")); err == nil {
		t.Fatal("bak should be consumed by the rename")
	}
	// Nothing to restore now.
	if RestoreRollback(dir) {
		t.Fatal("RestoreRollback should be false with no .bak")
	}
	// ClearRollback is a no-op-safe delete.
	_ = os.WriteFile(filepath.Join(dir, "panel.json.bak"), []byte(good), 0o600)
	ClearRollback(dir)
	if _, err := os.Stat(filepath.Join(dir, "panel.json.bak")); err == nil {
		t.Fatal("ClearRollback did not remove the bak")
	}
}
