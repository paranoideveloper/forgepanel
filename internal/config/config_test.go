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

func TestConfigRollbackAndClone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	prev := ClonePanel(cfg.Panel())
	if prev.Port != cfg.Panel().Port {
		t.Fatalf("ClonePanel mismatch: %d != %d", prev.Port, cfg.Panel().Port)
	}

	cfg.Panel().Port = 9999
	if err := cfg.SavePanel(); err != nil {
		t.Fatalf("SavePanel: %v", err)
	}

	if err := cfg.WriteRollback(&prev); err != nil {
		t.Fatalf("WriteRollback: %v", err)
	}

	if !RestoreRollback(dir) {
		t.Fatal("RestoreRollback returned false, expected true")
	}

	cfgReloaded, err := Load()
	if err != nil {
		t.Fatalf("Load reloaded: %v", err)
	}
	if cfgReloaded.Panel().Port == 9999 {
		t.Fatal("RestoreRollback did not revert panel port")
	}

	ClearRollback(dir)
	if RestoreRollback(dir) {
		t.Fatal("RestoreRollback expected false after ClearRollback")
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("TEST_BOOL_1", "1")
	t.Setenv("TEST_BOOL_TRUE", "true")
	t.Setenv("TEST_BOOL_YES", "yes")
	t.Setenv("TEST_BOOL_FALSE", "0")

	if !envBool("TEST_BOOL_1") || !envBool("TEST_BOOL_TRUE") || !envBool("TEST_BOOL_YES") {
		t.Fatal("envBool expected true")
	}
	if envBool("TEST_BOOL_FALSE") || envBool("TEST_BOOL_NONEXISTENT") {
		t.Fatal("envBool expected false")
	}
}

func TestConfigLoadFromDataDirAndReload(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadFromDataDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDataDir failed: %v", err)
	}

	if cfg.DataDir != dir {
		t.Fatalf("expected DataDir %s, got %s", dir, cfg.DataDir)
	}

	// Mutate panel.json on disk and test ReloadPanel
	p := cfg.Panel()
	p.Port = 9090
	p.Domain = "reloaded.local"

	if err := cfg.SavePanel(); err != nil {
		t.Fatalf("SavePanel failed: %v", err)
	}

	if err := cfg.ReloadPanel(); err != nil {
		t.Fatalf("ReloadPanel failed: %v", err)
	}

	if cfg.Panel().Port != 9090 || cfg.Panel().Domain != "reloaded.local" {
		t.Fatalf("ReloadPanel failed to reload saved panel data")
	}
}

func TestConfigCloneAndRollback(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadFromDataDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDataDir failed: %v", err)
	}

	p := cfg.Panel()
	nilCloned := ClonePanel(nil)
	if nilCloned.Port != 0 {
		t.Fatal("ClonePanel(nil) expected empty PanelSettings")
	}
	p.extra = map[string]json.RawMessage{"custom_key": []byte(`"value"`)}
	cloned := ClonePanel(p)
	if cloned.Port != p.Port || cloned.AdminPath != p.AdminPath {
		t.Fatalf("ClonePanel mismatch: %+v vs %+v", cloned, p)
	}

	// Test WriteRollback, RestoreRollback, ClearRollback
	oldPanel := cloned
	oldPanel.Port = 7777

	if err := cfg.WriteRollback(&oldPanel); err != nil {
		t.Fatalf("WriteRollback failed: %v", err)
	}

	if !RestoreRollback(dir) {
		t.Fatal("RestoreRollback returned false")
	}

	// Verify rollback restored panel settings
	if err := cfg.ReloadPanel(); err != nil {
		t.Fatalf("ReloadPanel after rollback failed: %v", err)
	}
	if cfg.Panel().Port != 7777 {
		t.Fatalf("expected rolled back port 7777, got %d", cfg.Panel().Port)
	}

	ClearRollback(dir)
	if RestoreRollback(dir) {
		t.Fatal("RestoreRollback should return false after ClearRollback")
	}
}

func TestConfigLockSettingsAndDataDir(t *testing.T) {
	dir := t.TempDir()
	release, err := LockSettings(dir)
	if err != nil {
		t.Fatalf("LockSettings failed: %v", err)
	}
	release()

	relData, err := LockDataDir(dir)
	if err != nil {
		t.Fatalf("LockDataDir failed: %v", err)
	}
	_ = relData()
}

func TestDefaultDataDirFallback(t *testing.T) {
	t.Setenv("FORGEPANEL_DATA", "")
	dd := defaultDataDir()
	if dd == "" {
		t.Fatal("defaultDataDir returned empty string")
	}
}

func TestConfigMissingEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// Corrupt panel.json
	_ = os.WriteFile(filepath.Join(dir, "panel.json"), []byte("invalid json"), 0600)
	if _, err := LoadFromDataDir(dir); err == nil {
		t.Fatal("expected error loading corrupt panel.json")
	}

	// Load valid then corrupt panel.json to test ReloadPanel error
	dir2 := t.TempDir()
	cfg, err := LoadFromDataDir(dir2)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir2, "panel.json"), []byte("corrupt"), 0600)
	if err := cfg.ReloadPanel(); err == nil {
		t.Fatal("expected ReloadPanel error with corrupt file")
	}

	// RestoreRollback missing file test
	if RestoreRollback(t.TempDir()) {
		t.Fatal("RestoreRollback should return false when no rollback exists")
	}

	// ClonePanel full copy test
	p := cfg.Panel()
	p.ACME.Email = "test@example.com"
	p.ACME.Enabled = true
	nilCloned := ClonePanel(nil)
	if nilCloned.Port != 0 {
		t.Fatal("ClonePanel(nil) expected empty PanelSettings")
	}
	p.extra = map[string]json.RawMessage{"custom_key": []byte(`"value"`)}
	cloned := ClonePanel(p)
	if cloned.ACME.Email != p.ACME.Email || !cloned.ACME.Enabled {
		t.Fatalf("ClonePanel ACME copy failed: %+v", cloned)
	}

	// WriteRollback & SavePanel error paths
	fileAsDir := filepath.Join(dir2, "regular_file")
	_ = os.WriteFile(fileAsDir, []byte("x"), 0600)
	cfg.DataDir = fileAsDir
	if err := cfg.SavePanel(); err == nil {
		t.Fatal("expected error saving panel to invalid path")
	}
	if err := cfg.WriteRollback(p); err == nil {
		t.Fatal("expected error writing rollback to invalid path")
	}
}
