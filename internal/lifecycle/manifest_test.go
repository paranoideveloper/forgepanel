package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestSaveLoadAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "install-manifest.json")
	m := NewManifest("curl", "v1.2.3", filepath.Join(dir, "data"))
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, err = %v", info.Mode(), err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Version != "v1.2.3" || loaded.InstallMethod != "curl" {
		t.Fatalf("load = %+v, err = %v", loaded, err)
	}
}

func TestCleanupRestoresBackupAndPreservesChangedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "forgepanel.service")
	backup := filepath.Join(dir, "original.service")
	if err := os.WriteFile(backup, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("installed"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManifest("curl", "v1", filepath.Join(dir, "data"))
	if err := m.AddResource("unit", target, false, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CleanupFiles(false, false, false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatalf("restored content = %q", got)
	}
	if err := os.WriteFile(target, []byte("operator change"), 0o644); err != nil {
		t.Fatal(err)
	}
	summary, err := m.CleanupFiles(false, false, false)
	if err != nil || !summary.Incomplete || summary.Actions[0].Action != "kept" {
		t.Fatalf("summary = %+v, err = %v", summary, err)
	}
}

func TestCleanupKeepsDataUnlessPurge(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "user-note"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManifest("curl", "v1", data)
	if err := m.AddResource("data_dir", data, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CleanupFiles(false, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(data); err != nil {
		t.Fatal("default cleanup removed data")
	}
	if _, err := m.CleanupFiles(true, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Fatal("purge did not remove manifest-owned data")
	}
}

func TestUpgradeRetainsOriginalOwnershipProof(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "forgectl")
	if err := os.WriteFile(target, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := NewManifest("curl", "v1", filepath.Join(dir, "data"))
	if err := m.AddResource("cli", target, true, ""); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "v1-backup")
	if err := os.WriteFile(backup, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.AddOrUpdateResource("cli", target, false, backup); err != nil {
		t.Fatal(err)
	}
	if !m.Resources[0].Created || m.Resources[0].Backup != "" {
		t.Fatalf("upgrade rewrote ownership proof: %+v", m.Resources[0])
	}
	if _, err := m.CleanupFiles(false, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("created resource was not removed: %v", err)
	}
}

func TestLegacyInventoryAndManagedRule(t *testing.T) {
	dir := t.TempDir()
	m := LegacyInventory(dir)
	if m == nil || m.InstallMethod != "legacy" {
		t.Fatalf("LegacyInventory unexpected: %+v", m)
	}

	if !IsManagedRule("forgepanel-porthop-rule1") {
		t.Fatal("IsManagedRule expected true")
	}
	if IsManagedRule("other-rule") {
		t.Fatal("IsManagedRule expected false")
	}
}

func TestManifestEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// Load non-existent file
	if _, err := Load(filepath.Join(dir, "nonexistent.json")); err == nil {
		t.Fatal("expected error loading nonexistent manifest")
	}

	// Load corrupt JSON
	corruptPath := filepath.Join(dir, "corrupt.json")
	_ = os.WriteFile(corruptPath, []byte("invalid json"), 0600)
	if _, err := Load(corruptPath); err == nil {
		t.Fatal("expected error loading corrupt manifest")
	}

	// Save to invalid path
	m := NewManifest("docker", "v1.0.0", filepath.Join(dir, "data"))
	fileAsDir := filepath.Join(dir, "regularfile")
	_ = os.WriteFile(fileAsDir, []byte("x"), 0600)
	if err := m.Save(filepath.Join(fileAsDir, "manifest.json")); err == nil {
		t.Fatal("expected error saving to non-existent directory")
	}
}

func TestAddOrUpdateResource(t *testing.T) {
	dir := t.TempDir()
	m := NewManifest("docker", "v1.0.0", filepath.Join(dir, "data"))

	filePath := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(filePath, []byte("v1"), 0644)

	// Add resource
	if err := m.AddOrUpdateResource("config", filePath, true, ""); err != nil {
		t.Fatalf("AddOrUpdateResource failed: %v", err)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(m.Resources))
	}

	// Update existing resource
	_ = os.WriteFile(filePath, []byte("v2"), 0644)
	if err := m.AddOrUpdateResource("config", filePath, true, ""); err != nil {
		t.Fatalf("AddOrUpdateResource update failed: %v", err)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("expected 1 resource after update, got %d", len(m.Resources))
	}
}

func TestCleanupFilesDryRunAndForce(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	_ = os.Mkdir(dataDir, 0700)

	m := NewManifest("curl", "v1", dataDir)

	file1 := filepath.Join(dir, "file1.txt")
	_ = os.WriteFile(file1, []byte("content1"), 0644)
	_ = m.AddResource("file", file1, true, "")

	// Dry run cleanup
	summary, err := m.CleanupFiles(false, true, false)
	if err != nil {
		t.Fatalf("CleanupFiles dryRun failed: %v", err)
	}
	if len(summary.Actions) == 0 || summary.Actions[0].Action != "would_remove" {
		t.Fatalf("expected would_remove in dryRun summary, got %+v", summary)
	}
	if _, err := os.Stat(file1); err != nil {
		t.Fatal("dryRun should not actually delete file")
	}

	// Modify file and test force cleanup
	_ = os.WriteFile(file1, []byte("modified"), 0644)
	summaryForce, err := m.CleanupFiles(false, false, true)
	if err != nil {
		t.Fatalf("CleanupFiles force failed: %v", err)
	}
	if len(summaryForce.Actions) == 0 || summaryForce.Actions[0].Action != "removed" {
		t.Fatalf("expected removed with force=true, got %+v", summaryForce)
	}
}
