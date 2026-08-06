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
