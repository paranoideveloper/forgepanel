package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seedDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"forgepanel.db", "secrets.json", "panel.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A backup was a bag of files that said nothing about itself, so a restore
// could not answer the question that decides whether it is safe: is this
// database from a schema this binary understands?
func TestABackupCarriesItsSchemaVersion(t *testing.T) {
	dir := seedDataDir(t)
	blob, err := CreateWithManifest("master", dir, PanelFiles(dir), Manifest{
		CreatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
		PanelVersion: "v1.9.0", SchemaVersion: 18,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest("master", blob)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("the backup carries no manifest")
	}
	if m.SchemaVersion != 18 || m.PanelVersion != "v1.9.0" || m.Format != ManifestFormat {
		t.Fatalf("manifest = %+v", m)
	}
	// Files is filled in by the writer, not by the caller, so it cannot claim a
	// count the blob does not have.
	if m.Files != 3 {
		t.Errorf("files = %d, want the 3 that were written", m.Files)
	}
}

// The dangerous direction. An older binary against a newer database does not
// know the columns that were added, its migration runner sees versions it has
// no entry for, and the first write leaves the database in a state neither
// version can read — discovered only after the live one has been overwritten.
func TestRestoringANewerBackupIsRefused(t *testing.T) {
	err := CheckRestorable(&Manifest{SchemaVersion: 25}, 18)
	if err == nil {
		t.Fatal("a backup from a newer schema was accepted")
	}
	var newer *ErrNewerSchema
	if !errors.As(err, &newer) {
		t.Fatalf("err = %v, want ErrNewerSchema so a caller can distinguish it", err)
	}
	// The message has to name both numbers and say what to do; "incompatible
	// backup" sends the operator nowhere.
	for _, want := range []string{"25", "18", "Upgrade the panel first"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not mention %q", err.Error(), want)
		}
	}
}

func TestRestoringAnOlderOrEqualBackupIsAllowed(t *testing.T) {
	// Older is the ordinary upgrade path: the migration runner brings it
	// forward on the next start.
	if err := CheckRestorable(&Manifest{SchemaVersion: 12}, 18); err != nil {
		t.Errorf("an older backup was refused: %v", err)
	}
	if err := CheckRestorable(&Manifest{SchemaVersion: 18}, 18); err != nil {
		t.Errorf("a same-schema backup was refused: %v", err)
	}
}

// Every backup written before manifests existed is from an older panel by
// definition. Refusing them would destroy the only copy some operator has.
func TestAPreManifestBackupIsStillRestorable(t *testing.T) {
	dir := seedDataDir(t)
	blob, err := CreateFrom("master", dir, PanelFiles(dir))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest("master", blob)
	if err != nil {
		t.Fatalf("reading a manifest-less backup errored: %v", err)
	}
	if m != nil {
		t.Fatalf("manifest = %+v, want none", m)
	}
	if err := CheckRestorable(nil, 18); err != nil {
		t.Errorf("a pre-manifest backup was refused: %v", err)
	}
}

// The manifest describes the backup; restoring it into the data directory would
// leave a stray file there that nothing reads.
func TestTheManifestIsNotRestoredAsAFile(t *testing.T) {
	dir := seedDataDir(t)
	blob, err := CreateWithManifest("master", dir, PanelFiles(dir), Manifest{SchemaVersion: 3})
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	files, err := RestoreChecked("master", blob, dest, 18)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Base(f) == ManifestName {
			t.Errorf("the manifest was restored into the data directory as %s", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ManifestName)); !os.IsNotExist(err) {
		t.Error("the manifest is on disk in the restored data directory")
	}
	if len(files) != 3 {
		t.Errorf("restored %d files, want 3", len(files))
	}
}

func TestRestoreCheckedRefusesBeforeWritingAnything(t *testing.T) {
	dir := seedDataDir(t)
	blob, err := CreateWithManifest("master", dir, PanelFiles(dir), Manifest{SchemaVersion: 99})
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := RestoreChecked("master", blob, dest, 18); err == nil {
		t.Fatal("a newer backup was restored")
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	// The whole point of checking is that the live data directory is untouched.
	if len(entries) != 0 {
		t.Errorf("the destination was written to before the refusal: %v", entries)
	}
}

// An empty backup must not become a one-member archive holding only its own
// manifest, which would decrypt, list "0 files" and look like it worked.
func TestAnEmptyBackupIsStillAnError(t *testing.T) {
	if _, err := CreateWithManifest("master", t.TempDir(), nil, Manifest{SchemaVersion: 1}); err == nil {
		t.Fatal("a backup with no files succeeded")
	}
}

// nodeca holds the CA that signs every node's client certificate. Losing it
// does not lose something re-issuable — it invalidates the identity of the whole
// fleet at once, and every node has to be re-enrolled by hand.
func TestTheNodeCAIsInsideTheBackup(t *testing.T) {
	dir := seedDataDir(t)
	caDir := filepath.Join(dir, "nodeca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range PanelFiles(dir) {
		if strings.HasSuffix(filepath.ToSlash(f), "nodeca/ca.key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the node CA is outside the backup: %v", PanelFiles(dir))
	}

	// And it must land back in the same place, not flattened next to the
	// database where nodeca.Open would never look for it.
	blob, err := CreateWithManifest("master", dir, PanelFiles(dir), Manifest{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := RestoreChecked("master", blob, dest, 18); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "nodeca", "ca.key")); err != nil {
		t.Errorf("the node CA did not restore to nodeca/ca.key: %v", err)
	}
}
