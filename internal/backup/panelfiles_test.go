package backup

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A backup must restore a WORKING panel, not merely its data — and it must not
// become an arbitrary file write when the blob came from somewhere untrusted.

func dataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(p string, body string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("forgepanel.db", "database")
	must("secrets.json", "master key lives here")
	must("panel.json", "address config")
	must("acme/live/panel.example.com.crt", "certificate")
	must("acme/live/panel.example.com.key", "private key")
	return dir
}

// Losing the ACME cache means re-issuing, and Let's Encrypt rate limits can
// leave a panel without a certificate for days — the failure a backup exists to
// prevent.
func TestBackupIncludesCertificatesAndSecrets(t *testing.T) {
	dir := dataDir(t)
	files := PanelFiles(dir)

	joined := strings.Join(files, "\n")
	for _, want := range []string{"forgepanel.db", "secrets.json", "panel.json",
		filepath.Join("acme", "live", "panel.example.com.crt")} {
		if !strings.Contains(joined, want) {
			t.Errorf("a backup would not contain %s:\n%s", want, joined)
		}
	}
}

// A certificate at acme/live/x.crt must restore to the same place, not be
// flattened into the data directory next to the database.
func TestPathsSurviveARoundTrip(t *testing.T) {
	dir := dataDir(t)
	blob, err := CreateFrom("master", dir, PanelFiles(dir))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	restored, err := Restore("master", blob, dest)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dest, "acme", "live", "panel.example.com.crt")
	found := false
	for _, r := range restored {
		if r == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("the certificate was not restored to its own path; got %v", restored)
	}
	body, err := os.ReadFile(want)
	if err != nil || string(body) != "certificate" {
		t.Fatalf("restored certificate is wrong: %q %v", body, err)
	}
}

// A backup blob is untrusted input. An entry named "../../etc/cron.d/x" would
// otherwise be an arbitrary file write, as root.
func TestRestoreRefusesPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{
		Name: "../../../../tmp/forgepanel-escape", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	blob, err := encrypt(deriveKey("master"), buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if _, err := Restore("master", blob, dest); err == nil {
		t.Fatal("a traversing entry was accepted; that is an arbitrary file write")
	}
	if _, err := os.Stat("/tmp/forgepanel-escape"); err == nil {
		_ = os.Remove("/tmp/forgepanel-escape")
		t.Fatal("the traversing entry actually wrote outside the destination")
	}
}

// A symlink entry would redirect a later write outside the tree.
func TestRestoreSkipsNonRegularEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777})
	body := []byte("ok")
	_ = tw.WriteHeader(&tar.Header{Name: "real.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	blob, _ := encrypt(deriveKey("master"), buf.Bytes())

	dest := t.TempDir()
	restored, err := Restore("master", blob, dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range restored {
		if strings.Contains(r, "evil-link") {
			t.Fatal("a symlink entry was restored")
		}
	}
	if len(restored) != 1 {
		t.Fatalf("expected only the regular file, got %v", restored)
	}
}

// Verifying a backup must not write anything: that is the whole point of being
// able to check one you are not restoring.
func TestInspectListsWithoutWriting(t *testing.T) {
	dir := dataDir(t)
	blob, err := CreateFrom("master", dir, PanelFiles(dir))
	if err != nil {
		t.Fatal(err)
	}
	names, err := Inspect("master", blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 4 {
		t.Fatalf("inspect found %d files, want the whole set: %v", len(names), names)
	}
	if _, err := Inspect("the-wrong-key", blob); err == nil {
		t.Fatal("a backup opened under the wrong master key")
	}
}

// A backup that only happens when someone remembers is not a policy.
func TestScheduledBackupsRotate(t *testing.T) {
	dir := dataDir(t)
	base := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if _, err := WriteLocal("master", dir, base.Add(time.Duration(i)*time.Hour), Manifest{}); err != nil {
			t.Fatal(err)
		}
	}
	_, count, err := LatestLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("wrote %d backups, want 5", count)
	}
	removed, err := PruneLocal(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("pruned %d, want 2", removed)
	}

	// keep<=0 must remove NOTHING: read as "keep zero" it would delete every
	// backup, the exact opposite of a retention setting.
	removed, _ = PruneLocal(dir, 0)
	if removed != 0 {
		t.Fatalf("keep=0 removed %d backups", removed)
	}
	_, count, _ = LatestLocal(dir)
	if count != 3 {
		t.Fatalf("%d backups remain, want 3", count)
	}
}

// A half-written backup must never be counted as a good one.
func TestPartialWritesAreNotCountedAsBackups(t *testing.T) {
	dir := dataDir(t)
	if _, err := WriteLocal("master", dir, time.Now(), Manifest{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(LocalDir(dir), "forgepanel-inprogress.fpbk.part"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, count, err := LatestLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("counted %d backups, want 1 — a .part file was treated as complete", count)
	}
}
