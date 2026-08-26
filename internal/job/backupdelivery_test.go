package job

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/backup"
)

func seedForBackup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"forgepanel.db", "secrets.json", "panel.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A backup that only exists on the machine it backs up is not a backup of that
// machine. The scheduler wrote one and had nowhere to send it, so the panel's
// only off-box copy was whatever the operator remembered to download by hand.
func TestAScheduledBackupIsHandedToTheDeliveryHook(t *testing.T) {
	dir := seedForBackup(t)
	var delivered []string
	s := New(Config{
		BackupConfig: func() (string, string, time.Duration, int) {
			return dir, "master-key", time.Hour, 7
		},
		DeliverBackup: func(path string) { delivered = append(delivered, path) },
	})

	s.runScheduledBackup()

	if len(delivered) != 1 {
		t.Fatalf("the delivery hook was called %d time(s)", len(delivered))
	}
	// The path must be the file that was just written, not a directory or a
	// name: the hook reads it and uploads the bytes.
	if !strings.HasSuffix(delivered[0], ".fpbk") {
		t.Errorf("delivered %q, want the backup file", delivered[0])
	}
	blob, err := os.ReadFile(delivered[0])
	if err != nil {
		t.Fatalf("the delivered path is not readable: %v", err)
	}
	// And it must be a real backup, not an empty file the hook would ship
	// happily. Opening it is the only way to know.
	if _, err := backup.Inspect("master-key", blob); err != nil {
		t.Errorf("the delivered file is not a valid backup: %v", err)
	}
}

// A panel with no delivery configured must behave exactly as it did before: the
// backup is written and stays local.
func TestAScheduledBackupWithNoHookStillWritesLocally(t *testing.T) {
	dir := seedForBackup(t)
	s := New(Config{
		BackupConfig: func() (string, string, time.Duration, int) {
			return dir, "master-key", time.Hour, 7
		},
	})
	s.runScheduledBackup()

	last, count, err := backup.LatestLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || last.IsZero() {
		t.Fatalf("local backups = %d", count)
	}
}

// The hook must not run when no backup was taken. A backup that was skipped
// because a recent one exists has no new file to deliver, and delivering
// yesterday's again every hour would fill the operator's chat.
func TestNothingIsDeliveredWhenTheBackupIsSkipped(t *testing.T) {
	dir := seedForBackup(t)
	calls := 0
	s := New(Config{
		BackupConfig: func() (string, string, time.Duration, int) {
			return dir, "master-key", 24 * time.Hour, 7
		},
		DeliverBackup: func(string) { calls++ },
	})
	s.runScheduledBackup() // takes one
	s.runScheduledBackup() // too soon: skipped
	if calls != 1 {
		t.Errorf("the hook ran %d time(s) for one backup", calls)
	}
}
