package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDataDirLockRefusesASecondHolder is the guarantee the systemd↔Docker
// migration depends on: two panels on one SQLite file corrupt traffic
// accounting in ways that are very hard to attribute afterwards, so the second
// one must refuse to start rather than quietly join in.
func TestDataDirLockRefusesASecondHolder(t *testing.T) {
	dir := t.TempDir()

	release, err := LockDataDir(dir)
	if err != nil {
		t.Fatalf("first lock failed: %v", err)
	}

	// A second acquisition from this process must fail. (flock is per open file
	// description, so a fresh OpenFile here behaves like a separate process.)
	if _, err := LockDataDir(dir); err == nil {
		t.Fatal("a second instance was allowed onto the same data directory")
	} else if !strings.Contains(err.Error(), "already using") {
		t.Fatalf("unhelpful error for a held lock: %v", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Once released, the directory is usable again — a stale lock file must
	// never block a restart.
	release2, err := LockDataDir(dir)
	if err != nil {
		t.Fatalf("lock not reusable after release: %v", err)
	}
	_ = release2()
}

// TestDataDirLockCreatesTheDirectory: a first run points at a path that does
// not exist yet.
func TestDataDirLockCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	release, err := LockDataDir(dir)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer release()
}

// TestDataDirLockNamesTheHolder so the operator knows which process to stop.
func TestDataDirLockNamesTheHolder(t *testing.T) {
	dir := t.TempDir()
	release, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	_, err = LockDataDir(dir)
	if err == nil {
		t.Fatal("expected a conflict")
	}
	if !strings.Contains(err.Error(), "pid") {
		t.Fatalf("error does not identify the holder: %v", err)
	}
	if !strings.Contains(err.Error(), "docker stop") {
		t.Fatalf("error does not tell the operator what to do: %v", err)
	}
}
