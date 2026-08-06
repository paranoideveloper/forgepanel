package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// LockDataDir takes an exclusive advisory lock on the data directory so two
// panel instances can never run against one database.
//
// This matters most for the systemd↔Docker migration path: the obvious mistake
// is to start the container while the host service is still running, both
// pointed at /var/lib/forgepanel. SQLite would let them both open the file and
// the two would then fight over engine processes, listening ports and the
// traffic counters — corrupting accounting in a way that is very hard to
// attribute afterwards. Failing loudly at startup is far kinder.
//
// The lock is flock-based, so it is released automatically if the process dies
// without cleaning up; a stale lock file never blocks a restart. The returned
// closer releases it.
func LockDataDir(dir string) (func() error, error) {
	return lockFile(filepath.Join(dir, "forgepanel.lock"), "another ForgePanel instance is already using")
}

// LockSettings serializes short configuration writes without taking the
// long-lived runtime lock. The panel holds forgepanel.lock for its entire
// lifetime, while the web API and forgectl only need mutual exclusion around a
// read-validate-write transition of panel.json.
func LockSettings(dir string) (func() error, error) {
	return lockFile(filepath.Join(dir, "settings.lock"), "another ForgePanel settings change is in progress for")
}

func lockFile(path, prefix string) (func() error, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("config: open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := ""
		if b, rerr := os.ReadFile(path); rerr == nil && len(b) > 0 {
			holder = " (held by pid " + string(b) + ")"
		}
		f.Close()
		hint := " — retry after the current operation completes"
		if prefix == "another ForgePanel instance is already using" {
			hint = " — two instances must not share a data directory. Stop the other one (systemctl stop forgepanel, or docker stop forgepanel) and retry"
		}
		return nil, fmt.Errorf(
			"%s %s%s%s",
			prefix,
			dir, holder, hint)
	}
	// Record our pid so the next process can name the holder in its error.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	return func() error {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}
