package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func withCgroup(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, files)
	old := cgroupRoot
	cgroupRoot = dir
	t.Cleanup(func() { cgroupRoot = old })
}

// The values a Railway trial container actually had (cgroup v2): 2 vCPUs and
// ~1 GB, on a host the panel had been reporting as 48 cores and 372 GB.
func TestARailwayContainerReportsItsOwnLimits(t *testing.T) {
	withCgroup(t, map[string]string{
		"cpu.max":        "200000 100000\n",
		"cpu.stat":       "usage_usec 49490638\nuser_usec 23813466\n",
		"memory.max":     "999997440\n",
		"memory.current": "191774720\n",
		"memory.stat":    "anon 43229184\nfile 46129152\ninactive_file 30134272\n",
	})
	if got := cgroupCPULimit(); got != 2 {
		t.Fatalf("cpu limit = %v, want 2", got)
	}
	lim, used, ok := cgroupMemory()
	if !ok || lim != 999997440 || used != 191774720-30134272 {
		t.Fatalf("memory = %d used %d ok=%v", lim, used, ok)
	}
}

func TestNoLimitMeansNoOverride(t *testing.T) {
	withCgroup(t, map[string]string{
		"cpu.max":    "max 100000\n",
		"memory.max": "max\n",
	})
	if got := cgroupCPULimit(); got != 0 {
		t.Fatalf("unlimited cpu.max read as %v CPUs", got)
	}
	if _, _, ok := cgroupMemory(); ok {
		t.Fatal(`memory.max "max" read as a limit`)
	}
}

func TestCgroupV1Limits(t *testing.T) {
	withCgroup(t, map[string]string{
		"cpu/cpu.cfs_quota_us":         "150000\n",
		"cpu/cpu.cfs_period_us":        "100000\n",
		"memory/memory.limit_in_bytes": "536870912\n",
		"memory/memory.usage_in_bytes": "300000000\n",
		"memory/memory.stat":           "total_inactive_file 100000000\n",
		"cpuacct/cpuacct.usage":        "5000000000\n",
	})
	if got := cgroupCPULimit(); got != 1.5 {
		t.Fatalf("v1 cpu limit = %v, want 1.5", got)
	}
	if lim, used, ok := cgroupMemory(); !ok || lim != 536870912 || used != 200000000 {
		t.Fatalf("v1 memory = %d used %d ok=%v", lim, used, ok)
	}
	if u, ok := cgroupCPUUsage(); !ok || u != 5000000 {
		t.Fatalf("v1 cpu usage = %d µs ok=%v", u, ok)
	}
}

// A data directory on the container's overlay layer has no disk of its own:
// statfs there reports the host's whole disk.
func TestAnOverlayDataDirIsEphemeral(t *testing.T) {
	dir := t.TempDir()
	mi := filepath.Join(dir, "mountinfo")
	writeFiles(t, dir, map[string]string{
		"mountinfo": "1 0 0:1 / / rw,relatime - overlay overlay rw,lowerdir=/a:/b\n" +
			"2 1 0:2 / /var/lib/forgepanel rw - ext4 /dev/sdb rw\n",
		"data/a.db": "0123456789",
	})
	old := mountinfoPath
	mountinfoPath = mi
	t.Cleanup(func() { mountinfoPath = old })
	if got := mountFSType("/srv/whatever"); got != "overlay" {
		t.Fatalf("root fstype = %q", got)
	}
	if got := mountFSType("/var/lib/forgepanel"); got != "ext4" {
		t.Fatalf("a mounted volume read as %q", got)
	}
	if got := mountFSType("/var/lib/forgepanelX"); got != "overlay" {
		t.Fatalf("prefix-but-not-child matched the volume: %q", got)
	}
	if n := dirSize(filepath.Join(dir, "data")); n != 10 {
		t.Fatalf("dirSize = %d, want 10", n)
	}
}

func TestContainerUptimeIsPID1sAge(t *testing.T) {
	dir := t.TempDir()
	// starttime (field 22) = 18000000 ticks = 180000 s after host boot.
	writeFiles(t, dir, map[string]string{
		"1/stat": "1 (forge panel) S 0 1 1 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 18000000 0 0\n",
	})
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
	if up, ok := containerUptime(180000 + 3600); !ok || up != 3600 {
		t.Fatalf("uptime = %d ok=%v, want 3600", up, ok)
	}
}
