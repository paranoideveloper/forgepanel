package sysinfo

// Container-aware readings.
//
// Inside a container, /proc and statfs describe the HOST: on Railway the panel
// reported 48 cores, 372 GB of memory and a 2.4 TB disk for a service whose
// actual allowance was 2 vCPUs and 1 GB, with no disk of its own. Those numbers
// were real, but they were somebody else's — every other tenant of that machine
// was in them — and an operator sizing a plan from them would be wrong by two
// orders of magnitude.
//
// The container's own limits live in its cgroup. Where one is set, it replaces
// the host figure; where none is (a VPS, or a container with no limit), nothing
// here changes what was reported before.

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Overridable in tests; the real paths otherwise.
var (
	cgroupRoot    = "/sys/fs/cgroup"
	mountinfoPath = "/proc/self/mountinfo"
	procRoot      = "/proc"
)

func readTrim(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func readUint(path string) (uint64, bool) {
	s, ok := readTrim(path)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// cgroupCPULimit is the number of CPUs the cgroup may use, or 0 when there is
// no limit. cgroup v2 writes "quota period" to cpu.max ("max period" when
// unlimited); v1 splits the same two numbers across two files with -1 for none.
func cgroupCPULimit() float64 {
	if s, ok := readTrim(filepath.Join(cgroupRoot, "cpu.max")); ok {
		f := strings.Fields(s)
		if len(f) == 2 && f[0] != "max" {
			q, err1 := strconv.ParseFloat(f[0], 64)
			p, err2 := strconv.ParseFloat(f[1], 64)
			if err1 == nil && err2 == nil && q > 0 && p > 0 {
				return q / p
			}
		}
		return 0
	}
	q, ok1 := readTrim(filepath.Join(cgroupRoot, "cpu", "cpu.cfs_quota_us"))
	p, ok2 := readTrim(filepath.Join(cgroupRoot, "cpu", "cpu.cfs_period_us"))
	if ok1 && ok2 {
		qv, err1 := strconv.ParseFloat(q, 64)
		pv, err2 := strconv.ParseFloat(p, 64)
		if err1 == nil && err2 == nil && qv > 0 && pv > 0 {
			return qv / pv
		}
	}
	return 0
}

// cgroupCPUUsage is the cgroup's cumulative CPU time in microseconds.
func cgroupCPUUsage() (uint64, bool) {
	if f, err := os.Open(filepath.Join(cgroupRoot, "cpu.stat")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "usage_usec "); ok {
				n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				return n, err == nil
			}
		}
		return 0, false
	}
	// v1 reports nanoseconds.
	if ns, ok := readUint(filepath.Join(cgroupRoot, "cpuacct", "cpuacct.usage")); ok {
		return ns / 1000, true
	}
	return 0, false
}

// cpuSample is the previous cgroup CPU reading. Utilisation needs two readings
// and the time between them; the dashboard polls, so the interval between two
// polls is the measurement window.
var cpuSample struct {
	mu   sync.Mutex
	usec uint64
	at   time.Time
}

// cgroupCPUPercent is the share of the cgroup's CPU allowance used since the
// previous call. With no recent previous reading it takes a short second one,
// so the first dashboard load shows a measurement rather than zero.
func cgroupCPUPercent(limit float64) (float64, bool) {
	if limit <= 0 {
		return 0, false
	}
	u1, ok := cgroupCPUUsage()
	if !ok {
		return 0, false
	}
	now := time.Now()
	cpuSample.mu.Lock()
	prevU, prevAt := cpuSample.usec, cpuSample.at
	cpuSample.usec, cpuSample.at = u1, now
	cpuSample.mu.Unlock()

	if prevAt.IsZero() || now.Sub(prevAt) > 5*time.Minute || u1 < prevU {
		time.Sleep(250 * time.Millisecond)
		u2, ok := cgroupCPUUsage()
		if !ok {
			return 0, false
		}
		now2 := time.Now()
		cpuSample.mu.Lock()
		cpuSample.usec, cpuSample.at = u2, now2
		cpuSample.mu.Unlock()
		prevU, prevAt, u1, now = u1, now, u2, now2
		if u1 < prevU {
			return 0, false
		}
	}
	elapsed := now.Sub(prevAt).Microseconds()
	if elapsed <= 0 {
		return 0, false
	}
	p := float64(u1-prevU) / (float64(elapsed) * limit) * 100
	if p > 100 {
		p = 100
	}
	return p, true
}

// cgroupMemory reports the cgroup's memory limit and what it really uses.
//
// Used excludes inactive page cache, as `docker stats` does: the kernel
// reclaims it before the limit is hit, so counting it shows a container near
// its ceiling that is not.
func cgroupMemory() (limit, used uint64, ok bool) {
	if s, has := readTrim(filepath.Join(cgroupRoot, "memory.max")); has {
		if s == "max" {
			return 0, 0, false
		}
		lim, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		cur, has := readUint(filepath.Join(cgroupRoot, "memory.current"))
		if !has {
			return 0, 0, false
		}
		inactive := memStat(filepath.Join(cgroupRoot, "memory.stat"), "inactive_file")
		if inactive < cur {
			cur -= inactive
		}
		return lim, cur, true
	}
	lim, has1 := readUint(filepath.Join(cgroupRoot, "memory", "memory.limit_in_bytes"))
	cur, has2 := readUint(filepath.Join(cgroupRoot, "memory", "memory.usage_in_bytes"))
	if !has1 || !has2 {
		return 0, 0, false
	}
	inactive := memStat(filepath.Join(cgroupRoot, "memory", "memory.stat"), "total_inactive_file")
	if inactive < cur {
		cur -= inactive
	}
	return lim, cur, true
}

func memStat(path, key string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+" "); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

// mountFSType is the filesystem type of the mount holding path, by the longest
// mount point that prefixes it.
func mountFSType(path string) string {
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	best, bestType := -1, ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024) // overlay lines list every layer
	for sc.Scan() {
		// "... mountpoint opts [optional...] - fstype source superopts"
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 1 {
			continue
		}
		mp := pf[4]
		if abs == mp || mp == "/" || strings.HasPrefix(abs, strings.TrimSuffix(mp, "/")+"/") {
			if len(mp) > best {
				best, bestType = len(mp), qf[0]
			}
		}
	}
	return bestType
}

// dirSize walks a directory, cached: the dashboard polls every few seconds and
// a data directory holding cores and a database is not free to walk.
var dirCache struct {
	mu   sync.Mutex
	path string
	size uint64
	at   time.Time
}

func dirSize(path string) uint64 {
	dirCache.mu.Lock()
	defer dirCache.mu.Unlock()
	if dirCache.path == path && time.Since(dirCache.at) < time.Minute {
		return dirCache.size
	}
	var total uint64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += uint64(info.Size())
			}
		}
		return nil
	})
	dirCache.path, dirCache.size, dirCache.at = path, total, time.Now()
	return total
}

// containerUptime is how long PID 1 — the container — has been running.
// /proc/uptime is the host's, which on a platform reads as months for a
// service deployed this morning.
func containerUptime(hostUptime float64) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, "1", "stat"))
	if err != nil {
		return 0, false
	}
	// The command name is in parentheses and may contain spaces; fields are
	// counted from after the closing one. starttime is field 22, i.e. index 19
	// of what follows ") ".
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseFloat(f[19], 64)
	if err != nil {
		return 0, false
	}
	const clkTck = 100 // USER_HZ, fixed at 100 on every Linux the panel ships for
	up := hostUptime - ticks/clkTck
	if up < 0 {
		return 0, false
	}
	return int64(up), true
}
