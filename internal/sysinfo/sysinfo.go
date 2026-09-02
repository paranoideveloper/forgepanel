// Package sysinfo reads what the machine is actually doing.
//
// The panel's Overview showed liveness, a version string, node counts and its
// own uptime — nothing about the server it runs on. An administrator watching
// for trouble had to leave the panel and open a shell, which is the one thing a
// control panel exists to avoid.
//
// Everything here comes from /proc and statfs. No dependency, no sampling
// daemon, and every number is a real reading rather than a plausible constant —
// a dashboard that invents figures is worse than one that omits them, because
// the operator acts on it.
//
// The node agent (cmd/forgenode) had its own copy of the CPU and memory reads.
// This is the shared one: the panel and the agent should not disagree about what
// "68% memory" means on the same box.
package sysinfo

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Memory is a snapshot of RAM, in bytes.
type Memory struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
	// SwapTotal/SwapUsed are reported because a box that has started swapping is
	// about to become slow in a way CPU and memory percentages do not show.
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
}

// Disk is a filesystem snapshot, in bytes.
type Disk struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
}

// CPU describes load. Percent is load-over-cores, which is a real measurement
// of this machine; it is NOT instantaneous utilisation, and is named Percent
// rather than Utilisation so nobody reads it as one.
type CPU struct {
	Cores   int     `json:"cores"`
	Load1   float64 `json:"load1"`
	Load5   float64 `json:"load5"`
	Load15  float64 `json:"load15"`
	Percent float64 `json:"percent"`
}

// Network is cumulative interface counters since boot, in bytes.
//
// Cumulative on purpose: a rate needs two readings and a clock, and the caller
// that polls is the one holding both. Returning a rate computed from a single
// reading would be a number with no meaning.
type Network struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

// Host is the machine's identity.
type Host struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	Uptime   int64  `json:"uptime_seconds"`
}

// Snapshot is everything, read together.
type Snapshot struct {
	CPU     CPU     `json:"cpu"`
	Memory  Memory  `json:"memory"`
	Disk    Disk    `json:"disk"`
	Network Network `json:"network"`
	Host    Host    `json:"host"`
}

// Read takes a snapshot. dataPath selects the filesystem to report; the panel's
// data directory is the one that matters, because that is what fills up and
// stops it writing configs.
func Read(dataPath string) Snapshot {
	return Snapshot{
		CPU:     ReadCPU(),
		Memory:  ReadMemory(),
		Disk:    ReadDisk(dataPath),
		Network: ReadNetwork(),
		Host:    ReadHost(),
	}
}

// ReadCPU reads /proc/loadavg.
func ReadCPU() CPU {
	c := CPU{Cores: runtime.NumCPU()}
	if c.Cores < 1 {
		c.Cores = 1
	}
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return c
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		c.Load1, _ = strconv.ParseFloat(f[0], 64)
		c.Load5, _ = strconv.ParseFloat(f[1], 64)
		c.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
	c.Percent = c.Load1 / float64(c.Cores) * 100
	if c.Percent > 100 {
		c.Percent = 100
	}
	return c
}

// ReadMemory reads /proc/meminfo.
//
// Used is Total-Available, not Total-Free. Free excludes the page cache, which
// the kernel will hand back on demand, so reporting it as used shows a box at
// 95% that is doing nothing at all.
func ReadMemory() Memory {
	var m Memory
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return m
	}
	defer f.Close()

	var total, avail, swapTotal, swapFree uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		v *= 1024 // meminfo is in kB
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		case "SwapTotal:":
			swapTotal = v
		case "SwapFree:":
			swapFree = v
		}
	}
	m.Total, m.Available, m.SwapTotal = total, avail, swapTotal
	if total >= avail {
		m.Used = total - avail
	}
	if swapTotal >= swapFree {
		m.SwapUsed = swapTotal - swapFree
	}
	return m
}

// ReadDisk stats the filesystem holding path.
func ReadDisk(path string) Disk {
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	d := Disk{Path: path}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return d
	}
	bs := uint64(st.Bsize)
	d.Total = st.Blocks * bs
	// Free-to-unprivileged, not free-to-root: the reserved blocks are not usable
	// by the panel, so counting them as free reports headroom it does not have.
	d.Free = st.Bavail * bs
	if d.Total >= d.Free {
		d.Used = d.Total - d.Free
	}
	return d
}

// ReadNetwork sums /proc/net/dev across real interfaces.
//
// Loopback is excluded: it carries the panel's own traffic to its cores and
// would dwarf the figure an operator is actually looking for. Virtual bridges
// and container veths are excluded for the same reason — they double-count
// traffic that also crosses a real NIC.
func ReadNetwork() Network {
	var n Network
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return n
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if skipInterface(name) {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 10 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		rxp, _ := strconv.ParseUint(fields[1], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		txp, _ := strconv.ParseUint(fields[9], 10, 64)
		n.RxBytes += rx
		n.RxPackets += rxp
		n.TxBytes += tx
		n.TxPackets += txp
	}
	return n
}

func skipInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"docker", "br-", "veth", "virbr", "tun", "tap", "wg", "awg"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var (
	kernelOnce sync.Once
	kernelStr  string
	osOnce     sync.Once
	osStr      string
)

// ReadHost reads the machine's identity and uptime.
func ReadHost() Host {
	h := Host{Arch: runtime.GOARCH}
	h.Hostname, _ = os.Hostname()

	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if secs, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.Uptime = int64(secs)
			}
		}
	}
	// Read once: neither changes without a reboot, and the dashboard polls.
	kernelOnce.Do(func() {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			kernelStr = strings.TrimSpace(string(b))
		}
	})
	osOnce.Do(func() { osStr = prettyOSName() })
	h.Kernel, h.OS = kernelStr, osStr
	return h
}

// prettyOSName reads PRETTY_NAME from os-release.
func prettyOSName() string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
				f.Close()
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		f.Close()
	}
	return runtime.GOOS
}

// Rate turns two Network readings into bytes per second.
//
// Here rather than at the call site because the subtraction has a trap: an
// interface counter is 64-bit but a container restart or a counter reset makes
// the second reading SMALLER, and an unguarded subtraction underflows to an
// astronomical rate. A reading that went backwards is reported as zero.
func Rate(prev, cur Network, elapsed time.Duration) (rxPerSec, txPerSec float64) {
	if elapsed <= 0 {
		return 0, 0
	}
	secs := elapsed.Seconds()
	if cur.RxBytes >= prev.RxBytes {
		rxPerSec = float64(cur.RxBytes-prev.RxBytes) / secs
	}
	if cur.TxBytes >= prev.TxBytes {
		txPerSec = float64(cur.TxBytes-prev.TxBytes) / secs
	}
	return rxPerSec, txPerSec
}
