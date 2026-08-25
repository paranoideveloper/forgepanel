package firewall

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This file answers "is this port already held on the host, and by what" by
// reading the kernel's socket tables in /proc/net/{tcp,tcp6,udp,udp6}.
//
// It deliberately does NOT shell out to lsof/ss/netstat. None of the three is
// guaranteed to exist on the minimal VPS and container images ForgePanel is
// installed onto, and a missing binary would silently degrade the answer into
// "the port is free" -- the exact false answer that lets an operator create an
// inbound the engine can never bind.
//
// It also never probes by binding the port. The panel's own engine is listening
// on every inbound port it manages, so a bind probe would report the operator's
// existing inbound as a foreign process squatting on their port.

// tcpListen is the /proc/net/tcp `st` value for TCP_LISTEN. Every other state is
// an established or closing connection, which does not reserve the port for a
// new listener -- counting those would flag a busy web server's thousands of
// ephemeral peers as unusable ports.
const tcpListen = 0x0A

// procRoot is the procfs mount the scan reads. It is a variable so tests can
// point it at a fixture tree: the cases that matter (an IPv6 wildcard bind, a
// privileged sshd socket, a hex-encoded high port) cannot be conjured on a test
// machine on demand, and a test that raced a real listener would be flaky.
var procRoot = "/proc"

// Listener is one socket currently holding a local port on this host.
type Listener struct {
	Proto   string `json:"proto"`   // "tcp" or "udp"
	Address string `json:"address"` // textual local address: "0.0.0.0", "::", "127.0.0.1"
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`     // 0 when the owner could not be attributed
	Process string `json:"process,omitempty"` // "" when the owner could not be attributed

	// inode is the socket inode from /proc/net, used only to attribute the
	// socket to a pid. It is not part of the API surface.
	inode string
}

// decodeProcAddr converts the hex local address /proc/net prints into a textual
// IP. The address is stored as 32-bit words in HOST byte order, so every 4-byte
// group has to be reversed. Skipping that turns ::1 into a bogus address (and
// 127.0.0.1 into 1.0.0.127), which reads as "some other interface" and quietly
// loses real collisions.
func decodeProcAddr(h string) (string, bool) {
	if len(h) != 8 && len(h) != 32 {
		return "", false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return net.IP(raw).String(), true
}

// splitHexAddr splits a "HEXADDR:HEXPORT" field into its decoded parts.
func splitHexAddr(field string) (addr string, port int, ok bool) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 {
		return "", 0, false
	}
	a, ok := decodeProcAddr(field[:i])
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(field[i+1:], 16, 32)
	if err != nil || p == 0 || p > 65535 {
		return "", 0, false
	}
	return a, int(p), true
}

// zeroPeer reports whether a remote "ADDR:PORT" field is all zeroes, i.e. the
// socket is unconnected.
func zeroPeer(field string) bool {
	for _, r := range field {
		if r != '0' && r != ':' {
			return false
		}
	}
	return len(field) > 0
}

// parseProcNet turns one /proc/net table into the sockets that actually hold
// their local port. proto is the L4 family the table describes ("tcp"/"udp"),
// not the address family: /proc/net/tcp6 is still TCP.
func parseProcNet(r io.Reader, proto string) []Listener {
	var out []Listener
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	header := true
	for sc.Scan() {
		line := sc.Text()
		if header {
			// The first row is the column header ("sl local_address ...").
			header = false
			if strings.Contains(line, "local_address") {
				continue
			}
		}
		f := strings.Fields(line)
		// sl, local, remote, st, tx:rx, tr:when, retrnsmt, uid, timeout, inode
		if len(f) < 10 {
			continue
		}
		if proto == "tcp" {
			st, err := strconv.ParseUint(f[3], 16, 16)
			if err != nil || st != tcpListen {
				continue
			}
		} else if !zeroPeer(f[2]) {
			// A CONNECTED UDP socket is an outbound flow on an ephemeral port
			// that vanishes in milliseconds -- a DNS query in flight, an NTP
			// poll. Reporting those as "port in use" would reject perfectly
			// good inbound ports at random. A UDP *server* socket is
			// unconnected, so this keeps exactly the ones we care about.
			continue
		}
		addr, port, ok := splitHexAddr(f[1])
		if !ok {
			continue
		}
		out = append(out, Listener{Proto: proto, Address: addr, Port: port, inode: f[9]})
	}
	return out
}

// procNetTables is the set of socket tables scanned, and the L4 family each one
// belongs to.
var procNetTables = []struct{ file, proto string }{
	{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"},
}

// Listeners returns every socket currently holding a port on this host, with the
// owning process filled in where /proc permits.
//
// A missing or unreadable procfs yields an empty slice, never an error: on a
// non-Linux build host or a locked-down container the answer is simply "we
// cannot tell", and the caller must not turn that into a refusal.
func Listeners() []Listener {
	var out []Listener
	for _, t := range procNetTables {
		f, err := os.Open(filepath.Join(procRoot, "net", t.file))
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(f, t.proto)...)
		_ = f.Close()
	}
	annotateOwners(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// PortHolders returns the sockets holding port on the given L4 protocol
// ("tcp"/"udp"). An empty result means the port is free as far as the kernel's
// socket tables can tell.
func PortHolders(port int, proto string) []Listener {
	var out []Listener
	for _, l := range Listeners() {
		if l.Port == port && l.Proto == proto {
			out = append(out, l)
		}
	}
	return out
}

// annotateOwners fills PID/Process by matching socket inodes against every
// process's open descriptors.
//
// This is best-effort ON PURPOSE: reading another user's /proc/<pid>/fd needs
// privileges the panel may not have, and an unprivileged panel can only see its
// own sockets. A permission error must leave the name blank -- turning it into a
// failure would discard a detection that was already correct, which is worse
// than an unnamed "another process holds this port".
func annotateOwners(ls []Listener) {
	want := map[string][]int{}
	for i := range ls {
		if ls[i].inode == "" || ls[i].inode == "0" {
			continue
		}
		want[ls[i].inode] = append(want[ls[i].inode], i)
	}
	if len(want) == 0 {
		return
	}
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a process directory
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // not ours to inspect
		}
		name := ""
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			idx, ok := want[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")]
			if !ok {
				continue
			}
			if name == "" {
				if b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm")); err == nil {
					name = strings.TrimSpace(string(b))
				}
			}
			for _, i := range idx {
				ls[i].PID, ls[i].Process = pid, name
			}
		}
	}
}
