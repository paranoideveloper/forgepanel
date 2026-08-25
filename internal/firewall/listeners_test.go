package firewall

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Real-shaped /proc/net tables. The fixtures matter more than a live probe:
// a test that opened a socket could only ever cover "an IPv4 TCP port on this
// machine right now", while every interesting case (an IPv6 wildcard bind, a
// privileged sshd socket, a connected UDP flow) is unreachable from a test.

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18452 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 17234 1 0000000000000000 100 0 0 10 0
   2: 0100007F:8085 0200007F:C1B2 01 00000000:00000000 00:00000000 00000000  1000        0 90210 1 0000000000000000 20 4 30 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22101 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22102 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:2383 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22104 1 0000000000000000 100 0 0 10 0
`

const procUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  515: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 17235 2 0000000000000000 0
  620: 0100007F:C350 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 91234 2 0000000000000000 0
`

const procUDP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
    1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22103 2 0000000000000000 0
`

// writeProcFixture builds a fake procfs tree and points the scanner at it.
func writeProcFixture(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"tcp": procTCP, "tcp6": procTCP6, "udp": procUDP, "udp6": procUDP6,
	} {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestParseProcNetTCPKeepsOnlyListeners(t *testing.T) {
	got := parseProcNet(strings.NewReader(procTCP), "tcp")
	if len(got) != 2 {
		t.Fatalf("want 2 listening sockets (the ESTABLISHED row must be dropped), got %d: %+v", len(got), got)
	}
	if got[0].Port != 22 || got[0].Address != "0.0.0.0" {
		t.Errorf("hex 00000000:0016 must decode to 0.0.0.0:22, got %s:%d", got[0].Address, got[0].Port)
	}
	if got[1].Port != 53 || got[1].Address != "127.0.0.1" {
		t.Errorf("hex 0100007F:0035 must decode to 127.0.0.1:53, got %s:%d", got[1].Address, got[1].Port)
	}
	if got[0].inode != "18452" {
		t.Errorf("socket inode not captured: %q", got[0].inode)
	}
}

func TestParseProcNetIPv6(t *testing.T) {
	got := parseProcNet(strings.NewReader(procTCP6), "tcp")
	if len(got) != 3 {
		t.Fatalf("want 3 ipv6 listeners, got %d: %+v", len(got), got)
	}
	want := []struct {
		addr string
		port int
	}{{"::", 443}, {"::1", 8080}, {"127.0.0.1", 9091}}
	for i, w := range want {
		if got[i].Address != w.addr || got[i].Port != w.port {
			t.Errorf("row %d: got %s:%d want %s:%d", i, got[i].Address, got[i].Port, w.addr, w.port)
		}
		if got[i].Proto != "tcp" {
			t.Errorf("row %d: /proc/net/tcp6 is still TCP, got %q", i, got[i].Proto)
		}
	}
}

func TestParseProcNetUDPSkipsConnectedFlows(t *testing.T) {
	got := parseProcNet(strings.NewReader(procUDP), "udp")
	if len(got) != 1 {
		t.Fatalf("a connected udp flow is an outbound socket, not a held port: %+v", got)
	}
	if got[0].Port != 53 || got[0].Proto != "udp" {
		t.Fatalf("want udp/53, got %s/%d", got[0].Proto, got[0].Port)
	}
}

func TestDecodeProcAddrRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "00", "zzzzzzzz", "000000000"} {
		if _, ok := decodeProcAddr(bad); ok {
			t.Errorf("decodeProcAddr(%q) must fail rather than invent an address", bad)
		}
	}
	if a, ok := decodeProcAddr("0000000000000000FFFF00000100007F"); !ok || a != "127.0.0.1" {
		t.Errorf("v4-mapped ipv6 must render as its ipv4 form, got %q ok=%v", a, ok)
	}
}

func TestListenersReadsAllFourTables(t *testing.T) {
	writeProcFixture(t)
	seen := map[string]bool{}
	for _, l := range Listeners() {
		seen[l.Proto+"/"+strconv.Itoa(l.Port)] = true
	}
	for _, want := range []string{"tcp/22", "tcp/53", "tcp/443", "tcp/8080", "tcp/9091", "udp/53", "udp/443"} {
		if !seen[want] {
			t.Errorf("missing %s from scan: %v", want, seen)
		}
	}
	if seen["udp/50000"] {
		t.Error("connected udp flow leaked into the scan")
	}
}

// TestPortHoldersSeparatesFamilies is the property the whole check rests on:
// a TCP listener on 443 must not make udp/443 look busy.
func TestPortHoldersSeparatesFamilies(t *testing.T) {
	writeProcFixture(t)
	if h := PortHolders(22, "tcp"); len(h) != 1 || h[0].Address != "0.0.0.0" {
		t.Fatalf("tcp/22 must be reported held: %+v", h)
	}
	if h := PortHolders(22, "udp"); len(h) != 0 {
		t.Fatalf("udp/22 is free — a TCP listener does not hold the UDP port: %+v", h)
	}
	if h := PortHolders(8080, "udp"); len(h) != 0 {
		t.Fatalf("udp/8080 is free: %+v", h)
	}
}
