package bridge

import (
	"strings"
	"testing"
)

// The golden strings below are BYTE-FOR-BYTE what was fed to each tool's real
// binary on 2026-08-26 and accepted — frps/frpc `verify`, rathole and backhaul
// started clean, wstunnel's client brought up the UDP listener. See
// backends_verified.md. Changing a template so the tool would reject it fails
// here, rather than on a bridge nobody can reach to debug.

func testSpec(backend string) Spec {
	return Spec{
		Backend: backend, ExitAddr: "203.0.113.10", TunnelPort: 38443,
		Token: "testtoken-long-enough",
		Services: []Service{
			{Name: "hy2", Protocol: "udp", BridgePort: 38081, ExitHost: "127.0.0.1", ExitPort: 38081},
			{Name: "reality", Protocol: "tcp", BridgePort: 38080, ExitHost: "127.0.0.1", ExitPort: 38080},
		},
	}
}

func render(t *testing.T, backend string, role Role) string {
	t.Helper()
	out, err := Render(testSpec(backend), role)
	if err != nil {
		t.Fatalf("%s/%s: %v", backend, role, err)
	}
	return out
}

func TestBackhaulRendersWhatTheBinaryAccepts(t *testing.T) {
	want := `[server]
bind_addr = "0.0.0.0:38443"
transport = "tcp"
token = "testtoken-long-enough"
ports = ["38081=38081", "38080=38080"]
`
	if got := render(t, "backhaul", RoleExit); got != want {
		t.Fatalf("exit config drifted from the bytes the binary accepted:\n--- got\n%s\n--- want\n%s", got, want)
	}
	want = `[client]
remote_addr = "203.0.113.10:38443"
transport = "tcp"
token = "testtoken-long-enough"
`
	if got := render(t, "backhaul", RoleBridge); got != want {
		t.Fatalf("bridge config drifted:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestRatholeRendersWhatTheBinaryAccepts(t *testing.T) {
	want := `[server]
bind_addr = "0.0.0.0:38443"
default_token = "testtoken-long-enough"

[server.services.hy2]
type = "udp"
bind_addr = "0.0.0.0:38081"

[server.services.reality]
type = "tcp"
bind_addr = "0.0.0.0:38080"
`
	if got := render(t, "rathole", RoleExit); got != want {
		t.Fatalf("exit config drifted:\n--- got\n%s\n--- want\n%s", got, want)
	}
	want = `[client]
remote_addr = "203.0.113.10:38443"
default_token = "testtoken-long-enough"

[client.services.hy2]
type = "udp"
local_addr = "127.0.0.1:38081"

[client.services.reality]
type = "tcp"
local_addr = "127.0.0.1:38080"
`
	if got := render(t, "rathole", RoleBridge); got != want {
		t.Fatalf("bridge config drifted:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestFRPRendersWhatVerifyAccepts(t *testing.T) {
	want := `bindPort = 38443
auth.method = "token"
auth.token = "testtoken-long-enough"
`
	if got := render(t, "frp", RoleExit); got != want {
		t.Fatalf("frps config drifted:\n--- got\n%s\n--- want\n%s", got, want)
	}
	want = `serverAddr = "203.0.113.10"
serverPort = 38443
auth.method = "token"
auth.token = "testtoken-long-enough"

[[proxies]]
name = "hy2"
type = "udp"
localIP = "127.0.0.1"
localPort = 38081
remotePort = 38081

[[proxies]]
name = "reality"
type = "tcp"
localIP = "127.0.0.1"
localPort = 38080
remotePort = 38080
`
	if got := render(t, "frp", RoleBridge); got != want {
		t.Fatalf("frpc config drifted:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestWstunnelRendersTheArgumentsTheBinaryParses(t *testing.T) {
	got := Args(render(t, "wstunnel", RoleBridge))
	want := []string{
		"client",
		"-L", "udp://38081:127.0.0.1:38081",
		"-L", "tcp://38080:127.0.0.1:38080",
		"--http-upgrade-path-prefix", "testtoken-long-enough",
		"ws://203.0.113.10:38443",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d = %q, want %q\nfull: %v", i, got[i], want[i], got)
		}
	}
}

func TestEveryOfferedBackendCarriesUDP(t *testing.T) {
	// Hysteria2, TUIC and WireGuard are UDP, and a TCP-only bridge drops them
	// while every dashboard stays green. Each flag below was set from the tool's
	// own binary (backends_verified.md); offering a backend that cannot carry
	// UDP would mean an operator can build a bridge that silently loses the
	// protocols that work best against Iranian DPI.
	for _, b := range All() {
		if !b.CarriesUDP {
			t.Errorf("%s is offered but cannot carry UDP", b.Name)
		}
	}
}

func TestAUDPServiceIsRefusedOnATCPOnlyBackend(t *testing.T) {
	// No backend is TCP-only today, so this pins the GUARD rather than a
	// current backend: the day a TCP-only one is added, a udp service on it
	// must fail loudly at render rather than produce a bridge that moves
	// nothing.
	tcpOnly := backends["rathole"]
	tcpOnly.Name = "tcponly"
	tcpOnly.Title = "TCP Only"
	tcpOnly.CarriesUDP = false
	backends["tcponly"] = tcpOnly
	defer delete(backends, "tcponly")

	spec := testSpec("tcponly")
	err := spec.Validate()
	if err == nil {
		t.Fatal("a udp service was accepted on a backend that cannot carry UDP")
	}
	if !strings.Contains(err.Error(), "Hysteria2") {
		t.Errorf("the error does not say what actually breaks: %v", err)
	}
}

func TestAShortTokenIsRefused(t *testing.T) {
	// The token is the only thing between the exit and anyone who finds its
	// tunnel port. A short one is worse than none, because it looks like
	// protection.
	s := testSpec("rathole")
	s.Token = "abc"
	if err := s.Validate(); err == nil {
		t.Fatal("a three-character shared token was accepted")
	}
}

func TestServicesRenderInAStableOrder(t *testing.T) {
	// A config that reshuffles between renders makes every diff meaningless and
	// restarts a tunnel that did not need restarting.
	s := testSpec("rathole")
	s.Services[0], s.Services[1] = s.Services[1], s.Services[0]
	a, err := Render(s, RoleExit)
	if err != nil {
		t.Fatal(err)
	}
	b := render(t, "rathole", RoleExit)
	if a != b {
		t.Fatal("reordering the service list changed the rendered config")
	}
}

func TestDuplicateServiceNamesAreRefused(t *testing.T) {
	// Both halves key on the name. Two services sharing one means one of them
	// silently never connects.
	s := testSpec("rathole")
	s.Services[1].Name = s.Services[0].Name
	if err := s.Validate(); err == nil {
		t.Fatal("two services with the same name were accepted")
	}
}

func TestAssetNamesMatchTheRealReleases(t *testing.T) {
	// Checked against the GitHub releases API on 2026-08-26. A wrong asset name
	// is a download that 404s at install time, on the machine furthest from the
	// operator.
	cases := map[string]string{
		"backhaul": "backhaul_linux_amd64.tar.gz",
		"rathole":  "rathole-x86_64-unknown-linux-gnu.zip",
		"frp":      "frp_0.71.0_linux_amd64.tar.gz",
		"wstunnel": "wstunnel_10.6.2_linux_amd64.tar.gz",
	}
	for name, want := range cases {
		b, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := b.Asset(); got != want {
			t.Errorf("%s asset = %q, want %q", name, got, want)
		}
	}
	// rathole moved orgs; rapiz1 redirects and a redirect that stops working is
	// an install failure nobody will connect to a project rename.
	if r, _ := Get("rathole"); r.Owner != "rathole-org" {
		t.Errorf("rathole owner = %q, want the current org", r.Owner)
	}
}

func TestAnUnknownBackendNamesTheOnesThatExist(t *testing.T) {
	_, err := Get("openvpn")
	if err == nil {
		t.Fatal("an unknown backend was accepted")
	}
	for _, n := range Names() {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("the error does not list %q as an option: %v", n, err)
		}
	}
}
