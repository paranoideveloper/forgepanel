package api

import (
	"net"
	"strconv"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.1", "172.18.0.2", "192.168.1.1",
		"169.254.1.1", "100.64.0.1", "100.127.255.254", "::1", "not-an-ip",
	}
	public := []string{
		"203.0.113.16", "8.8.8.8", "1.1.1.1", "203.0.113.10", "100.128.0.1",
	}
	for _, ip := range private {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range public {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true, want false", ip)
		}
	}
}

func TestLooksLikeKey(t *testing.T) {
	good := []string{
		"065b883074970af6bee6a192eb0e3df6",                                 // 16-byte hex (MasterDNS)
		"4540e390ff726fa6a24b6859d007f373262ec1c2503347634eb58b5a2873c8d9", // 32-byte hex
		"ABCDEF0123456789ABCDEF0123456789",
	}
	bad := []string{
		"", "short", "0123456789abcde", // too short (<16)
		"065b883074970af6bee6a192eb0e3dg6",        // non-hex char 'g'
		"065b8830 74970af6bee6a192eb0e3df6",       // space (partial write)
		"065b883074970af6bee6a192eb0e3df6\ntrail", // embedded newline/garbage
	}
	for _, k := range good {
		if !looksLikeKey(k) {
			t.Errorf("looksLikeKey(%q) = false, want true", k)
		}
	}
	for _, k := range bad {
		if looksLikeKey(k) {
			t.Errorf("looksLikeKey(%q) = true, want false", k)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"panel.example.com":                 "panel.example.com",
		"HTTPS://Panel.Example.com":         "panel.example.com",
		"http://panel.example.com:2053/x/y": "panel.example.com",
		"panel.example.com/":                "panel.example.com",
		"  panel.example.com.  ":            "panel.example.com",
		"panel.example.com:8443":            "panel.example.com",
		"":                                  "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	good := []string{"panel.example.com", "a.b.c.co", "x-y.example.io"}
	bad := []string{"", "localhost", "no_underscores.com", "-bad.example.com", "bad-.example.com", "space here.com", "example"}
	for _, d := range good {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

func TestPortFree(t *testing.T) {
	// A port we hold is not free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if portFree("127.0.0.1", port) {
		t.Fatalf("port %d is held but reported free", port)
	}
	// After closing, the same port should become bindable again.
	freePort := func() int {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		_, ps, _ := net.SplitHostPort(l.Addr().String())
		p, _ := strconv.Atoi(ps)
		_ = l.Close()
		return p
	}()
	if !portFree("127.0.0.1", freePort) {
		t.Fatalf("port %d should be free", freePort)
	}
}
