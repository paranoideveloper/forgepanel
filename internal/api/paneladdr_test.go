package api

import (
	"net"
	"strconv"
	"testing"
)

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
