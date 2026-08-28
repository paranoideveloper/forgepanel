package main

import (
	"os"
	"strings"
	"testing"
)

// Behind a platform edge the panel must serve PLAIN HTTP.
//
// This is a source guard rather than a behavioural test because the branch it
// protects lives in the goroutine that owns the process's only listener, and
// the failure it prevents cannot be observed from inside the package: the panel
// comes up, reports itself healthy, and answers the platform's plaintext proxy
// request with a TLS handshake. The platform then reports "application failed
// to respond" — which reads as a crash, not as a protocol mismatch — and there
// is no shell on the box to look any closer.
func TestBehindAPlatformEdgeThePanelServesPlainHTTP(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "cfg.PaaS().Enabled")
	if i < 0 {
		t.Fatal("nothing in main consults PaaS mode; the panel would serve TLS into a plaintext edge")
	}
	// The plain-HTTP Serve must come BEFORE the ServeTLS the normal path uses,
	// and must return, or the TLS path runs anyway.
	branch := body[i:]
	plain := strings.Index(branch, "httpSrv.Serve(ln)")
	tlsAt := strings.Index(branch, "httpSrv.ServeTLS(ln")
	if plain < 0 {
		t.Fatal("PaaS mode does not reach a plain-HTTP Serve")
	}
	if tlsAt >= 0 && plain > tlsAt {
		t.Fatal("the TLS listener is reached first in PaaS mode")
	}
	if !strings.Contains(branch[plain:plain+400], "return") {
		t.Fatal("the plain-HTTP branch falls through into the TLS path")
	}
}
