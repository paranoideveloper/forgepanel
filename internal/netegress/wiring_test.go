package netegress_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every internet-bound HTTP client must come from netegress.
//
// This is the guard the feature lives or dies by. The package can be perfect,
// tested and documented, and if one call site still constructs its own
// &http.Client{} then that call still goes direct — and it fails on exactly the
// network the proxy exists for, silently, because a direct dial on a censored
// link times out rather than erroring in any distinctive way.
//
// A client that talks to LOOPBACK must NOT be proxied: sending the local
// sing-box API or forgectl's call to the panel through a remote proxy would
// break them. Those are listed here with a reason, so exempting one is a
// deliberate act recorded in the tree rather than an omission.
var loopbackOnly = map[string]string{
	"internal/core/singboxapi/singboxapi.go": "talks to the local sing-box API over a unix/loopback socket",
	"internal/diag/verify.go":                "dials the loopback SOCKS port of a client core it just spawned itself",
	"cmd/forgenode/main.go":                  "the node agent's mTLS client to its own panel, pinned to a certificate",
	"internal/forgedns/upstream/manager.go":  "health-checks the local ForgeDNS upstream process",
	"cmd/forgectl/health.go":                 "probes the panel on this machine, with TLS trust deliberately not pinned",
	"cmd/forgectl/edge_ops.go":               "reads the panel's own feed at 127.0.0.1:2053",
}

func TestEveryInternetBoundClientGoesThroughNetegress(t *testing.T) {
	root := filepath.FromSlash("../..")
	bare := regexp.MustCompile(`&http\.Client\{`)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				switch info.Name() {
				case ".git", "node_modules", "frontend", "third_party", "test", "e2e", "dist", "bin":
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if strings.HasPrefix(rel, "internal/netegress/") {
			return nil // the package that builds them
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if !bare.Match(b) {
			return nil
		}
		if reason, ok := loopbackOnly[rel]; ok {
			if reason == "" {
				offenders = append(offenders, rel+" (exempt with no reason given)")
			}
			return nil
		}
		offenders = append(offenders, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these build their own HTTP client, so they ignore the configured egress proxy "+
			"and go direct on the network the proxy exists for:\n  %s\n\n"+
			"Use netegress.Client(timeout). If the call is to loopback, add it to loopbackOnly with "+
			"the reason.", strings.Join(offenders, "\n  "))
	}
}
