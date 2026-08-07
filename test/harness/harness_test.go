//go:build harness

// harness_test.go is the `go test` entry point for the connectivity matrix. It
// exists so CI can gate on the harness with the same command it uses for every
// other test, and so the matrix can be driven from an IDE.
//
// It refuses to run outside the harness topology. The matrix creates inbounds,
// rewrites users and deletes them again; pointing it at a panel that is not a
// disposable fixture would destroy real state, so the test requires
// FORGEPANEL_HARNESS=1 to be set explicitly and skips otherwise. `go test
// -tags harness ./...` on a developer machine is therefore always a no-op, and
// `go test ./...` never even compiles this file.
package harness

import (
	"os"
	"testing"
	"time"
)

func TestConnectivityMatrix(t *testing.T) {
	if os.Getenv("FORGEPANEL_HARNESS") != "1" {
		t.Skip("connectivity harness is opt-in: run test/harness/run.sh, " +
			"or set FORGEPANEL_HARNESS=1 inside the harness client container")
	}
	env := Env{
		PanelURL:   envOr("HARNESS_PANEL_URL", "http://panel:2053"),
		AdminUser:  envOr("HARNESS_ADMIN_USER", "harness"),
		AdminPass:  envOr("HARNESS_ADMIN_PASS", "Harness-Probe-9143"),
		SetupToken: os.Getenv("HARNESS_SETUP_TOKEN"),
		Origin: Origin{
			Host:     envOr("HARNESS_ORIGIN_HOST", "internet"),
			HTTPPort: 8080, TLSPort: 8443, DNSPort: 53,
		},
		XrayBin:     os.Getenv("HARNESS_XRAY_BIN"),
		SingboxBin:  os.Getenv("HARNESS_SINGBOX_BIN"),
		ResultsDir:  envOr("HARNESS_RESULTS", t.TempDir()),
		RealityDest: envOr("HARNESS_REALITY_DEST", "steal.harness.test:443"),
		Timeout:     30 * time.Second,
	}

	r, err := NewRunner(env)
	if err != nil {
		t.Fatalf("prepare runner: %v", err)
	}
	if err := r.Bootstrap(); err != nil {
		t.Fatalf("bootstrap panel: %v", err)
	}
	// Without isolation a "pass" proves nothing, so this is a hard failure
	// rather than a warning.
	if err := ProbeDirect(env.Origin, 5*time.Second); err == nil {
		t.Fatal("the origin is reachable without a tunnel; the harness networks are not isolated")
	}

	cases := append(ConnectivityCases(), PolicyCases()...)
	if only := os.Getenv("HARNESS_ONLY"); only != "" {
		cases = filterCases(cases, only)
	}
	results := make([]Result, 0, len(cases))
	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			var res Result
			if c.Expect == ExpectDeny {
				res = r.RunPolicy(c)
			} else {
				res = r.Run(c)
			}
			results = append(results, res)
			switch res.Status {
			case StatusFail:
				t.Errorf("%s: %s", res.Status, res.Reason)
			case StatusExperimental, StatusUnsupported:
				t.Logf("%s: %s", res.Status, res.Reason)
			}
		})
	}

	rep := NewReport(results)
	if p, err := rep.WriteJSON(env.ResultsDir); err == nil {
		t.Logf("matrix written to %s", p)
	}
	t.Log("\n" + rep.Table())
}

func filterCases(in []Case, substr string) []Case {
	var out []Case
	for _, c := range in {
		if containsFold(c.ID, substr) {
			out = append(out, c)
		}
	}
	return out
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
