//go:build harness

// Command harness runs the connectivity matrix from inside the client
// container. It is deliberately the only thing on that side of the topology
// that knows anything about ForgePanel: everything it learns about a tunnel, it
// learns by asking the panel's public API and then running a real proxy core.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	harness "github.com/forgepanel/forgepanel/test/harness"
)

func main() {
	var (
		set        = flag.String("set", "all", "which cases to run: all | connectivity | policy | quick")
		only       = flag.String("only", "", "comma-separated case id substrings to run")
		results    = flag.String("results", getenv("HARNESS_RESULTS", "/results"), "results directory")
		panelURL   = flag.String("panel", getenv("HARNESS_PANEL_URL", "http://panel:2053"), "panel base URL")
		originHost = flag.String("origin", getenv("HARNESS_ORIGIN_HOST", "internet"), "origin hostname (resolvable only past the tunnel)")
		xrayBin    = flag.String("xray", getenv("HARNESS_XRAY_BIN", ""), "xray client binary")
		singboxBin = flag.String("singbox", getenv("HARNESS_SINGBOX_BIN", ""), "sing-box client binary")
		realDest   = flag.String("reality-dest", getenv("HARNESS_REALITY_DEST", "steal.harness.test:443"), "REALITY dest inside the topology")
		token      = flag.String("setup-token", getenv("HARNESS_SETUP_TOKEN", ""), "one-time panel setup token")
		adminUser  = flag.String("admin-user", getenv("HARNESS_ADMIN_USER", "harness"), "panel admin username")
		adminPass  = flag.String("admin-pass", getenv("HARNESS_ADMIN_PASS", "Harness-Probe-9143"), "panel admin password")
		failOnFail = flag.Bool("fail-on-fail", true, "exit non-zero when any case fails")
	)
	flag.Parse()

	hcfg := harness.Env{
		PanelURL:   *panelURL,
		AdminUser:  *adminUser,
		AdminPass:  *adminPass,
		SetupToken: *token,
		Origin: harness.Origin{
			Host:     *originHost,
			HTTPPort: envInt("HARNESS_ORIGIN_HTTP", 8080),
			TLSPort:  envInt("HARNESS_ORIGIN_TLS", 8443),
			DNSPort:  envInt("HARNESS_ORIGIN_DNS", 53),
		},
		XrayBin:     *xrayBin,
		SingboxBin:  *singboxBin,
		ResultsDir:  *results,
		RealityDest: *realDest,
		Timeout:     30 * time.Second,
	}

	r, err := harness.NewRunner(hcfg)
	if err != nil {
		die("prepare runner: %v", err)
	}
	if err := r.Bootstrap(); err != nil {
		die("bootstrap panel: %v", err)
	}

	// The control that makes every later pass meaningful: from here, the origin
	// must NOT be reachable without a tunnel.
	direct := harness.ProbeDirect(hcfg.Origin, 5*time.Second)
	isolated := direct != nil
	fmt.Printf("isolation: origin %s:%d reachable without tunnel = %v (%v)\n",
		hcfg.Origin.Host, hcfg.Origin.HTTPPort, !isolated, direct)

	cases := selectCases(*set, *only)
	if len(cases) == 0 {
		die("no cases selected for set=%q only=%q", *set, *only)
	}
	fmt.Printf("running %d cases against %s\n\n", len(cases), hcfg.PanelURL)

	var out []harness.Result
	for i, c := range cases {
		fmt.Printf("[%2d/%2d] %-46s ", i+1, len(cases), c.ID)
		start := time.Now()
		var res harness.Result
		if c.Expect == harness.ExpectDeny {
			res = r.RunPolicy(c)
		} else {
			res = r.Run(c)
		}
		fmt.Printf("%-12s %5.1fs  %s\n", res.Status, time.Since(start).Seconds(), trunc(res.Reason, 90))
		out = append(out, res)
	}

	rep := harness.NewReport(out)
	rep.Topology = harness.Topology{
		PanelURL:        hcfg.PanelURL,
		Origin:          fmt.Sprintf("%s:%d", hcfg.Origin.Host, hcfg.Origin.HTTPPort),
		DirectReachable: !isolated,
		IsolationNote: "the client container is attached only to the panel-facing network; the origin " +
			"is on a separate network reachable solely from the panel, so a payload that arrives " +
			"intact can only have crossed the tunnel",
	}
	rep.Cores = map[string]string{"xray": coreVersion(*xrayBin), "sing-box": coreVersion(*singboxBin)}
	if v, err := r.Panel.Version(); err == nil {
		rep.PanelVersion = v
	}
	// run.sh drops this next to the matrix after execing each pinned core inside
	// the base image the production Dockerfile ships.
	if b, err := os.ReadFile(*results + "/preflight.json"); err == nil {
		var p harness.Preflight
		if json.Unmarshal(b, &p) == nil {
			rep.AddPreflight(&p)
		}
	}

	jsonPath, err := rep.WriteJSON(*results)
	if err != nil {
		die("write matrix.json: %v", err)
	}
	tablePath, _ := rep.WriteTable(*results)
	fmt.Println()
	fmt.Print(rep.Table())
	fmt.Printf("\nwrote %s and %s\n", jsonPath, tablePath)

	if !isolated {
		die("the harness networks are not isolated; results cannot be trusted")
	}
	if *failOnFail && rep.Summary.Fail > 0 {
		os.Exit(1)
	}
}

func selectCases(set, only string) []harness.Case {
	var cases []harness.Case
	switch set {
	case "connectivity":
		cases = harness.ConnectivityCases()
	case "policy":
		cases = harness.PolicyCases()
	case "quick":
		cases = harness.QuickCases()
	default:
		cases = append(harness.ConnectivityCases(), harness.PolicyCases()...)
	}
	if only == "" {
		return cases
	}
	pats := strings.Split(only, ",")
	var out []harness.Case
	for _, c := range cases {
		for _, p := range pats {
			if p = strings.TrimSpace(p); p != "" && strings.Contains(c.ID, p) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func coreVersion(bin string) string {
	if bin == "" {
		return "(not configured)"
	}
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return "(unavailable: " + err.Error() + ")"
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "harness: "+format+"\n", args...)
	os.Exit(2)
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
