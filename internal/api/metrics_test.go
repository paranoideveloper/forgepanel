package api

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The panel held real operational numbers and the only way to see any of them
// was to open the dashboard and look. Nothing to alert on, nothing to graph, and
// no way to notice at 3am that a node had been silent for an hour.

func scrape(t *testing.T, s *Server, token string) string {
	t.Helper()
	code, body := doGET(t, s, "/api/admin/metrics", token)
	if code != 200 {
		t.Fatalf("scrape: %d %s", code, body)
	}
	return body
}

func TestTheScrapeReportsTheNumbersWorthAlertingOn(t *testing.T) {
	s, token := adminAPI(t)

	soon := time.Now().Add(48 * time.Hour)
	for _, u := range []*store.User{
		{Username: "ok", SubToken: "a", Status: store.StatusActive},
		{Username: "full", SubToken: "b", Status: store.StatusActive, DataLimit: 100, UsedTraffic: 100},
		{Username: "lapsing", SubToken: "c", Status: store.StatusActive, ExpireAt: &soon},
		{Username: "off", SubToken: "d", Status: store.StatusDisabled},
	} {
		if err := s.db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}

	body := scrape(t, s, token)

	for _, want := range []string{
		`forgepanel_up 1`,
		`forgepanel_users{status="active"} 3`,
		`forgepanel_users{status="disabled"} 1`,
		`forgepanel_users_over_quota 1`,
		// The one worth alerting on BEFORE anything breaks, which is the whole
		// reason for a metrics endpoint rather than a dashboard.
		`forgepanel_users_expiring_7d 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q:\n%s", want, body)
		}
	}
}

func TestEveryMetricCarriesHelpAndType(t *testing.T) {
	s, token := adminAPI(t)
	body := scrape(t, s, token)

	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.SplitN(strings.SplitN(line, " ", 2)[0], "{", 2)[0]
		// A metric with no HELP is one somebody has to read the source to
		// understand, and the person reading a dashboard at 3am will not.
		if !strings.Contains(body, "# HELP "+name+" ") {
			t.Errorf("%s has no HELP line", name)
		}
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("%s has no TYPE line", name)
		}
	}
}

func TestAFamilyDeclaresItsTypeExactlyOnce(t *testing.T) {
	s, token := adminAPI(t)
	for i := 0; i < 3; i++ {
		if err := s.db.CreateUser(&store.User{
			Username: string(rune('a' + i)), SubToken: string(rune('a' + i)),
			Status: store.StatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	body := scrape(t, s, token)

	// Repeating HELP/TYPE per series makes the scrape fail OUTRIGHT rather than
	// degrading, so a labelled family cannot emit them casually per line.
	if n := strings.Count(body, "# TYPE forgepanel_users gauge"); n != 1 {
		t.Fatalf("forgepanel_users declared its type %d times, want 1", n)
	}
}

func TestANodeNameWithAQuoteDoesNotBreakTheWholeScrape(t *testing.T) {
	s, token := adminAPI(t)
	// Node names are operator-supplied. One unescaped quote makes the ENTIRE
	// scrape unparseable, so a single badly-named node would silently take down
	// all monitoring.
	n := &store.Node{Name: `edge "one"\two`, Address: "203.0.113.1", EnrollToken: "t", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, s, token)

	if !strings.Contains(body, `edge \"one\"\\two`) {
		t.Fatalf("the node name was not escaped:\n%s", body)
	}
}

func TestASilentNodeIsReportedAsDown(t *testing.T) {
	s, token := adminAPI(t)
	long := time.Now().Add(-time.Hour)
	fresh := time.Now()
	if err := s.db.SaveNode(&store.Node{Name: "quiet", Address: "1.1.1.1",
		EnrollToken: "t1", Enrolled: true, LastSeen: &long}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.SaveNode(&store.Node{Name: "healthy", Address: "1.1.1.2",
		EnrollToken: "t2", Enrolled: true, LastSeen: &fresh}); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, s, token)

	if !strings.Contains(body, `forgepanel_node_down{node="quiet"} 1`) {
		t.Errorf("a silent node is not reported as down:\n%s", body)
	}
	// A healthy node must emit a ZERO rather than be absent: an absent series
	// cannot be alerted on, and "no data" looks identical to "not scraped".
	if !strings.Contains(body, `forgepanel_node_down{node="healthy"} 0`) {
		t.Errorf("a healthy node is missing from the series:\n%s", body)
	}
}

func TestNotServingInboundsAreCounted(t *testing.T) {
	s, token := adminAPI(t)
	in := &store.Inbound{Remark: "broken", Protocol: "vless", Port: 443, Enabled: true}
	if err := s.db.SaveInbound(in); err != nil {
		t.Fatal(err)
	}
	if err := s.db.UpdateInboundFields(in.ID, map[string]any{
		"not_serving_reason": "no supervised engine"}); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, s, token)
	// Enabled but absent from the running config — the number an operator cannot
	// see any other way without reading every row.
	if !strings.Contains(body, "forgepanel_inbounds_not_serving 1") {
		t.Errorf("not-serving inbounds are not counted:\n%s", body)
	}
}

func TestMetricsRequireAuth(t *testing.T) {
	s, _ := adminAPI(t)
	// These numbers name every node and count every user. An open /metrics tells
	// anyone who finds it how large the deployment is and when it is struggling.
	if code, _ := doGET(t, s, "/api/admin/metrics", ""); code != 401 {
		t.Fatalf("unauthenticated scrape returned %d, want 401", code)
	}
}

func TestAnObservabilityTokenCanScrape(t *testing.T) {
	s, admin := adminAPI(t)
	secret, _ := mintToken(t, s, admin, "prometheus", "observability", "720h")

	code, body := withToken(t, s, "GET", "/api/admin/metrics", secret, "")
	if code != 200 {
		t.Fatalf("the narrowest token the panel issues could not scrape: %d %s", code, body)
	}
	if !strings.Contains(body, "forgepanel_up 1") {
		t.Errorf("unexpected scrape body: %s", body)
	}
}

// TestTheScrapeIsValidExpositionFormat checks the output against the format's
// own rules rather than against what this code happens to emit.
//
// Asserting that a scrape contains the strings this handler writes proves only
// that the handler is consistent with itself. The format has rules — one TYPE
// per family, TYPE before the samples, a parseable value on every line — and
// breaking any of them makes Prometheus reject the ENTIRE scrape, not the one
// bad metric.
func TestTheScrapeIsValidExpositionFormat(t *testing.T) {
	s, token := adminAPI(t)
	if err := s.db.CreateUser(&store.User{Username: "u", SubToken: "u", Status: store.StatusActive}); err != nil {
		t.Fatal(err)
	}
	n := &store.Node{Name: `weird "name"`, Address: "1.1.1.1", EnrollToken: "t", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}

	body := scrape(t, s, token)
	seenType := map[string]bool{}
	sampled := map[string]bool{}

	for i, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# TYPE ") {
			f := strings.Fields(line)
			if len(f) != 4 {
				t.Fatalf("line %d: malformed TYPE line %q", i+1, line)
			}
			if seenType[f[2]] {
				t.Fatalf("line %d: %s declares its TYPE twice; the scrape is rejected outright", i+1, f[2])
			}
			if sampled[f[2]] {
				t.Fatalf("line %d: TYPE for %s comes AFTER its samples", i+1, f[2])
			}
			seenType[f[2]] = true
			continue
		}
		if strings.HasPrefix(line, "# HELP ") {
			continue
		}

		// A sample line: <name>[{labels}] <value>
		//
		// Split on the LAST space, not the first: a label VALUE may legitimately
		// contain spaces (a node named "edge one"), and cutting at the first
		// space mistakes half the label set for the value.
		sp := strings.LastIndex(line, " ")
		if sp < 0 {
			t.Fatalf("line %d: no value on sample line %q", i+1, line)
		}
		nameAndLabels, value := line[:sp], line[sp+1:]
		if _, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err != nil {
			t.Fatalf("line %d: value %q is not a number", i+1, value)
		}
		name, labels, hasLabels := strings.Cut(nameAndLabels, "{")
		sampled[name] = true
		if !seenType[name] {
			t.Fatalf("line %d: sample for %s before its TYPE line", i+1, name)
		}
		if hasLabels {
			if !strings.HasSuffix(labels, "}") {
				t.Fatalf("line %d: unterminated label set %q", i+1, nameAndLabels)
			}
			// Quotes must be balanced once escapes are removed, or a label value
			// containing a quote has silently ended the label set early.
			inner := strings.TrimSuffix(labels, "}")
			unescaped := strings.NewReplacer(`\\`, "", `\"`, "").Replace(inner)
			if strings.Count(unescaped, `"`)%2 != 0 {
				t.Fatalf("line %d: unbalanced quotes in labels %q — one bad name breaks the whole scrape",
					i+1, inner)
			}
		}
	}
	if len(seenType) == 0 {
		t.Fatal("the scrape declared no metrics at all")
	}
}
