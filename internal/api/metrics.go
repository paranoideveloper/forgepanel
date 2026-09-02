package api

// A Prometheus scrape endpoint.
//
// The panel held real operational numbers — how many users are over quota, which
// nodes have stopped reporting, how many engine counters failed to parse — and
// the only way to see any of it was to open the dashboard and look. There was
// nothing to alert on, nothing to graph over time, and no way to notice at 3am
// that a node had been silent for an hour.
//
// TEXT FORMAT BY HAND, no client library. The exposition format is a dozen lines
// of printf and the alternative is a dependency tree larger than the rest of the
// panel's, for a handler that emits perhaps forty numbers. The format is
// stable and documented; this is one of the rare cases where writing it out is
// genuinely simpler than depending on something.
//
// AUTH IS REQUIRED, and that is not paranoia. These numbers name every node and
// count every user; an open /metrics tells anyone who finds it how large the
// deployment is, which nodes are struggling, and when the operator is asleep.
// It uses the ordinary token path, so an `observability`-scoped API token — the
// narrowest one the panel issues — is exactly what a scraper should hold.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// metricWriter accumulates exposition-format output.
type metricWriter struct {
	b strings.Builder
}

// gauge writes one metric with its HELP and TYPE lines.
//
// Prometheus tolerates missing metadata, but a metric with no HELP is one
// somebody has to go and read the source to understand — and the person reading
// a dashboard at 3am is not going to.
func (w *metricWriter) gauge(name, help string, value float64) {
	fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}

func (w *metricWriter) counter(name, help string, value float64) {
	fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s counter\n%s %g\n", name, help, name, name, value)
}

// labelled writes a metric family with one line per label set.
//
// The HELP and TYPE are emitted ONCE for the family, which the format requires:
// repeating them per series makes the scrape fail outright rather than
// degrading, so this cannot be done casually per line.
func (w *metricWriter) labelled(name, help, typ string, series map[string]float64) {
	fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	// Sorted, so a diff between two scrapes is a change in the numbers rather
	// than in Go's map ordering.
	keys := make([]string, 0, len(series))
	for k := range series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&w.b, "%s{%s} %g\n", name, k, series[k])
	}
}

// label renders one name="value" pair, escaped.
//
// It does NOT use %q, which escapes correctly for Go and not for Prometheus: %q
// renders a non-printable byte as \xNN, which the exposition format does not
// accept and which makes the whole scrape unparseable. Only these three
// sequences are defined, so only these three are produced.
//
// Node names and usernames are operator-supplied and can contain a quote or a
// backslash; one of those unescaped means a single badly-named node silently
// takes down all monitoring.
func label(name, value string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return name + `="` + r.Replace(value) + `"`
}

func (s *Server) handleMetrics(c *gin.Context) {
	w := &metricWriter{}

	w.gauge("forgepanel_up", "Always 1, so a scrape failure is distinguishable from a panel reporting zeros.", 1)

	if s.db != nil {
		users, err := s.db.ListUsers(0)
		if err == nil {
			byStatus := map[string]float64{}
			var overQuota, expiringSoon float64
			now := time.Now()
			for _, u := range users {
				byStatus[label("status", string(u.Status))]++
				if u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit {
					overQuota++
				}
				if u.ExpireAt != nil && u.ExpireAt.After(now) && u.ExpireAt.Sub(now) < 7*24*time.Hour {
					expiringSoon++
				}
			}
			w.labelled("forgepanel_users", "Users by lifecycle status.", "gauge", byStatus)
			w.gauge("forgepanel_users_over_quota",
				"Users whose usage has reached their data limit.", overQuota)
			// The number worth alerting on BEFORE anything breaks, which is the
			// whole reason for a metrics endpoint rather than a dashboard.
			w.gauge("forgepanel_users_expiring_7d",
				"Active users whose subscription expires within seven days.", expiringSoon)
		}

		if inbounds, err := s.db.ListInbounds(); err == nil {
			var enabled, notServing float64
			for _, in := range inbounds {
				if in.Enabled {
					enabled++
				}
				if in.Enabled && in.NotServingReason != "" {
					notServing++
				}
			}
			w.gauge("forgepanel_inbounds_enabled", "Inbounds the operator has enabled.", enabled)
			// Enabled but absent from the running config. This is the one an
			// operator cannot see any other way without reading each row.
			w.gauge("forgepanel_inbounds_not_serving",
				"Enabled inbounds that are NOT in the running configuration.", notServing)
		}

		if nodes, err := s.db.ListNodes(); err == nil {
			silent := map[string]float64{}
			cutoff := time.Now().Add(-nodeSilentAfter)
			for _, n := range nodes {
				if !n.Enrolled {
					continue
				}
				down := 0.0
				if n.LastSeen == nil || n.LastSeen.Before(cutoff) {
					down = 1
				}
				silent[label("node", n.Name)] = down
			}
			if len(silent) > 0 {
				w.labelled("forgepanel_node_down",
					"1 when an enrolled node has stopped reporting, 0 when it is healthy.",
					"gauge", silent)
			}
		}
	}

	if s.engine != nil {
		// Degraded accounting made visible. A counter that fails to parse is
		// traffic nobody is billing for, and the symptom without this is a usage
		// figure that quietly stops moving.
		w.counter("forgepanel_malformed_traffic_counters_total",
			"Engine traffic counters that could not be parsed since start.",
			float64(s.engine.MalformedStatsTotal()))
	}

	if s.login != nil {
		for k, v := range s.login.Metrics() {
			w.counter("forgepanel_login_"+k+"_total",
				"Login rate-limiter "+strings.ReplaceAll(k, "_", " ")+" since start.", float64(v))
		}
	}

	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, w.b.String())
}
