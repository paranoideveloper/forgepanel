package api

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// This file backs the panel's status indicator.
//
// The indicator used to be a coloured dot with no label, no tooltip and no
// backing state — it could not tell an operator what was wrong, which subsystem
// was affected, or where to look, and it showed red for "unknown" as readily as
// for "broken". A warning light that cannot be acted on trains people to ignore
// warning lights, so it is replaced by real per-subsystem health.
//
// Two rules the old indicator broke:
//
//   - Never signal a problem by colour alone. Every state carries a machine
//     value AND human text, so it is legible to screen readers, in monochrome,
//     and to the ~8% of men with a colour-vision deficiency.
//   - Never render "unknown" as a fault. A subsystem that is deliberately absent
//     (no engine in light-server mode, no DNS zones configured) is reported as
//     not-configured, which is a normal state, not a failure.

// HealthState is one subsystem's condition. The values are ordered by severity so
// the overall state is simply the worst one present.
type HealthState string

const (
	HealthOK            HealthState = "healthy"
	HealthNotConfigured HealthState = "not_configured"
	HealthUnknown       HealthState = "unknown"
	HealthWarning       HealthState = "warning"
	HealthCritical      HealthState = "critical"
)

// severity ranks states so the worst wins when rolling up.
func severity(s HealthState) int {
	switch s {
	case HealthOK:
		return 0
	case HealthNotConfigured:
		return 1
	case HealthUnknown:
		return 2
	case HealthWarning:
		return 3
	case HealthCritical:
		return 4
	}
	return 2
}

// Subsystem is one row of the health panel.
type Subsystem struct {
	// Key is stable and machine-readable; Label is what a human reads.
	Key   string      `json:"key"`
	Label string      `json:"label"`
	State HealthState `json:"state"`
	// Summary is the one-line explanation shown in the tooltip. It always says
	// something, including for healthy states, so the indicator is never mute.
	Summary string `json:"summary"`
	// Detail carries the specifics an operator needs to act (error text, counts).
	Detail string `json:"detail,omitempty"`
	// Link points at the panel page or endpoint where this can be investigated.
	Link string `json:"link,omitempty"`
}

// HealthReport is the whole indicator's backing state.
type HealthReport struct {
	State      HealthState `json:"state"`
	Label      string      `json:"label"`
	Summary    string      `json:"summary"`
	Subsystems []Subsystem `json:"subsystems"`
	CheckedAt  time.Time   `json:"checked_at"`
}

// stateLabel is the accessible text that accompanies (never replaces) the colour.
func stateLabel(s HealthState) string {
	switch s {
	case HealthOK:
		return "Healthy"
	case HealthNotConfigured:
		return "Not configured"
	case HealthWarning:
		return "Warning"
	case HealthCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// handleHealthDetail reports per-subsystem health for the status indicator.
func (s *Server) handleHealthDetail(c *gin.Context) {
	c.JSON(200, s.healthReport())
}

func (s *Server) healthReport() HealthReport {
	subs := []Subsystem{
		s.healthAPI(),
		s.healthDatabase(),
		s.healthStorage(),
		s.healthEngine(),
		s.healthNodes(),
		s.healthCerts(),
		s.healthDNS(),
		s.healthMetering(),
		s.healthScheduler(),
	}

	worst := HealthOK
	var worstSub *Subsystem
	for i := range subs {
		if severity(subs[i].State) > severity(worst) {
			worst = subs[i].State
			worstSub = &subs[i]
		}
	}
	summary := "All subsystems are healthy."
	if worstSub != nil {
		summary = worstSub.Label + ": " + worstSub.Summary
	}
	return HealthReport{
		State: worst, Label: stateLabel(worst), Summary: summary,
		Subsystems: subs, CheckedAt: time.Now(),
	}
}

// healthStorage reports whether the data directory survives a redeploy.
//
// On a platform the container's filesystem is thrown away on every deploy and
// every restart unless a volume is mounted, and losing it is total: the admin
// account, every inbound, every user, and all traffic history. What makes it
// dangerous rather than merely bad is that the panel comes back looking
// perfectly healthy — a clean first-run install — so the operator's own reading
// of the evidence is that nothing is wrong.
//
// The container already warns at boot, in the platform log. That is the wrong
// surface: the panel is what an operator looks at, and by the time anything is
// missing the boot log has scrolled away. Verified the hard way, by watching a
// Railway deployment lose twelve working inbounds on a redeploy with nothing
// anywhere to say why.
func (s *Server) healthStorage() Subsystem {
	sub := Subsystem{Key: "storage", Label: "Data directory"}
	if s.cfg == nil || !s.paas().Enabled {
		// On a machine the panel owns, the data directory is ordinary disk.
		// There is no question to answer and a row here would be noise.
		sub.State, sub.Summary = HealthNotConfigured, "Ordinary disk; not a platform deployment."
		return sub
	}
	dir := s.cfg.DataDir
	mounted, known := dirIsMounted(dir)
	switch {
	case !known:
		sub.State = HealthUnknown
		sub.Summary = "Could not determine whether " + dir + " is a mounted volume."
	case mounted:
		sub.State = HealthOK
		sub.Summary = "Persisted on a mounted volume at " + dir + "."
	default:
		// Critical, not a warning. A warning invites "I will get to it", and
		// the cost of getting to it late is everything in the panel.
		sub.State = HealthCritical
		sub.Summary = "NOT PERSISTENT — " + dir + " is not a mounted volume, so the next deploy or " +
			"restart erases the admin account, every inbound, every user and all traffic history. " +
			"Attach a volume mounted at " + dir + "."
	}
	return sub
}

// dirIsMounted reports whether dir is itself a mount point, and whether the
// question could be answered at all.
//
// It reads /proc/self/mountinfo rather than calling df: BusyBox df reports the
// first mount found for the underlying DEVICE, which inside a container is
// whatever bind-mount came first — /etc/resolv.conf, in practice — so a
// correctly mounted volume reads as unmounted. Field 5 of a mountinfo line is
// the mount point itself.
func dirIsMounted(dir string) (mounted, known bool) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, false
	}
	dir = strings.TrimRight(dir, "/")
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && strings.TrimRight(f[4], "/") == dir {
			return true, true
		}
	}
	return false, true
}

func (s *Server) healthAPI() Subsystem {
	// If this handler is running, the API is serving. Reporting it is still
	// worthwhile: it tells the operator the indicator itself is live, so a stale
	// panel is distinguishable from a healthy one.
	return Subsystem{
		Key: "api", Label: "Panel API", State: HealthOK,
		Summary: "Serving requests.",
		Link:    "/healthz",
	}
}

func (s *Server) healthDatabase() Subsystem {
	sub := Subsystem{Key: "database", Label: "Database", Link: "/api/admin/backup"}
	if s.db == nil {
		sub.State = HealthNotConfigured
		sub.Summary = "Running without a database (stateless preview mode)."
		return sub
	}
	sqlDB, err := s.db.DB().DB()
	if err != nil {
		sub.State = HealthCritical
		sub.Summary = "Cannot reach the database handle."
		sub.Detail = err.Error()
		return sub
	}
	if err := sqlDB.Ping(); err != nil {
		sub.State = HealthCritical
		sub.Summary = "Database is not responding."
		sub.Detail = err.Error()
		return sub
	}
	sub.State = HealthOK
	sub.Summary = "Reachable."
	return sub
}

func (s *Server) healthEngine() Subsystem {
	sub := Subsystem{Key: "engine", Label: "Proxy engine", Link: "/api/admin/engines/status"}
	if s.engine == nil {
		// Light-server mode is a supported deployment, not a fault.
		sub.State = HealthNotConfigured
		sub.Summary = "This panel runs without a local engine (light-server mode)."
		sub.Detail = "Inbounds are served by remote nodes."
		return sub
	}
	es := engineHealthFrom(s.engine.Status())
	sub.State, sub.Summary, sub.Detail = es.State, es.Summary, es.Detail
	if s.engine.MalformedStatsTotal() > 0 && sub.State == HealthOK {
		sub.State = HealthWarning
		sub.Summary = "Running, but some traffic counters could not be parsed."
		sub.Detail = fmt.Sprintf("%d malformed stat entries since start; per-user "+
			"accounting may be incomplete.", s.engine.MalformedStatsTotal())
	}
	return sub
}

// engineHealthFrom classifies the supervised cores. Split out from healthEngine
// so the classification can be driven directly: reaching it through a live
// Controller means the "engine is wedged" case can only be tested by wedging a
// real core.
func engineHealthFrom(st []supervisor.Status) Subsystem {
	var sub Subsystem
	running, failed, wedged := 0, 0, 0
	var detail string
	for _, e := range st {
		switch e.State {
		case "running":
			running++
		case "unresponsive":
			// Up, and answering nothing. This used to match NEITHER bucket, so
			// a box whose only engine was wedged left running==0 and failed==0
			// and fell through to the reassuring "no engine is running yet —
			// add an inbound" below. The one condition an operator most needs
			// told was reported as its own opposite.
			failed++
			wedged++
			if e.LastError != "" && detail == "" {
				detail = e.Engine + ": " + e.LastError
			}
		case "crashed", "error":
			failed++
			if e.LastError != "" && detail == "" {
				detail = e.Engine + ": " + e.LastError
			}
		}
	}
	switch {
	case failed > 0:
		sub.State = HealthCritical
		// Worded from the operator's seat: "not running" sends them to the
		// process table, where a wedged core is present and looks fine.
		if wedged == failed {
			sub.Summary = fmt.Sprintf("%d engine process(es) running but not answering.", wedged)
		} else {
			sub.Summary = fmt.Sprintf("%d engine process(es) not running.", failed)
		}
		sub.Detail = detail
	case running == 0:
		// Nothing to run is normal on a fresh panel with no inbounds yet.
		sub.State = HealthNotConfigured
		sub.Summary = "No engine is running yet — add an inbound to start one."
	default:
		sub.State = HealthOK
		sub.Summary = fmt.Sprintf("%d engine process(es) running.", running)
	}
	return sub
}

// healthMetering reports whether every protocol the panel serves is actually
// having its traffic counted.
//
// The sing-box protocols — hysteria2, tuic, anytls, shadowtls, wireguard — can
// only be metered by a sing-box built with with_v2ray_api, which the official
// release archives are not. Without it a user can exhaust their plan entirely on
// those protocols and stay active forever, because the quota system is guarding
// traffic it cannot see. That failure is silent and always in the customer's
// favour, so it has to be stated somewhere an operator looks rather than left to
// be discovered from the billing.
func (s *Server) healthMetering() Subsystem {
	sub := Subsystem{Key: "metering", Label: "Traffic metering"}
	if s.engine == nil {
		sub.State = HealthOK
		sub.Summary = "No local engine; nodes report their own usage."
		return sub
	}
	sup := s.engine.SingboxStatsSupported()

	// Only a concern if sing-box is actually serving something.
	unmetered := 0
	if ins, err := s.db.ListInbounds(); err == nil {
		for _, in := range ins {
			n, nodeErr := in.Node()
			if nodeErr != nil || n == nil || !in.Enabled {
				continue
			}
			if model.EngineFor(n.Protocol) == model.EngineSingBox {
				unmetered++
			}
		}
	}

	switch {
	case sup.Supported:
		sub.State = HealthOK
		sub.Summary = "Every protocol is metered."
		sub.Detail = "sing-box " + sup.Version + " reports per-user traffic."
		if e := s.engine.SingboxStatsError(); e != "" {
			sub.State = HealthWarning
			sub.Summary = "sing-box counters are not readable right now."
			sub.Detail = e
		}
	case unmetered == 0:
		// Nothing sing-box serves, so nothing goes uncounted.
		sub.State = HealthOK
		sub.Summary = "Every protocol in use is metered."
		sub.Detail = sup.Reason
	default:
		sub.State = HealthWarning
		sub.Summary = fmt.Sprintf("%d inbound(s) are NOT metered; their users' quotas cannot be enforced.", unmetered)
		sub.Detail = sup.Reason
	}
	return sub
}

func (s *Server) healthNodes() Subsystem {
	sub := Subsystem{Key: "nodes", Label: "Remote nodes", Link: "/api/admin/nodes"}
	if s.db == nil {
		sub.State = HealthNotConfigured
		sub.Summary = "No database, so no nodes are tracked."
		return sub
	}
	nodes, err := s.db.ListNodes()
	if err != nil {
		sub.State = HealthUnknown
		sub.Summary = "Could not read the node list."
		sub.Detail = err.Error()
		return sub
	}
	if len(nodes) == 0 {
		sub.State = HealthNotConfigured
		sub.Summary = "No remote nodes are enrolled."
		return sub
	}
	stale := 0
	cutoff := time.Now().Add(-3 * time.Minute)
	for _, n := range nodes {
		if !n.Enrolled {
			continue
		}
		if n.LastSeen == nil || n.LastSeen.Before(cutoff) {
			stale++
		}
	}
	if stale > 0 {
		sub.State = HealthWarning
		sub.Summary = fmt.Sprintf("%d of %d node(s) have not reported recently.", stale, len(nodes))
		sub.Detail = "A node is considered stale after 3 minutes without a heartbeat."
		return sub
	}
	sub.State = HealthOK
	sub.Summary = fmt.Sprintf("All %d node(s) reporting.", len(nodes))
	return sub
}

func (s *Server) healthCerts() Subsystem {
	sub := Subsystem{Key: "certificates", Label: "Certificates", Link: "/api/admin/certs"}
	if s.certs == nil {
		sub.State = HealthNotConfigured
		sub.Summary = "No certificate store configured."
		return sub
	}
	list := s.certs.List()
	if len(list) == 0 {
		sub.State = HealthNotConfigured
		sub.Summary = "No certificates are managed by the panel."
		return sub
	}
	soon, expired := 0, 0
	for _, cert := range list {
		if cert.NotAfter.IsZero() {
			continue
		}
		switch {
		case cert.NotAfter.Before(time.Now()):
			expired++
		case cert.NotAfter.Before(time.Now().Add(14 * 24 * time.Hour)):
			soon++
		}
	}
	switch {
	case expired > 0:
		sub.State = HealthCritical
		sub.Summary = fmt.Sprintf("%d certificate(s) have expired.", expired)
		sub.Detail = "Clients pinning a valid chain will fail to connect."
	case soon > 0:
		sub.State = HealthWarning
		sub.Summary = fmt.Sprintf("%d certificate(s) expire within 14 days.", soon)
	default:
		sub.State = HealthOK
		sub.Summary = fmt.Sprintf("%d certificate(s), none expiring soon.", len(list))
	}
	return sub
}

func (s *Server) healthDNS() Subsystem {
	sub := Subsystem{Key: "forgedns", Label: "ForgeDNS", Link: "/api/admin/forgedns/status"}
	if s.fdns == nil {
		sub.State = HealthNotConfigured
		sub.Summary = "The DNS-tunnel subsystem is not enabled."
		return sub
	}
	st := s.fdns.Status()
	zones, _ := st["zones"].([]string)
	lastErr, _ := st["last_error"].(string)
	if len(zones) == 0 {
		sub.State = HealthNotConfigured
		sub.Summary = "No DNS-tunnel zones are configured."
		return sub
	}
	if lastErr != "" {
		sub.State = HealthCritical
		sub.Summary = "The DNS listener reported an error."
		sub.Detail = lastErr
		return sub
	}
	sub.State = HealthOK
	sub.Summary = fmt.Sprintf("%d zone(s) served.", len(zones))
	return sub
}

// healthScheduler reports the panel's own background workers.
//
// The scheduler drives traffic accounting, expiry, on-hold activation and the
// periodic data-limit reset. When it wedges nothing outwardly breaks: the panel
// keeps serving, the UI looks normal, and quotas simply stop being enforced —
// always in the customer's favour, so no one reports it. It used to expose no
// status whatsoever (the job loop's panic recovery had an empty body and every
// job returned bare on error), which made this the one failure the health
// indicator could not see.
func (s *Server) healthScheduler() Subsystem {
	sub := Subsystem{Key: "scheduler", Label: "Background jobs", Link: "/api/admin/health/detail"}
	if s.sched == nil {
		// The light constructor runs without a scheduler. That is a supported
		// deployment, not a fault, so it must not light up red.
		sub.State = HealthNotConfigured
		sub.Summary = "This panel runs no background scheduler."
		sub.Detail = "Traffic accounting and expiry are driven elsewhere."
		return sub
	}
	st := s.sched.Status()
	if !st.Running {
		sub.State = HealthCritical
		sub.Summary = "The background scheduler is not running."
		sub.Detail = "Traffic accounting, expiry and data-limit resets are all stopped, " +
			"so quotas are not being enforced."
		return sub
	}
	now := time.Now()
	if late := st.OverdueJobs(now); len(late) > 0 {
		parts := make([]string, 0, len(late))
		for _, j := range late {
			parts = append(parts, schedulerJobPhrase(j, now))
		}
		sub.State = HealthCritical
		sub.Summary = fmt.Sprintf("%d background job(s) have stopped running on schedule.", len(late))
		sub.Detail = strings.Join(parts, "; ")
		return sub
	}
	failing, firstErr := 0, ""
	for _, j := range st.Jobs {
		if j.LastError == "" {
			continue
		}
		failing++
		if firstErr == "" {
			firstErr = j.Name + ": " + j.LastError
		}
	}
	if failing > 0 {
		// A warning, not critical: the loop is alive and the next tick retries,
		// which is a different situation from a scheduler that has stopped.
		sub.State = HealthWarning
		sub.Summary = fmt.Sprintf("%d background job(s) failed their last run.", failing)
		sub.Detail = firstErr
		return sub
	}
	sub.State = HealthOK
	sub.Summary = fmt.Sprintf("%d background job(s) running on schedule.", len(st.Jobs))
	// Per-worker round-trip time, which is what turns "it is alive" into
	// something an operator can watch degrade before it breaks.
	timings := make([]string, 0, len(st.Jobs))
	for _, j := range st.Jobs {
		if j.Runs == 0 {
			continue
		}
		timings = append(timings, fmt.Sprintf("%s %.0fms", j.Name, j.LastDurationMS))
	}
	if len(timings) == 0 {
		sub.Detail = "No job has completed a cycle yet."
	} else {
		sub.Detail = "Last run time: " + strings.Join(timings, ", ") + "."
	}
	return sub
}

// schedulerJobPhrase describes one overdue job in operator-facing terms. A job
// that never returned and a job that never started need different wording:
// the first is a wedge to investigate, the second means the loop itself is gone.
func schedulerJobPhrase(j job.JobStatus, now time.Time) string {
	switch {
	case j.Running:
		return fmt.Sprintf("%s started %s ago and has not returned",
			j.Name, now.Sub(j.LastStart).Truncate(time.Second))
	case j.LastRun.IsZero():
		return j.Name + " has not run once since the panel started"
	default:
		return fmt.Sprintf("%s last ran %s ago", j.Name, now.Sub(j.LastRun).Truncate(time.Second))
	}
}
