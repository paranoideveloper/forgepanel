package dns

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CleanIP is one stored working address. This is the value that becomes the
// `address` field of a client config while sni/host stay on the real domain —
// the whole point of the scan.
type CleanIP struct {
	IP         string    `json:"ip"`
	AvgRTTMs   int64     `json:"avg_rtt_ms"`
	MinRTTMs   int64     `json:"min_rtt_ms"`
	LossPct    float64   `json:"loss_pct"`
	TLS13      bool      `json:"tls13"`
	ALPN       string    `json:"alpn,omitempty"`
	Score      float64   `json:"score"`
	VerifiedAt time.Time `json:"verified_at"`
}

// CleanIPSet is a named working set produced by a scan.
type CleanIPSet struct {
	Name string `json:"name"`
	// SNI is the hostname the set was verified against. A set is only valid for
	// that name: an address that serves one hostname's edge may not serve
	// another's.
	SNI       string    `json:"sni"`
	Port      int       `json:"port"`
	IPs       []CleanIP `json:"ips"`
	Sampled   int       `json:"sampled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Addresses returns the addresses, best first.
func (s CleanIPSet) Addresses() []string {
	out := make([]string, 0, len(s.IPs))
	for _, ip := range s.IPs {
		out = append(out, ip.IP)
	}
	return out
}

// Best returns the fastest address, or "" when the set is empty.
func (s CleanIPSet) Best() string {
	if len(s.IPs) == 0 {
		return ""
	}
	return s.IPs[0].IP
}

// Stale reports whether the set is older than maxAge. A working set decays:
// addresses that were clean last month are routinely blocked today, so a
// consumer should re-scan rather than trust an old set.
func (s CleanIPSet) Stale(now time.Time, maxAge time.Duration) bool {
	if s.UpdatedAt.IsZero() {
		return true
	}
	return now.Sub(s.UpdatedAt) > maxAge
}

// CleanIPRepo persists scan results.
type CleanIPRepo interface {
	SaveCleanIPs(set CleanIPSet) error
	LoadCleanIPs(name string) (*CleanIPSet, error)
	ListCleanIPSets() ([]CleanIPSet, error)
}

// ScanJob is a schedulable clean-IP scan: it runs a scan, keeps the working
// addresses and writes them to the repository under a name.
type ScanJob struct {
	// Name is the set the results are stored under.
	Name string
	// Config is the scan to run.
	Config ScanConfig
	// Repo receives the working set. Required.
	Repo CleanIPRepo
	// Keep bounds how many addresses are stored. Zero means 10.
	Keep int
	// MinWorking is the number of addresses below which the job reports a
	// problem rather than silently storing a thin set. Zero means 1.
	MinWorking int
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (j ScanJob) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// Run executes one scan and stores the working set. It returns the stored set
// alongside the raw report so a caller can show both the winners and why the
// rest were rejected.
func (j ScanJob) Run(ctx context.Context) (*CleanIPSet, *ScanReport, error) {
	if j.Repo == nil {
		return nil, nil, &Error{Op: "scan-job", Kind: KindValidation,
			Message: "no clean-IP repository was supplied", Remediation: "pass Deps.CleanIPs"}
	}
	report, err := Scan(ctx, j.Config)
	if err != nil {
		return nil, nil, err
	}
	keep := j.Keep
	if keep <= 0 {
		keep = 10
	}
	minWorking := j.MinWorking
	if minWorking <= 0 {
		minWorking = 1
	}
	now := j.now().UTC()
	working := report.Working()
	if len(working) > keep {
		working = working[:keep]
	}
	set := CleanIPSet{
		Name: strings.TrimSpace(j.Name), SNI: report.SNI, Port: report.Port,
		Sampled: report.Sampled, UpdatedAt: now,
	}
	if set.Name == "" {
		set.Name = report.SNI
	}
	for _, r := range working {
		set.IPs = append(set.IPs, CleanIP{
			IP: r.IP, AvgRTTMs: r.AvgRTTMs, MinRTTMs: r.MinRTTMs, LossPct: r.LossPct,
			TLS13: r.TLS13, ALPN: r.ALPN, Score: r.Score, VerifiedAt: now,
		})
	}
	if len(set.IPs) < minWorking {
		return &set, report, &Error{Op: "scan-job", Kind: KindNetwork,
			Message: fmt.Sprintf("the scan found %d working address(es) out of %d sampled (%d passed TCP), below the required minimum of %d",
				len(set.IPs), report.Sampled, report.TCPPassed, minWorking),
			Remediation: scanShortfallRemediation(report),
		}
	}
	if err := j.Repo.SaveCleanIPs(set); err != nil {
		return &set, report, wrapRepoError("scan-job", err)
	}
	return &set, report, nil
}

// scanShortfallRemediation explains an empty scan in terms of what the two
// phases showed, because "TCP passed but TLS did not" and "nothing connected"
// call for completely different fixes.
func scanShortfallRemediation(report *ScanReport) string {
	switch {
	case report.TCPPassed == 0:
		return fmt.Sprintf("no sampled address accepted a TCP connection on port %d. Either this host has no route to the CDN's ranges (check egress firewall and any transparent proxy), or the whole range is blocked from this vantage point. Raise --scan-samples, try a different port, or run the scan from the network the clients are actually on.", report.Port)
	case report.TLSPassed == 0:
		return fmt.Sprintf("addresses connected on TCP but no TLS 1.3 handshake completed for %q. The usual causes are: the hostname is not actually proxied at the provider (turn the orange cloud on and wait for propagation), the edge has no certificate for it yet, or an in-path device is resetting on the SNI. Verify the hostname loads over HTTPS from a browser first, then re-scan.", report.SNI)
	default:
		return "raise --scan-samples so more addresses are tried, and re-run. Clean-address availability varies by hour and by network."
	}
}

// LoadFreshCleanIPs returns a stored set only when it is recent enough to
// trust, so a caller never hands clients addresses verified a month ago.
func LoadFreshCleanIPs(repo CleanIPRepo, name string, maxAge time.Duration, now time.Time) (*CleanIPSet, error) {
	if repo == nil {
		return nil, &Error{Op: "load-clean-ips", Kind: KindValidation,
			Message: "no clean-IP repository was supplied", Remediation: "pass Deps.CleanIPs"}
	}
	set, err := repo.LoadCleanIPs(name)
	if err != nil {
		return nil, wrapRepoError("load-clean-ips", err)
	}
	if set == nil {
		return nil, &Error{Op: "load-clean-ips", Kind: KindNotFound,
			Message:     fmt.Sprintf("no clean-IP set named %q has been scanned yet", name),
			Remediation: "run a scan first (`forgectl provision --scan` or POST /dns/cleanip/scan)"}
	}
	if set.Stale(now, maxAge) {
		return set, &Error{Op: "load-clean-ips", Kind: KindValidation,
			Message: fmt.Sprintf("the clean-IP set %q was last verified %s ago, older than the %s freshness window",
				name, now.Sub(set.UpdatedAt).Round(time.Minute), maxAge),
			Remediation: "re-run the scan; edge addresses that were reachable then are frequently blocked now"}
	}
	return set, nil
}
