package dns

// Keeping a clean-IP set honest over time.
//
// A working set decays. Addresses that completed a TLS handshake through the
// edge last month are routinely blocked today, and the panel was handing them to
// clients regardless: the scanner existed, ran once when an operator clicked it,
// and CleanIPSet.Stale had no caller anywhere. So the set aged quietly and the
// first sign of trouble was users reporting that configs had stopped working.
//
// THIS RE-VERIFIES, IT DOES NOT RE-SCAN. A full scan samples thousands of
// addresses across whole CIDR ranges; doing that on a timer is a lot of outbound
// connections nobody asked for, from a server whose whole purpose is to be
// inconspicuous. Re-testing the addresses ALREADY in the set is a few dozen
// handshakes, needs no stored CIDR list, and catches the exact failure that
// matters — an address that used to work and no longer does.
//
// Finding NEW addresses stays an operator action, because that is the part with
// a cost worth deciding about.

import (
	"context"
	"fmt"
	"time"
)

// RefreshResult describes what a refresh did.
type RefreshResult struct {
	Name string `json:"name"`
	// Before and After are address counts. A set that empties itself is the
	// signal an operator most needs: every known-good address is now blocked.
	Before int `json:"before"`
	After  int `json:"after"`
	// Dropped names the addresses that stopped working, so the change is
	// reviewable rather than just a number going down.
	Dropped []string `json:"dropped,omitempty"`
	Skipped string   `json:"skipped,omitempty"`
}

// RefreshCleanIPs re-verifies a stored set if it has gone stale.
//
// It returns a result with Skipped set (and no error) when there is nothing to
// do: no set, or one still fresh. "Nothing to do" is not a failure, and a
// scheduler that logged it as one would train an operator to ignore the log.
func RefreshCleanIPs(ctx context.Context, repo CleanIPRepo, name string, maxAge time.Duration, now time.Time) (*RefreshResult, error) {
	if repo == nil {
		return nil, &Error{Op: "refresh-clean-ips", Kind: KindValidation,
			Message: "no clean-IP repository was supplied", Remediation: "pass Deps.CleanIPs"}
	}
	set, err := repo.LoadCleanIPs(name)
	if err != nil {
		return nil, wrapRepoError("refresh-clean-ips", err)
	}
	if set == nil {
		// Never scanned. Refreshing must not become a way to start scanning on a
		// panel that never asked for it.
		return &RefreshResult{Name: name, Skipped: "no set has been scanned yet"}, nil
	}
	if !set.Stale(now, maxAge) {
		return &RefreshResult{Name: name, Before: len(set.IPs), After: len(set.IPs),
			Skipped: "the set is still within its freshness window"}, nil
	}
	if len(set.IPs) == 0 {
		return &RefreshResult{Name: name, Skipped: "the set is empty; a new scan is needed to find addresses"}, nil
	}

	before := set.Addresses()
	report, err := Scan(ctx, ScanConfig{
		SNI:  set.SNI,
		Port: set.Port,
		// The addresses already in the set, and only those.
		Addresses: before,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh clean-IP set %q: %w", name, err)
	}

	survived := map[string]bool{}
	next := CleanIPSet{
		Name: set.Name, SNI: set.SNI, Port: set.Port,
		Sampled: len(before), UpdatedAt: now.UTC(),
	}
	for _, r := range report.Working() {
		survived[r.IP] = true
		next.IPs = append(next.IPs, CleanIP{
			IP: r.IP, AvgRTTMs: r.AvgRTTMs, MinRTTMs: r.MinRTTMs, LossPct: r.LossPct,
			TLS13: r.TLS13, ALPN: r.ALPN, Score: r.Score, VerifiedAt: now.UTC(),
		})
	}

	var dropped []string
	for _, ip := range before {
		if !survived[ip] {
			dropped = append(dropped, ip)
		}
	}

	// An empty result is still written. Keeping the old set because the new one
	// is empty would hand clients addresses that have just been PROVEN blocked —
	// exactly the state this exists to prevent — and would hide the outage.
	if err := repo.SaveCleanIPs(next); err != nil {
		return nil, wrapRepoError("refresh-clean-ips", err)
	}
	return &RefreshResult{
		Name: name, Before: len(before), After: len(next.IPs), Dropped: dropped,
	}, nil
}
