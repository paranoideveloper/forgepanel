package api

// Periodic housekeeping.
//
// Both of these were written, documented as scheduled, and never scheduled.
// ForgeDNS's EvictIdle carried the comment "(called by the scheduler)" while
// having no caller outside tests, so every tunnel session lived until the
// process restarted. The clean-IP scanner ran once when an operator clicked it
// and CleanIPSet.Stale — the function whose entire job is noticing that a set
// has aged — had no caller at all.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/forgepanel/forgepanel/internal/dns"
)

const (
	// cleanIPMaxAge is how old a clean-IP set may get before it is re-verified.
	//
	// A day. Edge addresses that completed a handshake yesterday are routinely
	// blocked today, and the failure is invisible from the panel — clients just
	// stop connecting — so waiting a week to notice is too long. Re-verifying
	// costs a handshake per stored address, not a fresh scan.
	cleanIPMaxAge = 24 * time.Hour

	// cleanIPRefreshTimeout bounds one refresh. It runs on the maintenance
	// goroutine, and a hung handshake there would stop every later run.
	cleanIPRefreshTimeout = 3 * time.Minute
)

// runMaintenance is the scheduler's periodic housekeeping hook.
func (s *Server) runMaintenance() {
	s.evictIdleTunnelSessions()
	s.refreshCleanIPs()
}

// evictIdleTunnelSessions releases sessions whose clients have gone away.
func (s *Server) evictIdleTunnelSessions() {
	if s.fdns == nil {
		return
	}
	// The count is deliberately not logged when it is zero: a line every minute
	// saying nothing happened is how a log stops being read.
	if n := s.fdns.EvictIdle(); n > 0 {
		fmt.Fprintf(os.Stderr, "forgepanel: forgedns: evicted %d idle session(s)\n", n)
	}
}

// refreshCleanIPs re-verifies stored clean-IP sets that have gone stale.
//
// It re-tests the addresses already in a set rather than scanning for new ones.
// A full scan is thousands of outbound connections; finding NEW addresses stays
// an operator action because that is the part with a cost worth deciding about.
func (s *Server) refreshCleanIPs() {
	if s.db == nil {
		return
	}
	repo, err := dns.NewGormStore(s.db.DB())
	if err != nil {
		return
	}
	sets, err := repo.ListCleanIPSets()
	if err != nil || len(sets) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cleanIPRefreshTimeout)
	defer cancel()

	for _, set := range sets {
		name := set.Name
		res, err := dns.RefreshCleanIPs(ctx, repo, name, cleanIPMaxAge, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "forgepanel: clean-IP refresh %q: %v\n", name, err)
			continue
		}
		if res.Skipped != "" {
			// Fresh, or never scanned. Not a failure, and logging it every cycle
			// would train an operator to ignore this line.
			continue
		}
		if len(res.Dropped) > 0 {
			fmt.Fprintf(os.Stderr,
				"forgepanel: clean-IP set %q: %d of %d addresses stopped working (%v)\n",
				name, len(res.Dropped), res.Before, res.Dropped)
		}
		if res.After == 0 {
			// The one an operator has to see: every known-good address is now
			// blocked, and clients are being handed nothing that works.
			fmt.Fprintf(os.Stderr,
				"forgepanel: clean-IP set %q is now EMPTY — every stored address failed; run a new scan\n", name)
		}
	}
}
