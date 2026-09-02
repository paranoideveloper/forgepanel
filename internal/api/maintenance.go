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
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/telegram"
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

	// poolCheckTimeout bounds one sweep across every rotation pool, for the same
	// reason: it probes with a real TLS handshake per domain, and a hung one
	// must not stop the rest of the maintenance cycle.
	poolCheckTimeout = 3 * time.Minute

	// certExpiryWarn is how close to expiry a certificate has to be before the
	// panel says something.
	//
	// Twenty-one days. Let's Encrypt issues for 90 and renews at 30, so a
	// certificate still unrenewed with three weeks left means renewal is
	// FAILING, not merely pending — which is the only version of this worth
	// waking anyone for. Warning at 30 would fire on every healthy panel.
	certExpiryWarn = 21 * 24 * time.Hour

	// reconcileTimeout bounds one pass over the per-inbound cores. awg-quick
	// shells out per interface, so a host with many tunnels is not instant, and a
	// hung one must not stop the rest of the maintenance cycle.
	reconcileTimeout = 2 * time.Minute

	// dns01RenewTimeout bounds one DNS-01 renewal: an order, a TXT record, and
	// waiting for it to propagate to the authoritative nameservers.
	dns01RenewTimeout = 10 * time.Minute
)

// nodeSilentAfter is how long a node may go without reporting before it counts
// as down.
//
// Three minutes, matching the health endpoint's own threshold — two different
// answers to "is this node up" is how an operator ends up trusting neither. A
// node heartbeats far more often than this, so the window tolerates one missed
// beat and a slow network without crying wolf.
const nodeSilentAfter = 3 * time.Minute

// runMaintenance is the scheduler's periodic housekeeping hook.
func (s *Server) runMaintenance() {
	s.evictIdleTunnelSessions()
	s.refreshCleanIPs()
	s.checkRotationPools()
	s.sweepCertificates()
	s.reconcileCores()
	s.applyNetTune()
	s.checkNodesReachable()
	s.rotateWarpIfDue()
}

// reconcileCores brings back inbounds that went away on their own.
//
// Only the cores that reconcile per inbound — Brook, AmneziaWG — take part; the
// supervised ones restart themselves on crash and their Reload is a restart that
// would drop every live connection. See adapter.Reconciler.
//
// An AmneziaWG interface goes down for reasons that have nothing to do with the
// panel: the kernel module is reloaded, someone runs awg-quick down, a reboot
// races the unit. Before this the panel noticed, reported it correctly, and did
// nothing, because the only thing that re-applied a plan was a mutation to some
// other inbound.
func (s *Server) reconcileCores() {
	if s.engine == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()
	for name, err := range s.engine.ReconcileCores(ctx) {
		fmt.Fprintf(os.Stderr, "forgepanel: reconciling %s: %v\n", name, err)
	}
}

// sweepCertificates warns about certificates approaching expiry, and renews the
// ones nothing else will.
//
// autocert renews on the NEXT TLS HANDSHAKE, which is fine for a busy site and
// wrong for a panel: an admin panel can go weeks between visits, and the visit
// that would trigger renewal is the one that fails. A DNS-01 panel never renews
// through autocert at all — autocert cannot perform that challenge, which is the
// whole reason DNS-01 exists here — so its certificate simply expires.
//
// telegram.EventCertExpiry was declared for this and had no caller anywhere.
func (s *Server) sweepCertificates() {
	if s.certs == nil || s.cfg == nil {
		return
	}
	now := time.Now()

	// The panel's own domain first: it is the one whose expiry locks the
	// operator out of the thing they would use to fix it.
	p := s.cfg.Panel()
	if p != nil && p.Domain != "" {
		s.checkOneCertificate(p.Domain, now, true)
	}

	if s.db == nil {
		return
	}
	domains, err := s.db.ListDomains()
	if err != nil {
		return
	}
	for _, d := range domains {
		if p != nil && strings.EqualFold(d.Name, p.Domain) {
			continue // already done, and doing it twice would alert twice
		}
		// A domain the operator manages by hand is theirs to renew; alerting on
		// it is still right, renewing it is not.
		s.checkOneCertificate(d.Name, now, false)
	}
}

// checkOneCertificate reports on one domain, and renews it when the panel is the
// thing responsible for renewing it.
func (s *Server) checkOneCertificate(domain string, now time.Time, panelOwned bool) {
	info, ok := s.certs.CachedInfo(domain)
	if !ok {
		// No certificate yet. That is the first-issuance path's business, not a
		// renewal failure, and alerting here would fire on every fresh install.
		return
	}
	left := info.NotAfter.Sub(now)
	if left > certExpiryWarn {
		return
	}

	// DNS-01 is the case nothing else covers: autocert cannot perform the
	// challenge, so no handshake will ever renew this.
	if panelOwned && s.usesDNS01() {
		ctx, cancel := context.WithTimeout(context.Background(), dns01RenewTimeout)
		_, err := s.issueDNS01(ctx, domain)
		cancel()
		s.recordACMEOutcome(domain, err)
		if err == nil {
			return // renewed; nothing to say
		}
		fmt.Fprintf(os.Stderr, "forgepanel: DNS-01 renewal for %q failed with %v left: %v\n",
			domain, left.Round(time.Hour), err)
	}

	days := int(left.Hours() / 24)
	if days < 0 {
		fmt.Fprintf(os.Stderr, "forgepanel: certificate for %q EXPIRED %d day(s) ago\n", domain, -days)
	} else {
		fmt.Fprintf(os.Stderr, "forgepanel: certificate for %q expires in %d day(s)\n", domain, days)
	}
	msg := fmt.Sprintf("The certificate for %s expires in %d day(s). "+
		"Renewal has not happened on its own — check Certificates → Force ACME issue/renew.", domain, days)
	if days < 0 {
		msg = fmt.Sprintf("The certificate for %s EXPIRED %d day(s) ago. "+
			"Clients are refusing the connection now.", domain, -days)
	}
	s.emit(telegram.EventCertExpiry, domain, msg)
}

// checkRotationPools health-checks every rotation pool and retires the domains
// that have stopped answering.
//
// A rotation pool exists so that a blocked domain is replaced before anyone
// notices. It could only be swept by name, from an HTTP handler somebody had to
// call — the rotate handler's own comment says "rotating with no config just\n// health-checks and retires, which is a legitimate scheduled operation", and
// nothing scheduled it. So a pool whose domains were all blocked stayed that way
// until an operator happened to open the page, which is exactly the failure the
// pool is for.
//
// This CHECKS, it does not rotate. A check probes what is there and marks what
// is failing; rotating MINTS new DNS records against the operator's provider,
// which costs API quota and creates names nobody asked for. Deciding to spend
// that stays an operator action, and the check is what tells them it is time.
func (s *Server) checkRotationPools() {
	if s.db == nil {
		return
	}
	repo, err := dns.NewGormStore(s.db.DB())
	if err != nil {
		return
	}
	names, err := repo.ListPoolNames()
	if err != nil || len(names) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), poolCheckTimeout)
	defer cancel()

	for _, name := range names {
		pool, err := dns.NewPool(dns.PoolConfig{Name: name, Prober: s.poolProber}, repo)
		if err != nil {
			continue
		}
		report, err := pool.Check(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forgepanel: rotation pool %q health check: %v\n", name, err)
			continue
		}
		if len(report.Retired) > 0 {
			fmt.Fprintf(os.Stderr, "forgepanel: rotation pool %q retired %d domain(s): %v\n",
				name, len(report.Retired), report.Retired)
		}
		if len(report.Recovered) > 0 {
			fmt.Fprintf(os.Stderr, "forgepanel: rotation pool %q recovered %d domain(s): %v\n",
				name, len(report.Recovered), report.Recovered)
		}
		// The one that needs an operator: nothing in the pool answers, so
		// whatever it fronts is unreachable and rotating is the only way out.
		if report.Checked > 0 && report.Healthy == 0 {
			fmt.Fprintf(os.Stderr,
				"forgepanel: rotation pool %q has NO healthy domain left (%d checked) — rotate it to mint replacements\n",
				name, report.Checked)
			s.emit(telegram.EventPoolExhausted, name,
				fmt.Sprintf("DNS rotation pool %q has no healthy domain left (%d checked). "+
					"Rotate it to mint replacements.", name, report.Checked))
		}
	}
}

// checkNodesReachable alerts on nodes that have stopped reporting, and announces
// it when they come back.
//
// The health endpoint answers this on demand, which means somebody has to look.
// A node that goes down at 3am stays down until someone thinks to check.
func (s *Server) checkNodesReachable() {
	// NOT `s.notifier == nil`. A panel that configured webhooks and never
	// configured Telegram leaves the notifier nil — that is precisely the
	// operator who bought this feature — and the old guard silently disabled
	// node monitoring for exactly them.
	if s.db == nil || (s.notifier == nil && s.webhooks == nil) {
		return
	}
	nodes, err := s.db.ListNodes()
	if err != nil {
		// Cannot tell up from down, so say nothing. Alerting on a failed read
		// would announce that every node is down whenever the database hiccups.
		return
	}
	cutoff := time.Now().Add(-nodeSilentAfter)
	for _, n := range nodes {
		if !n.Enrolled {
			// Never enrolled: it has no reason to be reporting, and alerting on
			// it would fire forever for a node nobody finished setting up.
			continue
		}
		if n.Disabled {
			// Switched off by the operator. It is silent because they asked it
			// to be, and the heartbeat handler refuses it anyway — paging them
			// once a minute forever for their own decision is how an alert
			// channel stops being read. Resolve rather than skip outright, so a
			// node disabled WHILE it was down clears the alert it had already
			// raised instead of leaving it open with nothing left to close it.
			s.notifier.Resolve(telegram.EventNodeDown, n.Name,
				fmt.Sprintf("*%s* has been disabled by an operator.", n.Name))
			continue
		}
		silent := n.LastSeen == nil || n.LastSeen.Before(cutoff)
		if silent {
			s.emit(telegram.EventNodeDown, n.Name,
				fmt.Sprintf("*%s* has stopped reporting. Its inbounds may be down.", n.Name))
			continue
		}
		// Only announces if it was actually alerted on, so a healthy fleet stays
		// silent instead of announcing a recovery per node per minute.
		s.emitResolve(telegram.EventNodeDown, n.Name,
			fmt.Sprintf("*%s* is reporting again.", n.Name))
	}
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
