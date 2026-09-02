package api

// The Overview, as an operational dashboard.
//
// It used to return five fields: status, version, node counts and the panel's
// own uptime. Nothing about the machine, nothing about who or what the panel is
// actually serving. An administrator checking whether the server was healthy had
// to leave the panel and open a shell — the one thing a control panel exists to
// avoid.
//
// What is here is what an operator ACTS on, and every figure is read rather than
// estimated. Two deliberate omissions: there is no "connections per second" and
// no synthetic health score. The first needs sampling this endpoint does not do,
// and the second is a number that looks authoritative and means nothing.

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/sysinfo"
	"github.com/forgepanel/forgepanel/internal/version"
)

// netSample remembers the previous interface counters so a RATE can be derived.
//
// Cumulative counters alone cannot answer "how fast is traffic flowing now",
// which is the question an operator is actually asking. Two readings and the
// clock between them can.
type netSample struct {
	mu   sync.Mutex
	prev sysinfo.Network
	at   time.Time
}

var dashNet netSample

// sampleNetwork returns the current counters and the rate since the last call.
func sampleNetwork() (cur sysinfo.Network, rxPerSec, txPerSec float64) {
	cur = sysinfo.ReadNetwork()
	now := time.Now()

	dashNet.mu.Lock()
	defer dashNet.mu.Unlock()
	if !dashNet.at.IsZero() {
		rxPerSec, txPerSec = sysinfo.Rate(dashNet.prev, cur, now.Sub(dashNet.at))
	}
	dashNet.prev, dashNet.at = cur, now
	return cur, rxPerSec, txPerSec
}

// accountTotals is the who of the panel.
type accountTotals struct {
	Users     int64 `json:"users"`
	Active    int64 `json:"active"`
	Disabled  int64 `json:"disabled"`
	Expired   int64 `json:"expired"`
	Online    int64 `json:"online"`
	Admins    int64 `json:"admins"`
	Owners    int64 `json:"owners"`
	Resellers int64 `json:"resellers"`
	Viewers   int64 `json:"viewers"`
}

// inboundTotals is the what.
type inboundTotals struct {
	Total    int64            `json:"total"`
	Enabled  int64            `json:"enabled"`
	Disabled int64            `json:"disabled"`
	// NotServing counts inbounds the panel accepted and is NOT serving — the
	// state that used to be invisible. An operator seeing 12 inbounds and 11
	// listeners needs the 1 named, not hidden in a total.
	NotServing int64            `json:"not_serving"`
	ByProtocol map[string]int64 `json:"by_protocol"`
}

// handleDashboard is the Overview's data.
func (s *Server) handleDashboard(c *gin.Context) {
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	sys := sysinfo.Read(dataDir)
	netNow, rxRate, txRate := sampleNetwork()
	sys.Network = netNow

	acc, inb, warnings := s.dashboardCounts()

	online, totalNodes := 0, 0
	cutoff := time.Now().Add(-3 * time.Minute)
	if nodes, err := s.db.ListNodes(); err == nil {
		totalNodes = len(nodes)
		for _, n := range nodes {
			if n.Enrolled && n.LastSeen != nil && n.LastSeen.After(cutoff) {
				online++
			}
		}
	}

	pa := s.paas()
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"version": version.Get().Version,
		"panel": gin.H{
			"uptime_seconds": int64(time.Since(processStart).Seconds()),
			"public_address": s.knobs().String("public_address"),
			"deployment":     s.deploySurface(),
		},
		"system": sys,
		"traffic": gin.H{
			// Cumulative since boot, and the live rate between the last two
			// polls. Both, because "how much" and "how fast" are different
			// questions and a dashboard that answers only one gets used wrong.
			"rx_bytes":       netNow.RxBytes,
			"tx_bytes":       netNow.TxBytes,
			"rx_bytes_per_s": rxRate,
			"tx_bytes_per_s": txRate,
		},
		"accounts": acc,
		"inbounds": inb,
		"nodes":    gin.H{"online": online, "total": totalNodes},
		"paas":     pa.Enabled,
		// Things worth an operator's attention right now, already computed
		// rather than left for the UI to infer from thresholds it would have to
		// invent.
		"warnings": warnings,
	})
}

// dashboardCounts walks users, admins and inbounds once each.
func (s *Server) dashboardCounts() (accountTotals, inboundTotals, []string) {
	var acc accountTotals
	inb := inboundTotals{ByProtocol: map[string]int64{}}
	var warnings []string

	if s.db == nil {
		return acc, inb, warnings
	}

	// ownerID 0 means "every user", not "users owned by nobody" — a reseller's
	// users must be counted too or the panel under-reports its own load.
	if users, err := s.db.ListUsers(0); err == nil {
		online := time.Now().Add(-2 * time.Minute)
		for _, u := range users {
			acc.Users++
			switch u.Status {
			case store.StatusActive:
				acc.Active++
			case store.StatusDisabled:
				acc.Disabled++
			case store.StatusExpired:
				acc.Expired++
			}
			if u.LastSeenAt != nil && u.LastSeenAt.After(online) {
				acc.Online++
			}
		}
	}

	if admins, err := s.db.ListAdmins(); err == nil {
		for _, a := range admins {
			switch a.Role {
			case store.RoleOwner:
				acc.Owners++
			case store.RoleAdmin:
				acc.Admins++
			case store.RoleReseller:
				acc.Resellers++
			case store.RoleViewer:
				acc.Viewers++
			}
		}
	}

	if ins, err := s.db.ListInbounds(); err == nil {
		var notServing []string
		for _, in := range ins {
			inb.Total++
			if in.Enabled {
				inb.Enabled++
			} else {
				inb.Disabled++
			}
			inb.ByProtocol[strings.ToLower(in.Protocol)]++
			if strings.TrimSpace(in.NotServingReason) != "" {
				inb.NotServing++
				name := in.Remark
				if name == "" {
					name = in.Protocol
				}
				notServing = append(notServing, name+": "+in.NotServingReason)
			}
		}
		sort.Strings(notServing)
		warnings = append(warnings, notServing...)
	}
	return acc, inb, warnings
}
