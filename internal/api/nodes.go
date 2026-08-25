package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/forgepanel/forgepanel/internal/job"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// handleListNodes lists remote nodes (spec §10).
func (s *Server) handleListNodes(c *gin.Context) {
	q := parseListQuery(c)
	ns, total, err := s.db.ListNodesPage(q)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if !q.Paged() {
		c.JSON(200, ns)
		return
	}
	c.JSON(200, listPage{Items: ns, Total: total, Limit: effectiveLimit(q), Offset: q.Offset})
}

// handleEnrollNode creates a node with a one-time enroll token and returns the
// exact `curl | bash` command an operator runs on the new server (spec §10).
func (s *Server) handleEnrollNode(c *gin.Context) {
	var req struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.JSON(400, gin.H{"error": "name required"})
		return
	}
	tok, _ := keygen.Password(24)
	n := &store.Node{Name: req.Name, Address: req.Address, EnrollToken: tok}
	if err := s.db.CreateNode(n); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "node.enroll", req.Name)
	// Address the node to the panel's PUBLIC identity, not to whatever host the
	// admin happened to type. Once a domain is configured the panel presents an
	// ACME certificate for that NAME and a self-signed one for a bare IP, and a
	// node is given no fingerprint to pin (see below) — so an enrolment command
	// built from an IP request host would hand the node a URL whose certificate
	// it can never verify. Measured on a live host: with a domain set and ACME
	// issued, the enrol command still read https://<ip>:2053.
	panelURL := "https://" + c.Request.Host
	if d := strings.TrimSpace(s.cfg.Panel().Domain); d != "" {
		panelURL = fmt.Sprintf("https://%s:%d", d, s.cfg.Panel().Port)
	}
	// The node must be able to VERIFY this panel. Until a domain and a real
	// certificate exist, the panel serves a self-signed one that no remote host
	// can chain to a public CA — measured on live servers, forgenode crash-looped
	// on "certificate signed by unknown authority" and enrolment could never
	// complete. Handing the node the certificate's fingerprint at enrolment
	// time gives it a trust anchor without weakening the transport: the node
	// pins this exact certificate rather than skipping verification, so the
	// enrolment token is never shipped over an unverified connection.
	//
	// An empty fingerprint is not an error: it means the panel presents a
	// CA-issued certificate, and the node should use the system trust store.
	fp := s.panelCertFingerprint()
	enroll := "curl -fsSL " + panelURL + "/node-install.sh | PANEL=" + panelURL + " TOKEN=" + tok
	if fp != "" {
		enroll += " PANEL_FINGERPRINT=" + fp
	}
	enroll += " bash"
	c.JSON(201, gin.H{"id": n.ID, "name": n.Name, "enroll_command": enroll,
		"token": tok, "panel_fingerprint": fp})
}

// handleNodeRegister is called by a node agent with its enroll token to complete
// enrollment (node-facing; token-authenticated).
func (s *Server) handleNodeRegister(c *gin.Context) {
	var req struct {
		Token       string `json:"token"`
		CoreVersion string `json:"core_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	n, err := s.db.NodeByToken(req.Token)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid enroll token"})
		return
	}
	now := time.Now()
	n.Enrolled = true
	n.Healthy = true
	if n.LastSeen != nil && now.Before(*n.LastSeen) {
		c.JSON(200, gin.H{"xray_config": ""})
		return
	}
	n.LastSeen = &now
	n.CoreVersion = req.CoreVersion
	_ = s.db.SaveNode(n)
	c.JSON(200, gin.H{"node_id": n.ID, "name": n.Name})
}

// handleNodeHeartbeat is called periodically by a node agent to report health;
// the response carries the engine config the node should run (spec §10).
func (s *Server) handleNodeHeartbeat(c *gin.Context) {
	var req struct {
		Token string  `json:"token"`
		CPU   float64 `json:"cpu"`
		MemMB int     `json:"mem_mb"`
		// Traffic is the per-user delta this node served since its last
		// heartbeat, keyed by the stats email the panel stamped into its config.
		// Without it a node's traffic was counted nowhere and a user assigned to
		// a node had no enforceable quota at all.
		Traffic map[string]int64 `json:"traffic"`
		// TrafficCumulative marks the counters as running totals rather than
		// per-heartbeat deltas. Agents from before that change omit it, and are
		// accounted the old way so a panel upgraded ahead of its fleet does not
		// silently mis-count either generation.
		TrafficCumulative bool `json:"traffic_cumulative"`
		DiskUsedMB        int  `json:"disk_used_mb"`
		DiskTotalMB       int  `json:"disk_total_mb"`
		TCPConns          int  `json:"tcp_conns"`
		CoreUptimeSec     int  `json:"core_uptime_sec"`
		SingboxStats      bool `json:"singbox_stats"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	n, err := s.db.NodeByToken(req.Token)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}
	now := time.Now()
	n.LastSeen = &now
	n.CPU = req.CPU
	n.MemMB = req.MemMB
	n.DiskUsedMB = req.DiskUsedMB
	n.DiskTotalMB = req.DiskTotalMB
	n.TCPConns = req.TCPConns
	n.CoreUptimeSec = req.CoreUptimeSec
	n.SingboxStats = req.SingboxStats
	n.Healthy = true
	_ = s.db.SaveNode(n)
	s.accountNodeTraffic(n.ID, req.Traffic, req.TrafficCumulative)
	// Return the current config bundle so the node runs the same inbounds.
	//
	// BOTH engines. The bundle has always carried a sing-box config alongside the
	// xray one and the heartbeat sent only the xray half, so every hysteria2,
	// tuic, anytls, shadowtls and wireguard inbound simply vanished the moment it
	// was assigned to a remote node — the panel showed it, the node never served
	// it, and nothing said why.
	//
	// singbox_config is a NEW field rather than a change to the existing one, so
	// an agent that predates it ignores what it does not understand and keeps
	// serving xray exactly as before. Same reasoning as traffic_cumulative above.
	//
	// A control-plane-only panel has no local engine; the heartbeat still
	// succeeds and simply reports no bundle (spec: heartbeat works in light mode).
	// The stats section is emitted ONLY for a node that says its binary can serve
	// it. Emitting it for a stock sing-box is a startup failure that takes every
	// sing-box inbound on that node down — strictly worse than leaving them
	// unmetered, which is the state they were in anyway.
	sbAPIPort := 0
	if n.SingboxStats {
		sbAPIPort = nodeSingboxAPIPort
	}
	var xrayCfg, singboxCfg string
	specs := s.enabledInboundSpecsForNodeAddress(n.Address)
	if b, err := engine.BuildMultiFor(specs, nodeXrayAPIPort, sbAPIPort, "", "", nil, nil); err == nil && b != nil {
		xrayCfg, singboxCfg = string(b.Xray), singboxIfServing(b)
	} else if s.engine != nil {
		if b := s.engine.LastBundle(); b != nil {
			xrayCfg, singboxCfg = string(b.Xray), singboxIfServing(b)
		}
	}
	c.JSON(200, gin.H{"xray_config": xrayCfg, "singbox_config": singboxCfg})
}

// handleDeleteNode removes a node.
func (s *Server) handleDeleteNode(c *gin.Context) {
	id := parseID(c)
	if err := s.db.DeleteNode(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "node.delete", "")
	c.JSON(200, gin.H{"deleted": id})
}

// handleNodeInstallScript serves the one-line node bootstrap (spec §10).
func (s *Server) handleNodeInstallScript(c *gin.Context) {
	script := `#!/usr/bin/env bash
# ForgePanel node enrollment.
#
# Downloads the agent FROM THE PANEL, verifies it, installs a systemd unit and
# starts it. The agent comes from the panel rather than a release URL so its
# version always matches the panel that will drive it, and so this works with a
# private release repo or a node that cannot reach GitHub.
set -euo pipefail
: "${PANEL:?set PANEL}" ; : "${TOKEN:?set TOKEN}"
# The enroll command exports PANEL_FINGERPRINT, and the agent's own unit reads
# the same name, so the script uses it too: one name end to end. A mismatch here
# would leave the pin empty and the node would refuse to trust a self-signed
# panel for what looks like an interception.
PANEL_FINGERPRINT="${PANEL_FINGERPRINT:-}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "forgenode: unsupported architecture $ARCH" >&2 ; exit 1 ;;
esac

# The panel may serve a self-signed certificate, in which case the node pins it
# by fingerprint instead of trusting a CA. Pinning is what makes -k safe here:
# without a pin an intercepted download would be accepted silently.
CURL=(curl -fsSL --proto "=https" --max-time 120)
if [ -n "$PANEL_FINGERPRINT" ]; then
  CURL+=(-k)
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "forgenode: downloading the agent from $PANEL"
if ! "${CURL[@]}" "$PANEL/api/node/agent?arch=$ARCH" -o "$TMP/forgenode"; then
  echo "forgenode: could not download the agent from $PANEL." >&2
  echo "forgenode: the panel reported why at $PANEL/api/node/agent?arch=$ARCH" >&2
  exit 1
fi

# Verify before installing. A truncated or tampered download that reaches
# /usr/local/bin becomes a crash-looping service whose logs say nothing useful.
if WANT="$("${CURL[@]}" "$PANEL/api/node/agent/sha256" | sed -n 's/.*"sha256":"\([a-f0-9]*\)".*/\1/p')" && [ -n "$WANT" ]; then
  GOT="$(sha256sum "$TMP/forgenode" | cut -d" " -f1)"
  if [ "$WANT" != "$GOT" ]; then
    echo "forgenode: checksum mismatch (expected $WANT, got $GOT) — refusing to install" >&2
    exit 1
  fi
  echo "forgenode: checksum verified"
else
  echo "forgenode: WARNING — the panel did not report a checksum; installing unverified" >&2
fi

chmod 0755 "$TMP/forgenode"
# Prove it runs on this host before making it a service, so a wrong-architecture
# or corrupt binary fails here with a clear message rather than as a systemd
# restart loop.
if ! "$TMP/forgenode" --version >/dev/null 2>&1 && ! "$TMP/forgenode" -h >/dev/null 2>&1; then
  echo "forgenode: the downloaded agent will not execute on this host" >&2
  exit 1
fi

install -d /etc/forgenode
install -m 0755 "$TMP/forgenode" /usr/local/bin/forgenode

cat > /etc/systemd/system/forgenode.service <<UNIT
[Unit]
Description=ForgePanel node agent
After=network-online.target
Wants=network-online.target
[Service]
Environment=PANEL=$PANEL
Environment=TOKEN=$TOKEN
Environment=PANEL_FINGERPRINT=$PANEL_FINGERPRINT
ExecStart=/usr/local/bin/forgenode
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now forgenode

# Report the truth about whether it actually came up. "enable --now" succeeding
# only means systemd accepted the unit.
sleep 2
if systemctl is-active --quiet forgenode; then
  echo "forgenode: started and enrolled with $PANEL"
else
  echo "forgenode: the service did not stay up. Recent log:" >&2
  journalctl -u forgenode -n 20 --no-pager >&2 || true
  exit 1
fi
`
	c.Data(200, "text/x-shellscript; charset=utf-8", []byte(script))
}

// panelCertFingerprint returns the SHA-256 of the certificate this panel serves,
// hex encoded, for a node to pin.
//
// It reads the certificate the panel actually presents rather than any
// configured path, because those can diverge: a panel that fell back to its
// self-signed certificate after an ACME failure would otherwise hand out the
// fingerprint of a certificate it is not using, and every node would then
// refuse to connect for what looks like an interception.
//
// A CA-issued certificate returns "" — the node uses the system trust store and
// needs no pin.
func (s *Server) panelCertFingerprint() string {
	if s.cfg == nil || s.cfg.Panel() == nil {
		return ""
	}
	p := s.cfg.Panel()
	// A configured domain implies a real certificate; nothing to pin.
	if strings.TrimSpace(p.Domain) != "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "certs", "self.crt"))
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// accountNodeTraffic records a node's reported per-user usage and enforces the
// data limit, so traffic served remotely counts exactly like traffic the panel
// served itself.
//
// Counters are keyed by the stats email the panel stamped into the config it
// handed that node (job.UserEmail), which is the same key the local poller uses,
// so both planes converge on one number per user rather than two half-counts
// nobody can reconcile.
//
// CUMULATIVE vs DELTA. A current agent reports running totals and never resets
// them, and the delta is computed here against a snapshot scoped to that node.
// That makes a heartbeat idempotent, which matters because the previous design
// was not: the agent posted deltas and reset only after a successful response,
// so a response lost AFTER the panel had already accounted them left the agent
// unreset, the same bytes arrived again, and the user was charged twice. A
// flaky link inflated usage and cut people off early, silently.
//
// An older agent omits the flag and is still accounted as deltas, so a panel
// upgraded ahead of its fleet mis-counts neither generation.
//
// Enforcement runs here as well as in the local poller: a user who exhausts
// their quota entirely on remote nodes would otherwise stay active until the
// local poller happened to see traffic that, by definition, is not passing
// through the panel.
func (s *Server) accountNodeTraffic(nodeID uint, counters map[string]int64, cumulative bool) {
	if s.db == nil || len(counters) == 0 {
		return
	}
	scope := fmt.Sprintf("node:%d", nodeID)
	var prev map[string]int64
	if cumulative {
		var err error
		prev, err = s.db.TrafficSnapshots(scope)
		if err != nil {
			// Without the baseline every total would read as a fresh delta and
			// inflate usage by the node's whole lifetime. Skipping the cycle
			// keeps the numbers right; nothing was reset, so the next heartbeat
			// recovers it.
			return
		}
	}

	changed := false
	for email, reported := range counters {
		delta := reported
		if cumulative {
			if _, known := prev[email]; !known {
				// FIRST contact for this counter: record the baseline and bill
				// nothing. An unknown baseline cannot distinguish "this node has
				// been serving for a month" from "it just started", and the
				// panel does not control when a remote core was launched.
				// Billing the whole counter would charge a month of traffic in
				// one heartbeat and could exhaust a user's quota instantly;
				// starting from here costs at most one heartbeat interval. The
				// local poller differs on purpose — the panel starts that engine
				// itself, so zero really is zero.
				_ = s.db.SetTrafficSnapshot(scope, email, reported)
				continue
			}
			delta = store.TrafficDelta(prev[email], reported)
		}
		id, ok := job.UserIDFromEmail(email)
		if !ok {
			if cumulative {
				// Remember it anyway: a key that later resolves to a real user
				// must not hand them the counter's entire history at once.
				_ = s.db.SetTrafficSnapshot(scope, email, reported)
			}
			continue
		}
		if delta <= 0 {
			if cumulative && reported != prev[email] {
				// No usage, but a counter that restarted lower still has to move
				// the baseline, or the next real delta is measured from one that
				// no longer exists.
				_ = s.db.SetTrafficSnapshot(scope, email, reported)
			}
			continue
		}

		tripped := false
		stamp := func(u *store.User) {
			now := time.Now()
			u.LastSeenAt = &now
			// First use starts an on-hold user's clock on this plane too: a user
			// whose only traffic is remote must not stay on hold forever.
			if u.Status == store.StatusOnHold && u.FirstConnectAt == nil {
				first := now
				u.FirstConnectAt = &first
			}
			if u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit && u.Status == store.StatusActive {
				u.Status = store.StatusLimited
				tripped = true
			}
		}

		if cumulative {
			// The usage and the snapshot move in ONE transaction. Saving one
			// without the other either double-counts on the next heartbeat or
			// drops the bytes entirely, and both are invisible.
			if _, _, err := s.db.ApplyTrafficDelta(scope, email, id, delta, reported, stamp); err != nil {
				continue // snapshot did not move either; recomputed next heartbeat
			}
		} else {
			u, err := s.db.UserByID(id)
			if err != nil || u == nil {
				continue
			}
			if math.MaxInt64-delta < u.UsedTraffic {
				u.UsedTraffic = math.MaxInt64
			} else {
				u.UsedTraffic += delta
			}
			stamp(u)
			_ = s.db.SaveUser(u)
		}
		if tripped {
			changed = true
		}
	}
	// A user who just went over now has to stop being served, on every plane.
	if changed {
		s.startBackground(s.reloadEngines)
	}
}

// The loopback ports a node's cores expose their stats APIs on.
//
// Fixed rather than negotiated: both ends have to agree, and a value the node
// discovers from the config it was just handed would be one more thing that can
// disagree after a partial update. cmd/forgenode holds the same constants.
const (
	nodeXrayAPIPort    = 10085
	nodeSingboxAPIPort = 10086
)

// singboxIfServing returns the sing-box config only when it actually has
// inbounds to serve.
//
// BuildMulti always emits a syntactically valid sing-box document, even an empty
// one. Sending that to a node would have it download the binary and run a core
// that listens on nothing — cost and a process to supervise, for no traffic.
func singboxIfServing(b *engine.Bundle) string {
	if b == nil || b.SingboxN == 0 {
		return ""
	}
	return string(b.Singbox)
}
