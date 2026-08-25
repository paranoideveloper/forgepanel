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
	ns, err := s.db.ListNodes()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ns)
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
	n.Healthy = true
	_ = s.db.SaveNode(n)
	s.accountNodeTraffic(req.Traffic)
	// Return the current xray config bundle so the node runs the same inbounds.
	// A control-plane-only panel has no local engine; the heartbeat still
	// succeeds and simply reports no bundle (spec: heartbeat works in light mode).
	var xrayCfg string
	specs := s.enabledInboundSpecsForNodeAddress(n.Address)
	if b, err := engine.BuildMulti(specs, 10085, "", ""); err == nil && b != nil {
		xrayCfg = string(b.Xray)
	} else if s.engine != nil {
		if b := s.engine.LastBundle(); b != nil {
			xrayCfg = string(b.Xray)
		}
	}
	c.JSON(200, gin.H{"xray_config": xrayCfg})
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

// accountNodeTraffic adds a node's reported per-user deltas to those users and
// enforces their data limit, so traffic served remotely counts exactly like
// traffic the panel served itself.
//
// The node reports deltas keyed by the stats email the panel stamped into the
// config it handed that node (job.UserEmail), which is the same key the local
// poller uses — so both planes converge on one number per user rather than two
// half-counts nobody can reconcile.
//
// Enforcement is applied here as well as in the local poller. A user who blows
// their quota entirely on remote nodes would otherwise stay active until the
// local poller happened to see traffic that, by definition, is not passing
// through the panel.
func (s *Server) accountNodeTraffic(deltas map[string]int64) {
	if s.db == nil || len(deltas) == 0 {
		return
	}
	changed := false
	for email, bytes := range deltas {
		if bytes <= 0 {
			continue
		}
		id, ok := job.UserIDFromEmail(email)
		if !ok {
			continue
		}
		u, err := s.db.UserByID(id)
		if err != nil || u == nil {
			continue
		}
		if math.MaxInt64-bytes < u.UsedTraffic {
			u.UsedTraffic = math.MaxInt64
		} else {
			u.UsedTraffic += bytes
		}
		now := time.Now()
		u.LastSeenAt = &now
		// First use starts an on-hold user's clock, on this plane too. A user
		// whose only traffic is remote must not stay on hold forever just
		// because the panel never served them directly.
		if u.Status == store.StatusOnHold && u.FirstConnectAt == nil {
			first := now
			u.FirstConnectAt = &first
		}
		if u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit && u.Status == store.StatusActive {
			u.Status = store.StatusLimited
			changed = true
		}
		_ = s.db.SaveUser(u)
	}
	// A user who just went over now has to stop being served, on every plane.
	if changed {
		s.startBackground(s.reloadEngines)
	}
}
