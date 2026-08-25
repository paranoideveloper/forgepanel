package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
set -euo pipefail
: "${PANEL:?set PANEL}" ; : "${TOKEN:?set TOKEN}"
# Download the forgenode agent for this platform (placeholder URL — point at your
# release), install a systemd unit, and start it.
echo "forgenode: enrolling with $PANEL"
install -d /etc/forgenode
cat > /etc/systemd/system/forgenode.service <<UNIT
[Unit]
Description=ForgePanel node agent
After=network-online.target
[Service]
Environment=PANEL=$PANEL
Environment=TOKEN=$TOKEN
ExecStart=/usr/local/bin/forgenode
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now forgenode
echo "forgenode: started"
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
