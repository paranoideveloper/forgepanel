package api

import (
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
	panelURL := "https://" + c.Request.Host
	enroll := "curl -fsSL " + panelURL + "/node-install.sh | PANEL=" + panelURL + " TOKEN=" + tok + " bash"
	c.JSON(201, gin.H{"id": n.ID, "name": n.Name, "enroll_command": enroll, "token": tok})
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
