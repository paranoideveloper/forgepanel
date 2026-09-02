package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/forgepanel/forgepanel/internal/job"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// nodeStatus derives a node's lifecycle state and the reason for it.
//
// Healthy is one bit and the Nodes table needed four states. Before this, a
// node mid-install, a node that had died, a node whose core was refusing every
// config it was sent, and a node an operator had deliberately switched off all
// rendered the same "Stale" badge — so the page reported four emergencies where
// there was one, and the operator had to go to the server to find out which.
//
// DERIVED, not read back from the column. Node.Status is stored so the last
// thing a node said survives a restart, but a state written only at heartbeat
// time is a state that stays "connected" forever for a node that has stopped
// heartbeating — which is precisely how Healthy came to mean nothing (see
// handleListNodes). The stored value is the input; this is the answer.
//
// The silence cutoff is deliberately nodeSilentAfter, the one /metrics, the
// overview counter and the health page already use, so every place the panel
// talks about a node agrees with the others.
func nodeStatus(n *store.Node) (store.NodeStatus, string) {
	if n == nil {
		return store.NodeError, ""
	}
	// Deliberate beats everything. A node the operator turned off is not an
	// error and must not read as one, however long it has been quiet — being
	// quiet is what was asked of it.
	if n.Disabled {
		return store.NodeDisabled, ""
	}
	// Enrolled-but-never-heard-from is an install in progress. Calling it an
	// error is what made the table unreadable during a fleet rollout, and it is
	// also what would page an operator at 3am for a node they created at 2:59.
	if !n.Enrolled || n.LastSeen == nil {
		return store.NodeConnecting, ""
	}
	// StatusMessage holds the last failure the NODE reported about itself, which
	// is the only way the panel learns that a node whose agent is perfectly
	// healthy is running a core that refuses to start.
	last := strings.TrimSpace(n.StatusMessage)
	if age := time.Since(*n.LastSeen); age >= nodeSilentAfter {
		msg := fmt.Sprintf("no heartbeat for %s", age.Truncate(time.Second))
		if last != "" {
			// The cause usually predates the silence: a core that will not start
			// is why the box went away. Dropping it would leave the operator
			// with "it is gone" and nothing to act on.
			msg += "; last reported: " + last
		}
		return store.NodeError, msg
	}
	if last != "" {
		return store.NodeError, last
	}
	return store.NodeConnected, ""
}

// handleListNodes lists remote nodes (spec §10).
func (s *Server) handleListNodes(c *gin.Context) {
	q := parseListQuery(c)
	ns, total, err := s.db.ListNodesPage(q)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	// Node.Healthy is only ever WRITTEN true — on register and on every
	// heartbeat — and nothing in this tree ever writes it false. Served as
	// stored it means "this node checked in at least once", not "this node is
	// up", which made the Online badge decorative: a node that died an hour ago
	// still read Online while the last_seen column beside it said "1h ago".
	// Derive it from the heartbeat age instead, using the same nodeSilentAfter
	// cutoff /metrics, the overview counter and the health page already use, so
	// every place the panel talks about a node agrees with the others.
	//
	// Status is derived in the same loop and for the same reason, and Healthy is
	// then defined as "status is connected" rather than computed separately: two
	// fields on one row that answer the same question from different inputs will
	// eventually disagree, and the operator has no way to tell which one lied.
	for i := range ns {
		st, msg := nodeStatus(&ns[i])
		ns[i].Status, ns[i].StatusMessage = st, msg
		ns[i].Healthy = st == store.NodeConnected
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
		fail(c, 400, "name required")
		return
	}
	tok, _ := keygen.Password(24)
	// The bootstrap token is separate from the legacy enrol token, hashed at
	// rest, and expires. It buys ONE client certificate and is then spent — an
	// enrolment command that still works after the node has enrolled is a
	// permanent credential again, just with extra steps.
	bootstrap, _ := keygen.Password(32)
	expires := time.Now().Add(BootstrapTTL)
	n := &store.Node{
		Name: req.Name, Address: req.Address, EnrollToken: tok,
		BootstrapHash: hashBootstrap(bootstrap), BootstrapExpires: &expires,
	}
	if err := s.db.CreateNode(n); err != nil {
		failErr(c, 500, err)
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
	// The fetch of the install script has to survive the same self-signed
	// certificate the script itself is being told to pin. -k alone would fetch
	// the pinning logic over an unverified connection, so the peer is pinned by
	// public key here too.
	fetch := "curl -fsSL"
	if pin := s.panelCertPubkeyPin(); pin != "" {
		fetch += " -k --pinnedpubkey sha256//" + pin
	}
	enroll := fetch + " " + panelURL + "/node-install.sh | PANEL=" + panelURL +
		" BOOTSTRAP=" + bootstrap + " TOKEN=" + tok
	if fp != "" {
		enroll += " PANEL_FINGERPRINT=" + fp
	}
	enroll += " bash"
	c.JSON(201, gin.H{"id": n.ID, "name": n.Name, "enroll_command": enroll,
		"token": tok, "bootstrap": bootstrap,
		"bootstrap_expires": expires, "panel_fingerprint": fp})
}

// handleNodeRegister is called by a node agent with its enroll token to complete
// enrollment (node-facing; token-authenticated).
func (s *Server) handleNodeRegister(c *gin.Context) {
	var req struct {
		Token       string `json:"token"`
		CoreVersion string `json:"core_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	// mTLS first, then the legacy token. The order matters: a node that holds a
	// certificate must be judged on it, so revoking that certificate actually
	// stops the node even while its old token row still exists.
	n, err := s.authenticateNode(c, req.Token)
	if err != nil {
		failErr(c, 401, err)
		return
	}
	// A disabled node is refused at the door, exactly as at heartbeat: an agent
	// that has been restarted re-registers before it heartbeats, and letting it
	// through here would mark a node the operator switched off as enrolled and
	// reporting again.
	if n.Disabled {
		fail(c, 403, "node is disabled")
		return
	}
	now := time.Now()
	n.Enrolled = true
	if n.LastSeen != nil && now.Before(*n.LastSeen) {
		c.JSON(200, gin.H{"xray_config": ""})
		return
	}
	n.LastSeen = &now
	n.CoreVersion = req.CoreVersion
	// Registering is a fresh start: whatever failure the node last reported
	// belonged to the process that has just been replaced.
	n.StatusMessage = ""
	n.Status, _ = nodeStatus(n)
	n.Healthy = n.Status == store.NodeConnected
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
		// DataDir is where the node keeps its state, so the config built for it
		// can name a certificate path that exists on that machine. Empty from an
		// older agent, and from anything that is not the shipped agent, so it
		// falls back to the installer's default rather than failing.
		DataDir      string `json:"data_dir"`
		SingboxStats bool   `json:"singbox_stats"`
		// LastError is the node's own verdict on itself: the most recent thing
		// one of its cores said before it stopped serving. A node whose agent is
		// perfectly healthy can be running an xray that refuses every config it
		// is handed, and without this the panel calls that node "connected"
		// forever — which is how a node stayed green in the UI for hours while
		// serving nobody. Empty from an older agent, which simply reports no
		// fault rather than being called faulty.
		LastError string `json:"last_error"`
		// Logs are the lines that node's cores have written since the sequence
		// number the panel last acknowledged, and LogSeq is where they start.
		//
		// They ride the heartbeat because the agent is strictly pull: it polls
		// the panel and the panel can never open a connection to it (a node is
		// commonly behind NAT and always behind its own firewall). See nodelogs.go.
		Logs   []string `json:"logs"`
		LogSeq int      `json:"log_seq"`
		// LogEpoch identifies the agent PROCESS those numbers belong to. Without
		// it a restarted agent — whose sequence starts at zero again — is
		// indistinguishable from one re-sending its first batch, and the panel
		// has to choose between losing every line after a restart and
		// duplicating lines on every dropped response.
		LogEpoch string `json:"log_epoch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	n, err := s.authenticateNode(c, req.Token)
	if err != nil {
		fail(c, 401, "invalid token")
		return
	}
	// THE REFUSAL IS THE FEATURE. A Disabled flag the heartbeat does not consult
	// is a decorative column: the node keeps checking in, keeps being handed the
	// full config bundle below, and keeps serving traffic while the panel tells
	// the operator it is switched off. ConfigDirty on this same model is the
	// warning from history — declared, migrated, serialised, typed in the
	// frontend and rendered as a badge, and written by nothing in the tree.
	//
	// Refused BEFORE last_seen is touched, so a disabled node also stops looking
	// alive, and long before the bundle is built, so it is handed no credentials
	// and no inbounds to serve.
	if n.Disabled {
		fail(c, 403, "node is disabled")
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
	// What the node says about itself, kept verbatim so the operator reads the
	// core's own words rather than a category. Trimmed to a sane length: this is
	// a badge tooltip, and an agent shipping a stack trace should not turn every
	// node list into a page of it.
	n.StatusMessage = clipStatusMessage(req.LastError)
	// Derived through the same function the list endpoint uses, so the stored
	// state and the served state cannot drift apart. Healthy stays in step with
	// it for the same reason.
	n.Status, _ = nodeStatus(n)
	n.Healthy = n.Status == store.NodeConnected
	_ = s.db.SaveNode(n)
	s.logs.publish(n.ID, req.LogEpoch, req.LogSeq, req.Logs)
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
	// ROUTING GOES TO THE NODE TOO. This call passed nil, nil for the operator's
	// outbounds and rules, so the panel's own box enforced the routing table and
	// every remote node enforced none of it: a saved "block private networks"
	// preset protected the panel host's metadata endpoint and left the whole
	// fleet's wide open, with nothing in the UI to say the rules stopped at the
	// panel. The rules are scoped to the inbounds this node actually serves —
	// see nodeRoutingSpecs.
	outs, rules, groups := s.nodeRoutingSpecs(specs)
	// THE NODE NEEDS A SERVER CERTIFICATE. These two arguments were "" and "",
	// so every TLS-terminating inbound assigned to a node was built with no
	// certificate and refused by the core on that node:
	//
	//	FATAL initialize inbound[0]: missing certificate
	//
	// which is every hysteria2, TUIC, AnyTLS and ShadowTLS inbound — the whole
	// sing-box protocol family — plus any TLS xray inbound. They were accepted
	// by the panel, shown in the UI, delivered to the node, and rejected there
	// every ten seconds forever. Measured on a real node, not inferred.
	//
	// The paths are on the NODE's filesystem; the agent materialises the
	// certificate at exactly this location before it applies any config.
	certPath, keyPath := nodeCertPaths(req.DataDir)
	b, err := engine.BuildMultiFor(specs, nodeXrayAPIPort, sbAPIPort, certPath, keyPath, outs, rules, groups)
	if err != nil {
		// A routing table that renders for the panel can still be refused for a
		// node: RenderRules rejects a rule whose outbound tag the node's own
		// config does not define, and a relay-chain egress tag exists only
		// where its inbound does. Retry unrouted rather than let the build
		// fail — a node with no operator rules still serves its own inbounds,
		// while the LastBundle fallback below would hand it the PANEL's config,
		// whose inbounds belong to a different machine.
		b, err = engine.BuildMultiFor(specs, nodeXrayAPIPort, sbAPIPort, certPath, keyPath, nil, nil, nil)
	}
	if err == nil && b != nil {
		xrayCfg, singboxCfg = string(b.Xray), singboxIfServing(b)
	} else if s.engine != nil {
		if b := s.engine.LastBundle(); b != nil {
			xrayCfg, singboxCfg = string(b.Xray), singboxIfServing(b)
		}
	}
	c.JSON(200, gin.H{"xray_config": xrayCfg, "singbox_config": singboxCfg,
		// PORT HOPPING HAS TO REACH THE NODE TOO. A hysteria2 hop range is two
		// things: a hint in the client's link, and firewall redirects that send
		// the whole range at the listening port. The panel installed the
		// redirects for its OWN inbounds and nothing installed them on a node —
		// so an inbound assigned to a node handed clients a link advertising
		// mport=30000-30100 and redirected none of those ports. The tunnel worked
		// until the client hopped and then broke, which is worse than not
		// offering the feature.
		"port_hops": nodePortHops(specs)})
}

// nodeRoutingSpecs is routingSpecs narrowed to what can apply on one node.
//
// Outbounds are passed through whole: a rule may name any of them, and an
// outbound the config defines but no rule uses costs nothing. Rules are
// filtered, because a rule scoped to inbound tags names inbounds by the tag the
// panel stamps into the config, and a node only receives the inbounds bound to
// its address. Shipping a rule whose inbounds all live elsewhere puts a
// condition in the node's config that can never match and hands the operator a
// node config that does not resemble the routing table they wrote.
//
// A rule with no inbound scope is fleet-wide by definition and always goes.
func (s *Server) nodeRoutingSpecs(specs []engine.InboundSpec) ([]engine.OutboundSpec, []engine.RuleSpec, []engine.GroupSpec) {
	outs, rules, groups := s.routingSpecs()
	if len(rules) == 0 {
		// No rules can apply here, so no outbound and no group is needed here
		// either — a balancer nothing selects changes nothing about what the
		// node does, while its members' credentials would still have to travel
		// to the node to make the config render. See keepReferencedOutbounds.
		return nil, nil, nil
	}
	// Mirror the tag BuildMultiFor will assign, or a rule written against an
	// inbound the operator never named would be dropped for the wrong reason.
	onNode := map[string]bool{}
	for _, sp := range specs {
		if sp.Node == nil {
			continue
		}
		if sp.Node.Tag != "" {
			onNode[sp.Node.Tag] = true
			continue
		}
		onNode[fmt.Sprintf("in-%d", sp.Node.Port)] = true
	}
	kept := make([]engine.RuleSpec, 0, len(rules))
	for _, r := range rules {
		if len(r.InboundTags) == 0 {
			kept = append(kept, r)
			continue
		}
		scoped := make([]string, 0, len(r.InboundTags))
		for _, t := range r.InboundTags {
			if onNode[t] {
				scoped = append(scoped, t)
			}
		}
		if len(scoped) == 0 {
			continue
		}
		// Narrow the rule to the tags that exist here rather than passing the
		// operator's full list: the surplus tags are inert but they are also a
		// list of inbound names from other nodes, sitting in a config file on a
		// machine that has no business knowing them.
		r.InboundTags = scoped
		kept = append(kept, r)
	}
	if len(kept) == 0 {
		return nil, nil, nil
	}
	keptGroups := keepReferencedGroups(groups, kept)
	return keepReferencedOutbounds(outs, kept, keptGroups), kept, keptGroups
}

// keepReferencedGroups returns only the failover groups the kept rules target.
//
// Same reasoning as keepReferencedOutbounds, one step further out: a group is a
// list of relay tags whose OUTBOUNDS have to be shipped with it, credentials and
// all. A group no surviving rule can select cannot change what this node does,
// so sending it is pure exposure — and it would drag every member's password
// onto a machine with no use for any of them.
func keepReferencedGroups(groups []engine.GroupSpec, rules []engine.RuleSpec) []engine.GroupSpec {
	need := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.OutboundTag != "" {
			need[r.OutboundTag] = true
		}
	}
	kept := make([]engine.GroupSpec, 0, len(groups))
	for _, g := range groups {
		if need[g.Tag] {
			kept = append(kept, g)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// keepReferencedOutbounds returns only the outbounds the kept rules name.
//
// An operator outbound is a full proxy definition: a Trojan relay carries its
// password, a SOCKS hop its username and password. Shipping the whole set to
// every node meant a node with one inbound and no applicable rules received the
// credentials for every relay the operator had ever configured — on a machine
// that has no use for them, in a config file on disk, for the lifetime of the
// enrolment. Nodes previously received NO outbounds at all, so sending them
// all was a strictly new exposure introduced by making routing reach nodes.
//
// The filter is by rule reference rather than by "is it valid here", because
// that is the property that makes an outbound necessary: an outbound no
// surviving rule can select cannot change what the node does.
func keepReferencedOutbounds(outs []engine.OutboundSpec, rules []engine.RuleSpec, groups []engine.GroupSpec) []engine.OutboundSpec {
	need := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.OutboundTag != "" {
			need[r.OutboundTag] = true
		}
	}
	// A rule that targets a group names the GROUP, not an exit. Its members and
	// its all-down policy have to travel too, or the node receives a balancer
	// selecting tags its own config does not define — which the core accepts
	// and then sends that rule's traffic out DIRECT, from the node's own
	// address, past the relays the group exists to hide behind.
	for _, g := range groups {
		for _, m := range g.Members {
			need[m] = true
		}
		if g.FallbackTag != "" {
			need[g.FallbackTag] = true
		}
	}
	if len(need) == 0 {
		return nil
	}
	kept := make([]engine.OutboundSpec, 0, len(need))
	for _, o := range outs {
		if need[o.Tag] {
			kept = append(kept, o)
		}
	}
	return kept
}

// nodeStatusMessageMax bounds what a node can make the panel store and render
// for itself. The field is a badge tooltip; an agent shipping a stack trace or a
// core looping on a long error would otherwise turn the Nodes list into a wall
// of it, and put an unbounded string from a remote machine in the database.
const nodeStatusMessageMax = 400

func clipStatusMessage(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= nodeStatusMessageMax {
		return s
	}
	// Cut on a rune boundary. A core's error can be in any language the operator
	// runs it in, and a byte-exact cut through a multi-byte character produces
	// invalid UTF-8 that JSON encoding silently replaces with a question mark in
	// the middle of the one sentence that was supposed to explain the outage.
	cut := nodeStatusMessageMax
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// handleSetNodeState turns a node on or off (spec §10).
//
// Disabling is a control-plane action, not a label: handleNodeHeartbeat and
// handleNodeRegister refuse a disabled node, so it stops receiving config
// bundles and its inbounds drain rather than continuing to be served by a box
// the operator believes is out of service. The alternative — a badge and nothing
// else — is worse than no feature, because it tells the operator a machine is
// off while it keeps taking traffic.
func (s *Server) handleSetNodeState(c *gin.Context) {
	var req struct {
		// A POINTER, so "not mentioned" is distinguishable from "false". A plain
		// bool would make every PATCH that forgot the field silently re-enable
		// the node it was meant to be editing.
		Disabled *bool `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Disabled == nil {
		fail(c, 400, "disabled is required")
		return
	}
	n, err := s.db.NodeByID(parseID(c))
	if err != nil {
		fail(c, 404, "not found")
		return
	}
	n.Disabled = *req.Disabled
	// Re-derive rather than assign a state: a node coming back on is
	// "connecting" or "error" depending on how long it has been quiet, and that
	// judgement already exists in one place.
	st, msg := nodeStatus(n)
	n.Status = st
	n.Healthy = st == store.NodeConnected
	if err := s.db.SaveNode(n); err != nil {
		failErr(c, 500, err)
		return
	}
	if n.Disabled {
		s.audit(c, "node.disable", n.Name)
	} else {
		s.audit(c, "node.enable", n.Name)
	}
	c.JSON(200, gin.H{"id": n.ID, "name": n.Name, "disabled": n.Disabled,
		"status": st, "status_message": msg})
}

// handleDeleteNode removes a node.
func (s *Server) handleDeleteNode(c *gin.Context) {
	id := parseID(c)
	// Revoke BEFORE deleting. The certificate outlives the row, and a deleted
	// node whose certificate still verifies is a credential for a node the
	// operator believes is gone — read the row while it is still there so the
	// serial is known.
	if n, err := s.db.NodeByID(id); err == nil {
		s.revokeNodeCert(n)
	}
	if err := s.db.DeleteNode(id); err != nil {
		failErr(c, 500, err)
		return
	}
	// Its log buffer has no owner any more. Left behind it is a few hundred
	// lines the panel holds for the lifetime of the process about a node nobody
	// can look at.
	s.logs.forget(id)
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
# Either credential is enough: BOOTSTRAP on a current panel, TOKEN against one
# that predates the mTLS control plane. Requiring both would refuse to install
# on exactly the mixed fleet this has to survive.
: "${PANEL:?set PANEL}"
if [ -z "${BOOTSTRAP:-}" ] && [ -z "${TOKEN:-}" ]; then
  echo "set BOOTSTRAP (preferred) or TOKEN" >&2; exit 2
fi
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
Environment=BOOTSTRAP=$BOOTSTRAP
Environment=TOKEN=$TOKEN
Environment=PANEL_FINGERPRINT=$PANEL_FINGERPRINT
ExecStart=/usr/local/bin/forgenode
# CAP_NET_ADMIN installs the firewall redirects a hysteria2 hop range needs, and
# CAP_NET_BIND_SERVICE lets an inbound use a port below 1024. Without the first,
# a hop range on this node is accepted, advertised to clients in the share link,
# and silently not redirected.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
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

// panelCertPubkeyPin returns the base64 SHA-256 of the panel certificate's
// SubjectPublicKeyInfo, in the form curl's --pinnedpubkey takes.
//
// This exists because the enrolment command the panel PRINTS did not work on a
// self-signed panel, which is the only case where the panel bothers to compute a
// fingerprint at all. The command is:
//
//	curl -fsSL https://<panel>/node-install.sh | PANEL=... PANEL_FINGERPRINT=... bash
//
// The SCRIPT knows to pass -k once it has a fingerprint. The curl that FETCHES
// the script does not, so on a self-signed panel it dies with "SSL certificate
// problem: self-signed certificate" before any of the pinning logic exists on
// the node. Measured on a real host, not reasoned about: the enrol command as
// generated could never complete on a panel without a domain.
//
// Adding a bare -k there would fetch the pinning script over an unverified
// connection — an attacker who can MITM that fetch simply serves a script
// without the pin, and the fingerprint becomes decoration. --pinnedpubkey is
// the fix that keeps it a one-liner AND verifies the peer: -k stops curl
// consulting the CA store, and the pin then decides.
func (s *Server) panelCertPubkeyPin() string {
	if s.cfg == nil || s.cfg.Panel() == nil || strings.TrimSpace(s.cfg.Panel().Domain) != "" {
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
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(crt.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
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

// defaultNodeDataDir is where the node installer puts a node's state. It is the
// fallback when an agent does not report its own, which is any agent older than
// the certificate fix.
const defaultNodeDataDir = "/var/lib/forgepanel"

// nodeCertPaths names the server certificate on the NODE's filesystem.
//
// It is the same layout the panel uses for itself (<data>/certs/self.{crt,key}),
// so an operator reading either machine finds the same thing in the same place,
// and the agent creates it with the same helper the panel does.
//
// The panel never ships its own key to a node: a node terminating TLS with the
// panel's private key would mean one stolen node compromises the panel and every
// other node with it.
func nodeCertPaths(dataDir string) (certPath, keyPath string) {
	d := strings.TrimSpace(dataDir)
	if d == "" {
		d = defaultNodeDataDir
	}
	return filepath.Join(d, "certs", "self.crt"), filepath.Join(d, "certs", "self.key")
}

// nodePortHops maps each hysteria2 inbound's listen port to its hop range, for
// the inbounds this node serves.
//
// Only hysteria2 has one: it is the protocol whose client hops, and a range on
// anything else would install redirects nothing dials.
func nodePortHops(specs []engine.InboundSpec) map[int]string {
	out := map[int]string{}
	for _, sp := range specs {
		n := sp.Node
		if n == nil || n.Protocol != model.ProtoHysteria2 || n.Hysteria2 == nil {
			continue
		}
		if r := strings.TrimSpace(n.Hysteria2.PortHopping); r != "" {
			out[n.Port] = r
		}
	}
	return out
}
