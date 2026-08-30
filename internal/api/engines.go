package api

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// enabledInboundNodes returns the canonical nodes for every enabled inbound.
func (s *Server) enabledInboundNodes() []*model.Node {
	if s.db == nil {
		return nil
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		return nil
	}
	var nodes []*model.Node
	for _, in := range ins {
		if !in.Enabled {
			continue
		}
		if n, err := in.Node(); err == nil {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// enabledInboundSpecs builds the multi-user materialisation: each enabled
// inbound plus a client per active user whose EFFECTIVE access includes it —
// inherited from their group or assigned to them directly. This is what the
// served config must contain for users to authenticate (spec §11), so it has to
// agree with what the subscription hands out: an inbound a user can see in their
// subscription but cannot authenticate on is worse than not offering it.
func (s *Server) enabledInboundSpecs() []engine.InboundSpec {
	if s.db == nil {
		return nil
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		return nil
	}
	groups, _ := s.db.ListGroups()
	users, _ := s.db.ListUsers(0)
	// inbound id -> its active users
	byInbound := map[uint][]store.User{}
	groupInbounds := map[uint][]uint{}
	for _, g := range groups {
		groupInbounds[g.ID] = []uint(g.InboundIDs)
	}
	for _, u := range users {
		// A user who is disabled, expired, OR over their data limit (StatusLimited)
		// must not have their client credential materialized into any inbound, so
		// the core refuses their traffic. Skipping only Disabled/Expired let an
		// over-quota account keep transferring until the next engine reload.
		if u.Status == store.StatusDisabled || u.Status == store.StatusExpired || u.Status == store.StatusLimited {
			continue
		}
		// A user held for exceeding their concurrent-address limit is excluded
		// for as long as the hold lasts. This is what makes User.IPLimit mean
		// anything: it was stored and editable for its whole life while nothing
		// read it, so an operator could cap an account at two devices and have
		// the panel accept the number and do nothing with it.
		if u.IPLimitedUntil != nil && u.IPLimitedUntil.After(time.Now()) {
			continue
		}
		seen := map[uint]bool{}
		for _, inID := range groupInbounds[u.GroupID] {
			if !seen[inID] {
				seen[inID] = true
				byInbound[inID] = append(byInbound[inID], u)
			}
		}
		direct, err := s.db.UserAssignments(u.ID)
		if err != nil {
			continue
		}
		for _, inID := range direct.Direct {
			if !seen[inID] {
				seen[inID] = true
				byInbound[inID] = append(byInbound[inID], u)
			}
		}
	}
	var specs []engine.InboundSpec
	for _, in := range ins {
		if !in.Enabled {
			continue
		}
		n, err := in.Node()
		if err != nil {
			continue
		}
		if in.NodeID > 0 {
			if node, err := s.db.NodeByID(in.NodeID); err == nil && node.Address != "" {
				n.Address = node.Address
			}
		}
		// Per-client WireGuard peers, so several users on one WG inbound each get
		// their own key and tunnel address instead of sharing one and taking the
		// session from each other in turn.
		s.applyWGPeers(n, in.ID, byInbound[in.ID])
		sp := engine.InboundSpec{Node: n}
		// The inbound's OWN credential — the UUID/password embedded in the config
		// link the panel shows and hands out (handleInboundConfig → export.URI) —
		// must always authenticate. Without it a standalone inbound with no assigned
		// users renders an empty `clients` list and VLESS/VMess/Trojan reject every
		// connection; only Shadowsocks (shared-key, no client list) worked. Assigned
		// users are materialized in addition, for per-user multi-tenant access.
		if n.UUID != "" || n.Password != "" {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email:    "inbound-" + strconv.FormatUint(uint64(in.ID), 10),
				Username: n.Username, UUID: n.UUID, Password: n.Password, Flow: n.Flow,
			})
		}
		for _, u := range byInbound[in.ID] {
			sp.Clients = append(sp.Clients, engine.ClientCred{
				Email: job.UserEmail(u.ID), Username: u.Username, UUID: u.UUID, Password: u.Password, Flow: n.Flow,
			})
		}
		specs = append(specs, sp)
	}
	return specs
}

// engineUnavailable writes the one consistent response used whenever a request
// needs the local proxy engine but none is attached (control-plane-only panel,
// light-server mode, or tests). Every engine-dependent route uses this shape so
// callers can branch on the code, and nothing ever dereferences a nil engine.
func (s *Server) engineUnavailable(c *gin.Context) {
	apierr.Fail(c, &apierr.Error{Op: "engine-op", Kind: apierr.KindUnavailable,
		Code: "engine_unavailable", Message: "proxy engine is not available on this server"})
}

// reloadEngines regenerates and hot-applies the engine configs for all enabled
// inbounds + their users. Called after any inbound/user mutation and at boot.
// Errors are non-fatal (surfaced via /api/admin/engines): a panel must not crash
// because a core failed to download or a saved config is rejected.
// specsForBuild is the inbound list ANY config generated for this machine is
// built from — running it, validating it, or previewing it.
//
// A normal install serves what it can bind on its own interfaces. Behind a
// platform edge there is one port and no interface of our own, so the specs are
// rewritten for loopback.
//
// Every caller goes through here on purpose. When validation built from a
// different list than the reload, the two disagreed in exactly the way that is
// hardest to read: on a platform, saving any routing rule was refused with
//
//	failed to build inbound config with tag in-443 >
//	unable to listen on domain address: app.up.railway.app
//
// — the panel asking the core to bind a hostname the container does not own,
// while the running config was correct all along. Routing was simply
// unusable there, and the error was about the inbounds rather than the rule
// the operator was trying to save.
func (s *Server) specsForBuild() ([]engine.InboundSpec, []paasRoute, []engine.SkippedInbound) {
	if s.cfg != nil && s.paas().Enabled {
		return s.paasSpecs()
	}
	specs, skipped := s.localInboundSpecs()
	return specs, nil, skipped
}

// candidateSpecs is specsForBuild without the reload's side effects, for the
// paths that build a config to inspect rather than to run.
func (s *Server) candidateSpecs() []engine.InboundSpec {
	specs, _, _ := s.specsForBuild()
	return specs
}

// candidateNodes is candidateSpecs as bare nodes, for validators that take them.
func (s *Server) candidateNodes() []*model.Node {
	specs := s.candidateSpecs()
	out := make([]*model.Node, 0, len(specs))
	for _, sp := range specs {
		if sp.Node != nil {
			out = append(out, sp.Node)
		}
	}
	return out
}

// reloadSpecs picks the inbound list to serve and republishes the routing table
// that fronts it — in the same step, because a table that disagrees with what
// the cores were just told routes traffic to a port nothing is listening on.
func (s *Server) reloadSpecs() ([]engine.InboundSpec, []engine.SkippedInbound) {
	specs, routes, skipped := s.specsForBuild()
	s.setPaaSRoutes(routes)
	return specs, skipped
}

func (s *Server) reloadEngines() {
	defer func() {
		if r := recover(); r != nil {
			// recover gracefully from engine reload panic
		}
	}()
	if s.isClosed() || s.engine == nil {
		return
	}
	specs, paasSkipped := s.reloadSpecs()
	bundle, _ := s.engine.ReloadSpecs(specs)
	// Inbounds this deployment cannot serve at all were dropped before the
	// cores ever saw them, so the bundle has no idea they exist. Merging them
	// in is what makes the not-serving column tell the whole truth instead of
	// only the part the engine layer happened to witness.
	if len(paasSkipped) > 0 {
		if bundle == nil {
			bundle = &engine.Bundle{}
		}
		bundle.Skipped = append(bundle.Skipped, paasSkipped...)
	}
	// The bundle used to be discarded. It carries the list of inbounds no core
	// could serve, so throwing it away meant an operator created an inbound, the
	// panel accepted it, it never carried a byte, and NOTHING anywhere said why.
	s.recordNotServing(bundle)
	// Keep the host firewall in sync with the inbound ports so a created inbound
	// is actually reachable from the internet — otherwise it listens, passes the
	// loopback Verify, and ufw silently drops every external client (a phone).
	// Best-effort and backgrounded; never blocks or fails the reload.
	// Not behind a platform edge: there the inbound ports are loopback-only by
	// construction, the one public port is the platform's to manage, and
	// opening a hole for 127.0.0.1:39000 would be a firewall rule for traffic
	// that can never arrive.
	if s.cfg == nil || !s.paas().Enabled {
		ports := make([]int, 0, len(specs))
		for _, sp := range specs {
			if sp.Node != nil && sp.Node.Port > 0 {
				ports = append(ports, sp.Node.Port)
			}
		}
		go firewall.EnsureOpen(ports)
	}
}

// handleEngines returns the supervised cores' live status (spec §6).
func (s *Server) handleEngines(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, []any{})
		return
	}
	c.JSON(200, s.engine.Status())
}

// handleEngineConfig returns the last generated engine configs — the "show
// generated config" debugging superpower (spec §6).
func (s *Server) handleEngineConfig(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, gin.H{})
		return
	}
	b := s.engine.LastBundle()
	if b == nil {
		c.JSON(200, gin.H{"xray": "", "singbox": "", "note": "no inbounds loaded yet"})
		return
	}
	c.JSON(200, gin.H{
		"xray": string(b.Xray), "singbox": string(b.Singbox),
		"xray_inbounds": b.XrayN, "singbox_inbounds": b.SingboxN, "skipped": b.Skipped,
	})
}

// handleEngineValidate builds configs from current inbounds and runs each core's
// own validator without applying them (Config Doctor, spec §8.6).
func (s *Server) handleEngineValidate(c *gin.Context) {
	if s.engine == nil {
		c.JSON(200, gin.H{})
		return
	}
	_, results := s.engine.Validate(s.candidateNodes())
	c.JSON(200, results)
}

// enabledInboundSpecsForNodeAddress returns inbound specs filtered for a specific node address.
// localInboundSpecs is the panel's OWN share: the inbounds this machine can
// actually bind.
//
// A core cannot bind an address that does not exist on the host, and it refuses
// a config as a WHOLE — so ONE unbindable inbound stops the panel's core from
// starting and takes every other inbound with it:
//
//	Failed to start: app/proxyman/inbound: failed to listen TCP on 25443 >
//	listen tcp 94.183.174.37:25443: bind: cannot assign requested address
//
// Two ways that happens, and the first fix only covered one of them. An inbound
// bound to an ENROLLED NODE's address belongs to that node. But an operator who
// pastes a subscription into the importer gets a hundred inbounds addressed to
// other people's servers — 13.113.18.50, usejh2.neobo-tooth.ru — which are not
// nodes and are not here either. Measured on a live panel: 110 imported configs,
// xray crashed, 41 restarts, every locally-created inbound dead.
//
// So the test is bindability, not node membership: an inbound is served here if
// its address is empty, a wildcard, a loopback, or an address this host actually
// holds. That covers node addresses and imported foreign ones with one rule, and
// it is the same question the core is about to ask the kernel.
func (s *Server) localInboundSpecs() ([]engine.InboundSpec, []engine.SkippedInbound) {
	all := s.enabledInboundSpecs()
	local := localAddresses()
	if len(local) == 0 {
		// The interface list could not be read. Filtering on a set we do not
		// have would silently stop serving everything; leave the list alone and
		// let the core report what it cannot bind.
		return all, nil
	}
	out := make([]engine.InboundSpec, 0, len(all))
	var skipped []engine.SkippedInbound
	for _, sp := range all {
		if sp.Node == nil {
			continue
		}
		if boundHere(sp.Node.Address, local) {
			out = append(out, sp)
			continue
		}
		// Dropping it is right — xray refuses the WHOLE config over one address
		// it cannot bind, so serving it would take every other inbound down with
		// it. Saying so is the part that was missing: without a reason the panel
		// showed the inbound enabled, reachable, and serving nothing, with
		// nothing in the engine log and nothing listening, which is
		// indistinguishable from a broken core.
		skipped = append(skipped, engine.SkippedInbound{
			Remark: sp.Node.Remark,
			Reason: fmt.Sprintf("address %q is not an address this server can bind, so it is left "+
				"out rather than taking the whole config down with it. Use one of this host's own "+
				"addresses (or 0.0.0.0), and put the public hostname clients dial in the link instead.",
				sp.Node.Address),
		})
	}
	return out, skipped
}

// boundHere reports whether this host can bind addr.
//
// A name is resolved, because an operator may legitimately address an inbound by
// the panel's own hostname. Resolution failure means NOT here: an address we
// cannot even look up is one the core certainly cannot bind, and excluding it
// costs one inbound while including it costs all of them.
func boundHere(addr string, local map[string]bool) bool {
	a := strings.TrimSpace(addr)
	switch a {
	case "", "0.0.0.0", "::", "*", "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(a); ip != nil {
		return local[ip.String()]
	}
	ips, err := net.LookupIP(a)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if local[ip.String()] {
			return true
		}
	}
	return false
}

// localAddresses is every IP this host holds, as a set.
func localAddresses() map[string]bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			out[ipnet.IP.String()] = true
		}
	}
	return out
}

func (s *Server) enabledInboundSpecsForNodeAddress(addr string) []engine.InboundSpec {
	all := s.enabledInboundSpecs()
	if addr == "" {
		return all
	}
	var out []engine.InboundSpec
	for _, sp := range all {
		if sp.Node != nil && (sp.Node.Address == "" || sp.Node.Address == "0.0.0.0" || sp.Node.Address == addr) {
			out = append(out, sp)
		}
	}
	return out
}
