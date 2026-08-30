package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Port-collision validation (FP2-API-020).
//
// Two ForgePanel inbounds on one port do not fail politely: the generated engine
// document is rejected as a whole, so a single bad create takes EVERY other
// inbound offline — and because the panel never applies a config the core
// rejects, the operator sees a silent no-op with the stale config still running.
// The only place to catch that is before the row is written, which is what this
// file does.
//
// It is equally careful in the other direction. A check that refuses a port it
// merely cannot prove free is worse than no check at all, so every uncertain
// signal here (an unreadable procfs, an unattributable pid, a malformed hop
// range) resolves to "allowed", and only a concrete holder produces a 409.

const (
	l4TCP = "tcp"
	l4UDP = "udp"
)

// hostListeners is the host socket scan, indirected so tests can drive the
// foreign-process branch from a fixed table. The real machine's ports are not a
// test fixture: they change under us and cannot be made to contain an sshd on
// the port a test needs.
var hostListeners = firewall.Listeners

// portClaim is one contiguous port range held on one transport-layer protocol.
// Ranges (not single ports) because Hysteria2 port hopping answers on a whole
// span of UDP ports that nothing else may take.
type portClaim struct {
	lo, hi int
	l4     string
	holder string // human-readable owner, for the message
	id     uint   // owning inbound, 0 for panel-internal claims
}

func (c portClaim) overlaps(o portClaim) bool {
	return c.l4 == o.l4 && c.lo <= o.hi && o.lo <= c.hi
}

func (c portClaim) coversPort(port int, l4 string) bool {
	return c.l4 == l4 && port >= c.lo && port <= c.hi
}

// hopRanges parses a Hysteria2 port-hopping spec ("20000-50000", or a
// comma-separated list) into UDP claims. A malformed entry is SKIPPED rather
// than failing the check: the renderer skips it too, so it reserves nothing and
// must not block an unrelated port.
func hopRanges(spec string) []portClaim {
	var out []portClaim
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loS, hiS, ok := strings.Cut(strings.ReplaceAll(part, "-", ":"), ":")
		if !ok {
			hiS = loS // a single port is a legal degenerate range
		}
		lo, err1 := strconv.Atoi(strings.TrimSpace(loS))
		hi, err2 := strconv.Atoi(strings.TrimSpace(hiS))
		if err1 != nil || err2 != nil {
			continue
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo < 1 || hi > 65535 {
			continue
		}
		out = append(out, portClaim{lo: lo, hi: hi, l4: l4UDP})
	}
	return out
}

// inboundClaims expands an inbound into every port range it actually BINDS.
//
// It builds on requiredPorts — the panel's existing L4 authority, already used
// for firewall advice — with two corrections that only matter when the answer is
// used to reject a create:
//
//   - mKCP and QUIC transports ride UDP. requiredPorts answers by protocol
//     alone, so VLESS-over-mKCP reads as TCP there; trusting that would both
//     invent a TCP collision that cannot happen and miss the real UDP one.
//   - a ForgeDNS zone binds nothing of its own. Every zone is multiplexed onto
//     the single controller listener (core.NewForgeDNSController on cfg.DNSPort),
//     so two zones both nominally "on 53" are normal operation, not a collision.
func inboundClaims(n *model.Node, holder string, id uint) []portClaim {
	if n == nil || n.Port <= 0 || n.Port > 65535 || n.Protocol == model.ProtoForgeDNS {
		return nil
	}
	// An unknown protocol binds nothing we can reason about, and the handler's
	// own Validate rejects it with a far better message than "port taken".
	if !knownProtocol(n.Protocol) {
		return nil
	}
	tcp, udp := false, false
	var ranges []portClaim
	for _, r := range requiredPorts(n) {
		if r.Range != "" {
			ranges = append(ranges, hopRanges(r.Range)...)
			continue
		}
		switch r.Proto {
		case l4TCP:
			tcp = true
		case l4UDP:
			udp = true
		}
	}
	if n.Protocol.UsesTransport() {
		switch n.Transport.Network {
		case model.NetQUIC, model.NetMKCP:
			tcp, udp = false, true
		}
	}
	var out []portClaim
	if tcp {
		out = append(out, portClaim{lo: n.Port, hi: n.Port, l4: l4TCP})
	}
	if udp {
		out = append(out, portClaim{lo: n.Port, hi: n.Port, l4: l4UDP})
	}
	out = append(out, ranges...)
	for i := range out {
		out[i].holder, out[i].id = holder, id
	}
	return out
}

// panelClaims are the ports ForgePanel itself binds. An inbound placed on one of
// them either loses the race at boot or steals the operator's own way back in.
func (s *Server) panelClaims() []portClaim {
	if s.cfg == nil {
		return nil
	}
	var out []portClaim
	add := func(p int, l4, holder string) {
		if p > 0 && p <= 65535 {
			out = append(out, portClaim{lo: p, hi: p, l4: l4, holder: holder})
		}
	}
	add(s.cfg.PanelPort, l4TCP, "the ForgePanel web UI")
	if s.cfg.APIPort > 0 {
		// core.NewController is handed cfg.APIPort+1 and renders it as the Xray
		// stats/API inbound, so an operator inbound there collides inside the
		// very document that is supposed to serve it.
		add(s.cfg.APIPort+1, l4TCP, "the Xray stats API")
	}
	if s.fdns != nil {
		add(s.cfg.DNSPort, l4UDP, "the ForgeDNS tunnel listener")
	}
	return out
}

// PortConflict names exactly what is holding a port and what to do instead.
type PortConflict struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"` // tcp | udp
	Kind      string `json:"kind"`  // inbound | panel | system
	InboundID uint   `json:"inbound_id,omitempty"`
	HeldBy    string `json:"held_by"`
	Address   string `json:"address,omitempty"` // local bind address, system holders only
	PID       int    `json:"pid,omitempty"`     // 0 when /proc would not tell us
	Suggested int    `json:"suggested_port,omitempty"`
	Message   string `json:"message"`
}

// panelEngines are the process names ForgePanel's own supervisor runs. A socket
// owned by one of these on a port no inbound claims is our own engine mid-reload
// (or a not-yet-reaped process), not a foreign service to warn about.
var panelEngines = map[string]bool{
	"xray": true, "sing-box": true, "brook": true, "forgepanel": true,
	"awg-quick": true, "amneziawg-go": true, "wg-quick": true,
}

// portConflictFor reports the first reason n's port cannot be used, or nil when
// it is free. excludeID is the inbound being updated (0 on create): an inbound
// never conflicts with itself, and — crucially — the engine's own live listener
// on that inbound's port must not read as a foreign process squatting on it.
func (s *Server) portConflictFor(n *model.Node, excludeID uint) *PortConflict {
	if n == nil {
		return nil
	}
	// The request body has not been through the handler's pipeline yet, so
	// "VLESS" and "mkcp" still arrive in whatever case the caller typed.
	// Normalize a copy first — an unrecognised spelling would otherwise skip the
	// check entirely, which is the silent failure this whole file exists to stop.
	n = n.Clone()
	n.Normalize()

	// Behind a platform edge the public port is SHARED on purpose.
	//
	// Every inbound there is reached on the platform's single port — 443 at the
	// edge — and they are told apart by their transport path, not by port. The
	// port each one names is a public label, not a listener: the cores are given
	// private loopback ports the operator never sees or chooses (see paas.go).
	// So two inbounds "on 443" are not in conflict, they are the normal case.
	//
	// Left in place, this guard made a platform deploy permanently
	// single-inbound: the first one took 443, and the create form refused every
	// one after it with a conflict against a listener that does not exist. The
	// collision that IS real there is two inbounds on one PATH, and paasSpecs
	// refuses that with its own reason.
	if s.cfg != nil && s.paas().Enabled && paasSharesPublicPort(n) {
		return nil
	}

	want := inboundClaims(n, "", 0)
	if len(want) == 0 {
		return nil
	}

	var taken, self []portClaim
	if s.db != nil {
		ins, err := s.db.ListInbounds()
		if err == nil {
			for i := range ins {
				other, err := ins[i].Node()
				if err != nil || other == nil {
					continue
				}
				cs := inboundClaims(other, describeInbound(ins[i].ID, ins[i].Remark, ins[i].Enabled), ins[i].ID)
				if ins[i].ID == excludeID {
					self = append(self, cs...)
					continue
				}
				taken = append(taken, cs...)
			}
		}
	}
	taken = append(taken, s.panelClaims()...)

	busy := busyChecker(taken, self, hostListeners())
	for _, w := range want {
		for _, t := range taken {
			if !w.overlaps(t) {
				continue
			}
			port := w.lo
			if t.lo > port {
				port = t.lo // report the first port that actually clashes
			}
			kind := "panel"
			if t.id != 0 {
				kind = "inbound"
			}
			return finishConflict(&PortConflict{
				Port: port, Proto: w.l4, Kind: kind, InboundID: t.id, HeldBy: t.holder,
			}, n, busy)
		}
	}

	for _, l := range hostListeners() {
		var hit *portClaim
		for i := range want {
			if want[i].coversPort(l.Port, l.Proto) {
				hit = &want[i]
				break
			}
		}
		if hit == nil {
			continue
		}
		// Our own engine already serving THIS inbound's unchanged port is not a
		// collision — without this, every edit that keeps its port would be
		// refused because the running listener is visible in /proc.
		if coveredBy(self, l.Port, l.Proto) || panelEngines[l.Process] {
			continue
		}
		return finishConflict(&PortConflict{
			Port: l.Port, Proto: l.Proto, Kind: "system",
			HeldBy: describeProcess(l), Address: l.Address, PID: l.PID,
		}, n, busy)
	}
	return nil
}

// describeInbound labels a conflicting inbound. A DISABLED inbound still counts:
// it owns the port the moment someone toggles it back on, and discovering that
// then means discovering it as an engine that refuses to start.
func describeInbound(id uint, remark string, enabled bool) string {
	label := fmt.Sprintf("inbound #%d", id)
	if strings.TrimSpace(remark) != "" {
		label += fmt.Sprintf(" %q", remark)
	}
	if !enabled {
		label += " (currently disabled, but it still owns the port)"
	}
	return label
}

// describeProcess names a foreign holder as precisely as /proc allowed. An
// unnamed holder is still a real, correct detection — it just needs an honest
// label instead of a guess.
func describeProcess(l firewall.Listener) string {
	switch {
	case l.Process != "" && l.PID > 0:
		return fmt.Sprintf("%s (pid %d)", l.Process, l.PID)
	case l.Process != "":
		return l.Process
	default:
		return "another process ForgePanel did not start"
	}
}

// coveredBy reports whether any claim covers port/l4.
func coveredBy(claims []portClaim, port int, l4 string) bool {
	for _, c := range claims {
		if c.coversPort(port, l4) {
			return true
		}
	}
	return false
}

// busyChecker builds the "is this port spoken for" predicate used to suggest an
// alternative. self is included: an inbound's own current port is exactly the
// one being moved away from, so proposing it back is useless advice.
func busyChecker(taken, self []portClaim, live []firewall.Listener) func(port int, l4 string) bool {
	held := map[string]bool{}
	for _, l := range live {
		held[l.Proto+"/"+strconv.Itoa(l.Port)] = true
	}
	return func(port int, l4 string) bool {
		return held[l4+"/"+strconv.Itoa(port)] ||
			coveredBy(taken, port, l4) || coveredBy(self, port, l4)
	}
}

// finishConflict fills in a free alternative port and the operator-facing
// sentence. Suggestion is best-effort: a host with nothing free above the
// requested port simply gets no suggestion rather than a wrong one.
func finishConflict(cf *PortConflict, n *model.Node, busy func(int, string) bool) *PortConflict {
	var need []string
	for _, c := range inboundClaims(n, "", 0) {
		if c.lo == c.hi && c.lo == n.Port {
			need = append(need, c.l4)
		}
	}
	cf.Suggested = suggestPort(n.Port+1, need, busy)

	switch cf.Kind {
	case "inbound":
		cf.Message = fmt.Sprintf("port %d/%s is already claimed by %s. Two inbounds on one port make the whole "+
			"generated engine config invalid, which takes every other inbound offline, so this is refused up front.",
			cf.Port, cf.Proto, cf.HeldBy)
	case "panel":
		cf.Message = fmt.Sprintf("port %d/%s is reserved by %s. Using it would cut off the panel itself.",
			cf.Port, cf.Proto, cf.HeldBy)
	default:
		cf.Message = fmt.Sprintf("port %d/%s is already in use on this host by %s, listening on %s. "+
			"ForgePanel will not stop it — pick another port, or stop that service yourself first.",
			cf.Port, cf.Proto, cf.HeldBy, cf.Address)
	}
	if cf.Suggested > 0 {
		cf.Message += fmt.Sprintf(" Port %d is free.", cf.Suggested)
	}
	return cf
}

// suggestPort finds the lowest port at or above start that is free on EVERY
// transport the inbound needs — a Shadowsocks inbound wants tcp and udp, and
// half a port is no use to it.
func suggestPort(start int, need []string, busy func(int, string) bool) int {
	if len(need) == 0 {
		return 0
	}
	if start < 1024 {
		// Below 1024 needs privileges the panel process may not have, so a
		// suggestion there could fail to bind for a second, unrelated reason.
		start = 1024
	}
	for p := start; p <= 65535; p++ {
		free := true
		for _, l4 := range need {
			if busy(p, l4) {
				free = false
				break
			}
		}
		if free {
			return p
		}
	}
	return 0
}

// portCollisionGuard rejects an inbound create/update whose port is already
// claimed, BEFORE the handler writes the row.
//
// It is a middleware rather than a call inside the handler so the same rule
// covers every route that accepts a node body, and it restores the request body
// it consumed so the handler still binds normally. A body it cannot parse is
// passed straight through: the handler's own binding produces the better error.
func (s *Server) portCollisionGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost && c.Request.Method != http.MethodPut {
			c.Next()
			return
		}
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
		if err != nil {
			c.Next()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
		var n model.Node
		if json.Unmarshal(raw, &n) != nil {
			c.Next()
			return
		}
		var exclude uint
		if v := c.Param("id"); v != "" {
			if id, err := strconv.ParseUint(v, 10, 32); err == nil {
				exclude = uint(id)
			}
		}
		if cf := s.portConflictFor(&n, exclude); cf != nil {
			abortFailWith(c, &apierr.Error{Op: "port-guard", Kind: apierr.KindConflict,
				Code: "port_conflict", Message: cf.Message,
				Details: map[string]any{"conflict": cf}})
			return
		}
		c.Next()
	}
}

// registerPortRoutes exposes the checker to the UI so the create form can warn
// while the operator is still typing, instead of after they submit.
func (s *Server) registerPortRoutes(g *gin.RouterGroup) {
	g.POST("/ports/check", s.handlePortCheck)
	g.GET("/ports/listening", s.handleListeningPorts)
}

// handlePortCheck answers "can this inbound have this port". It is a query, not
// a mutation, so a taken port is a 200 with available=false — the UI needs the
// conflict detail either way.
func (s *Server) handlePortCheck(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		failErr(c, 400, err)
		return
	}
	var exclude uint
	if v := c.Query("id"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 32); err == nil {
			exclude = uint(id)
		}
	}
	canon := n.Clone()
	canon.Normalize()
	protos := []string{}
	for _, cl := range inboundClaims(canon, "", 0) {
		if cl.lo == cl.hi && cl.lo == n.Port {
			protos = append(protos, cl.l4)
		}
	}
	if cf := s.portConflictFor(&n, exclude); cf != nil {
		c.JSON(200, gin.H{"available": false, "port": n.Port, "binds": protos, "conflict": cf})
		return
	}
	c.JSON(200, gin.H{"available": true, "port": n.Port, "binds": protos})
}

// handleListeningPorts reports what is holding ports on this host. Read-only by
// design: the panel names a foreign process so the operator can decide, and
// never signals or displaces one.
func (s *Server) handleListeningPorts(c *gin.Context) {
	all := hostListeners()
	if v := c.Query("port"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			fail(c, 400, "port must be a number")
			return
		}
		filtered := make([]firewall.Listener, 0, 2)
		for _, l := range all {
			if l.Port == p {
				filtered = append(filtered, l)
			}
		}
		all = filtered
	}
	if all == nil {
		all = []firewall.Listener{}
	}
	c.JSON(200, gin.H{"listeners": all, "count": len(all)})
}
