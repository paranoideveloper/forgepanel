package engine

// Rendering operator-defined outbounds and routing rules into a core config.
//
// RULE ORDER IS A SAFETY DECISION, not a detail. Xray evaluates routing rules in
// order and takes the first match, so where these rules sit relative to the
// per-inbound relay chains decides what happens when both could apply.
//
// The order is: api, then per-inbound EGRESS, then operator rules, then the
// default direct outbound.
//
// Egress goes first deliberately. An inbound with a relay chain was explicitly
// told "send everything you receive through this upstream", and its users are
// relying on that: it is the whole reason the chain exists. If an operator rule
// were evaluated first, a rule as ordinary as "send *.example.com direct" would
// pull that domain OUT of the chain and expose the server's real address for it
// — a deanonymisation caused by a rule that looks harmless. The cost of this
// order is the opposite case: a "block ads" rule does not apply to traffic on a
// chained inbound. That is a visible, harmless failure. The other one is
// invisible and is not.
//
// This is stated in the UI too, because a routing table whose precedence has to
// be inferred from behaviour is a routing table people get wrong.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OutboundSpec is one operator-defined outbound, flattened for rendering.
type OutboundSpec struct {
	Tag            string
	Protocol       string
	Settings       json.RawMessage
	StreamSettings json.RawMessage
	SendThrough    string
}

// RuleSpec is one operator-defined routing rule, flattened for rendering.
//
// UserEmails rather than user ids: the core knows users by the email tag the
// panel writes into the inbound, and translating at the boundary keeps the
// encoding in one place.
type RuleSpec struct {
	Name        string
	Domain      []string
	IP          []string
	Port        string
	Network     string
	Protocol    []string
	InboundTags []string
	UserEmails  []string
	OutboundTag string
}

// GroupSpec is one operator-defined failover group: several outbounds behind a
// single tag, health-probed, so that new connections move off a member that has
// stopped answering instead of piling onto a dead relay.
//
// It is a distinct entity from an outbound because it is not one: a rule that
// targets a group is rendered with "balancerTag", not "outboundTag". Measured on
// Xray 26.2.6, a rule that names a balancer under "outboundTag" is ACCEPTED by
// the config validator and then drops every connection it matches, logging one
// "non existing outTag" line — so the mistake survives validation and shows up
// as traffic that silently stops.
type GroupSpec struct {
	Tag string
	// Members are outbound tags. Xray matches them by PREFIX, not by equality —
	// a member "relay" also selects "relay-eu" and "relay-us" — which is a trap
	// worth knowing about when naming exits.
	Members []string
	// Strategy is how the balancer chooses among the members that are up:
	// leastPing, leastLoad, roundRobin or random. Empty means DefaultGroupStrategy.
	Strategy string
	// ProbeURL and ProbeInterval drive the health check that decides which
	// members are up. They are per-group here and GLOBAL in Xray — see
	// RenderBalancers for what that costs.
	ProbeURL      string
	ProbeInterval string
	// FallbackTag is the outbound traffic takes when EVERY member is down, and
	// leaving it empty is not a neutral choice. Measured on Xray 26.2.6 with two
	// unreachable members: with no fallbackTag the connection went out DIRECT
	// (access log "[in >> direct]") — out of the server's real address, past the
	// relays the group existed to hide behind; with fallbackTag set to a
	// blackhole it was dropped. The store therefore defaults it to "block".
	FallbackTag string
}

// Defaults for a group the operator did not fully specify. They live here, in
// the renderer, so there is exactly one answer to "what does an unset field do"
// — the store validates these fields but does not invent values for them.
const (
	// gstatic's generate_204 is the probe every proxy client uses, so it is the
	// one least likely to be treated as anomalous by whatever sits in front of
	// the exit.
	DefaultProbeURL      = "https://www.gstatic.com/generate_204"
	DefaultProbeInterval = "60s"
	// leastPing, not random: a group exists to keep working when a member
	// stops, and random spreads a quarter of the traffic onto the slowest exit
	// on purpose.
	DefaultGroupStrategy = "leastPing"
	// A group with no fallback LEAKS when every member is down — see
	// GroupSpec.FallbackTag — so the renderer never emits one without it.
	DefaultAllDownTag = "block"
)

// RenderBalancers converts operator groups into Xray balancers plus the single
// observatory that keeps them honest.
//
// TWO OBJECTS, IN TWO PLACES. The balancer lives inside routing; the health
// probe is a top-level app. A balancer without one is not a degraded failover
// group, it is not a failover group at all: every member is graded equally
// healthy forever and traffic keeps going to the relay that died an hour ago.
//
// known is the set of outbound tags the config will define. An unknown member is
// REPORTED rather than skipped, and this is the sharpest edge in the feature.
// Xray's selector is a PREFIX match over outbound tags, so a member naming an
// outbound that does not exist selects nothing — and a balancer that selects
// nothing does not fail. Measured on Xray 26.2.6: the config validates, the
// process starts, and every connection the rule matched goes out DIRECT, past
// the relays, from the server's own address. fallbackTag does not catch it.
// That is a deanonymisation with a clean log, so it is refused here instead.
func RenderBalancers(specs []GroupSpec, known map[string]bool) ([]any, jobj, error) {
	if len(specs) == 0 {
		return nil, nil, nil
	}
	out := make([]any, 0, len(specs))
	seen := map[string]bool{}
	subjects := make([]string, 0, len(specs))
	subjectSeen := map[string]bool{}
	var probeURL, probeInterval, probeOwner string

	for _, sp := range specs {
		tag := strings.TrimSpace(sp.Tag)
		if tag == "" {
			return nil, nil, fmt.Errorf("a routing group has no tag")
		}
		if seen[tag] {
			// Two balancers of one name make the rule that targets it ambiguous
			// inside the core, which resolves it in whatever order it indexed
			// them — so traffic goes through an exit nobody chose.
			return nil, nil, fmt.Errorf("duplicate routing group tag %q", tag)
		}
		seen[tag] = true
		if len(sp.Members) == 0 {
			// The core refuses an empty selector outright ("infra/conf: empty
			// selector list"), and it refuses the WHOLE config for it — so one
			// half-finished group takes every inbound on the box offline.
			return nil, nil, fmt.Errorf("group %q has no members; the core refuses a balancer with an empty selector, and refuses the whole config with it", tag)
		}
		members := make([]string, 0, len(sp.Members))
		for _, m := range sp.Members {
			m = strings.TrimSpace(m)
			if !known[m] {
				return nil, nil, fmt.Errorf("group %q selects %q, which no outbound defines", tag, m)
			}
			members = append(members, m)
			if !subjectSeen[m] {
				subjectSeen[m] = true
				subjects = append(subjects, m)
			}
		}

		strategy := strings.TrimSpace(sp.Strategy)
		if strategy == "" {
			strategy = DefaultGroupStrategy
		}
		b := jobj{"tag": tag, "selector": members, "strategy": jobj{"type": strategy}}
		fb := strings.TrimSpace(sp.FallbackTag)
		if fb == "" {
			// Defaulted here rather than only in the store, because an omitted
			// fallback is the one mistake in this feature that fails OPEN.
			fb = DefaultAllDownTag
		}
		if !known[fb] {
			return nil, nil, fmt.Errorf("group %q falls back to %q, which no outbound defines", tag, fb)
		}
		b["fallbackTag"] = fb
		out = append(out, b)

		// ONE OBSERVATORY FOR THE WHOLE CONFIG is Xray's design, not the
		// panel's. Two groups asking for different probes cannot both be
		// honoured, and quietly honouring the first leaves the operator reading
		// a health check that is not the one their second group is graded on.
		url, interval := strings.TrimSpace(sp.ProbeURL), strings.TrimSpace(sp.ProbeInterval)
		if url == "" {
			url = DefaultProbeURL
		}
		if interval == "" {
			interval = DefaultProbeInterval
		}
		if probeOwner == "" {
			probeURL, probeInterval, probeOwner = url, interval, tag
			continue
		}
		if url != probeURL || interval != probeInterval {
			return nil, nil, fmt.Errorf(
				"groups %q and %q ask for different health probes (%s every %s vs %s every %s); "+
					"the core has one observatory for the whole config, so they must agree",
				probeOwner, tag, probeURL, probeInterval, url, interval)
		}
	}

	observatory := jobj{
		"subjectSelector": subjects,
		"pingConfig": jobj{
			"destination": probeURL,
			"interval":    probeInterval,
			// A probe that hangs must not hold a member's verdict open until the
			// next interval; five seconds is well past any exit worth using.
			"timeout": "5s",
			// Three samples, so one dropped packet on a working relay does not
			// evict it and start flapping every connection between members.
			"sampling": 3,
		},
	}
	return out, observatory, nil
}

// RenderOutbounds converts operator outbounds into core outbound objects.
//
// An outbound whose settings are not valid JSON is REPORTED, not skipped: a
// silently missing outbound leaves every rule that targets it pointing at
// nothing, and the core then refuses the entire config — so the operator sees
// every inbound go down and no indication which outbound caused it.
func RenderOutbounds(specs []OutboundSpec) ([]any, error) {
	out := make([]any, 0, len(specs))
	seen := map[string]bool{}
	for _, sp := range specs {
		tag := strings.TrimSpace(sp.Tag)
		if tag == "" {
			return nil, fmt.Errorf("an outbound has no tag")
		}
		if seen[tag] {
			// Two outbounds of one name make the core's choice arbitrary, so
			// traffic sent to a "block" outbound could leave the machine.
			return nil, fmt.Errorf("duplicate outbound tag %q", tag)
		}
		seen[tag] = true

		o := jobj{"tag": tag, "protocol": sp.Protocol}
		if len(sp.Settings) > 0 && !isJSONNull(sp.Settings) {
			var v any
			if err := json.Unmarshal(sp.Settings, &v); err != nil {
				return nil, fmt.Errorf("outbound %q settings: %w", tag, err)
			}
			o["settings"] = v
		}
		if len(sp.StreamSettings) > 0 && !isJSONNull(sp.StreamSettings) {
			var v any
			if err := json.Unmarshal(sp.StreamSettings, &v); err != nil {
				return nil, fmt.Errorf("outbound %q streamSettings: %w", tag, err)
			}
			o["streamSettings"] = v
		}
		if sp.SendThrough != "" {
			o["sendThrough"] = sp.SendThrough
		}
		out = append(out, o)
	}
	return out, nil
}

// RenderRules converts operator rules into core routing rules.
//
// known is the set of outbound tags the config will define and balancers is the
// set of group tags. A rule pointing at anything else is refused here rather
// than passed to the core, which rejects the whole config and takes every
// inbound down with it.
//
// The two sets are kept apart because the core spells the target differently for
// each: a rule aimed at a group carries "balancerTag". Naming a balancer under
// "outboundTag" is not caught anywhere — the config validates and the core
// starts — and then every connection that rule matches is dropped with a single
// "non existing outTag" line in the log. Setting both keys does not help either:
// outboundTag wins and the connections are dropped just the same. Both measured
// on Xray 26.2.6.
func RenderRules(specs []RuleSpec, known, balancers map[string]bool) ([]any, error) {
	out := make([]any, 0, len(specs))
	for _, sp := range specs {
		if sp.OutboundTag == "" {
			return nil, fmt.Errorf("rule %q has no outbound", sp.Name)
		}
		if !known[sp.OutboundTag] && !balancers[sp.OutboundTag] {
			return nil, fmt.Errorf("rule %q sends traffic to %q, which no outbound defines", sp.Name, sp.OutboundTag)
		}

		r := jobj{"type": "field"}
		if balancers[sp.OutboundTag] {
			r["balancerTag"] = sp.OutboundTag
		} else {
			r["outboundTag"] = sp.OutboundTag
		}
		matched := false
		if len(sp.Domain) > 0 {
			r["domain"] = sp.Domain
			matched = true
		}
		if len(sp.IP) > 0 {
			r["ip"] = sp.IP
			matched = true
		}
		if sp.Port != "" {
			r["port"] = sp.Port
			matched = true
		}
		if sp.Network != "" && sp.Network != "tcp,udp" {
			r["network"] = sp.Network
			matched = true
		}
		if len(sp.Protocol) > 0 {
			r["protocol"] = sp.Protocol
			matched = true
		}
		if len(sp.InboundTags) > 0 {
			r["inboundTag"] = sp.InboundTags
			matched = true
		}
		if len(sp.UserEmails) > 0 {
			r["user"] = sp.UserEmails
			matched = true
		}
		if !matched {
			// A rule with no conditions matches everything. Placed above a
			// carefully ordered list it silently swallows all of it, and routing
			// appears to have "stopped working" with nothing to point at.
			return nil, fmt.Errorf("rule %q has no conditions and would match all traffic", sp.Name)
		}
		out = append(out, r)
	}
	return out, nil
}

func isJSONNull(b json.RawMessage) bool {
	return strings.TrimSpace(string(b)) == "null"
}
