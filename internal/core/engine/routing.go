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
// known is the set of outbound tags the config will define. A rule pointing at
// anything else is refused here rather than passed to the core, which rejects
// the whole config and takes every inbound down with it.
func RenderRules(specs []RuleSpec, known map[string]bool) ([]any, error) {
	out := make([]any, 0, len(specs))
	for _, sp := range specs {
		if sp.OutboundTag == "" {
			return nil, fmt.Errorf("rule %q has no outbound", sp.Name)
		}
		if !known[sp.OutboundTag] {
			return nil, fmt.Errorf("rule %q sends traffic to %q, which no outbound defines", sp.Name, sp.OutboundTag)
		}

		r := jobj{"type": "field", "outboundTag": sp.OutboundTag}
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
