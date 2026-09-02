package model

// Multi-hop egress chains.
//
// A single hop already let an inbound relay out through one upstream server
// (client -> entry -> exit). A CHAIN adds the transit hops in between, which is
// the shape that actually survives Iranian filtering: the client reaches a
// nearby entry that is cheap to replace, the entry hands off to a transit box
// outside the country, and only the last hop touches the open internet. Losing
// any single link costs one hop, not the whole path.
//
// It is expressed as an ordered list of client URIs — the same links an operator
// would paste into a client app — running from the hop THIS server dials first
// to the final exit.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EgressChain is the ordered list of upstream hops an inbound relays through.
//
// Index 0 is dialled by this server; each later hop is reached THROUGH the one
// before it; the last hop is where traffic reaches the internet. An empty chain
// means the inbound egresses directly, which is what every inbound does by
// default.
//
// This is SERVER-side secret material: every entry carries an upstream hop's
// credentials, so a chain must never appear in a subscription or a client link.
type EgressChain []string

// UnmarshalJSON accepts either a single URI string or an array of them.
//
// The string form is what the field held before chains existed, and it is still
// what a one-hop chain marshals back to. Accepting both means stored inbounds,
// imported share links and older API clients keep working untouched — a stricter
// parser would have turned every existing single-hop inbound into a parse error
// on the first read after upgrade.
func (e *EgressChain) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*e = nil
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		*e = cleanChain(list)
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return fmt.Errorf("egress: expected a hop URI or a list of them: %w", err)
	}
	*e = cleanChain([]string{one})
	return nil
}

// MarshalJSON writes a single hop as a bare string and a chain as an array.
//
// Emitting the legacy shape for the legacy case keeps every existing consumer —
// stored JSON, the studio round trip, share-link import — byte-identical to what
// it was, so adding chains changes nothing for anyone not using them.
func (e EgressChain) MarshalJSON() ([]byte, error) {
	switch len(e) {
	case 0:
		return []byte("null"), nil
	case 1:
		return json.Marshal(e[0])
	default:
		return json.Marshal([]string(e))
	}
}

// cleanChain drops blank entries and trims each hop.
//
// A blank hop in the middle of a chain is not a hop that does nothing: it is a
// link the builder cannot render, and the inbound would be skipped entirely.
// Removing them here means a trailing comma in the UI does not take an inbound
// offline.
func cleanChain(in []string) EgressChain {
	out := make(EgressChain, 0, len(in))
	for _, h := range in {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Empty reports whether the inbound egresses directly.
func (e EgressChain) Empty() bool { return len(e) == 0 }

// Exit is the last hop — where traffic reaches the internet.
func (e EgressChain) Exit() string {
	if len(e) == 0 {
		return ""
	}
	return e[len(e)-1]
}

// Key is a stable identity for the whole chain, used to share one set of
// outbounds between inbounds that relay through the same path.
//
// The separator is a NUL because a URI can contain almost anything else; two
// different chains must never collide into one key, or inbounds would silently
// be routed through a path their operator did not configure.
func (e EgressChain) Key() string { return strings.Join(e, "\x00") }
