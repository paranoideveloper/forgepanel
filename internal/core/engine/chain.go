package engine

// Rendering a multi-hop egress chain into each engine's config.
//
// A chain is client -> entry (this server) -> hop0 -> hop1 -> ... -> internet.
// Both engines express it the same way conceptually — an outbound that is
// DIALLED THROUGH another outbound — under different names:
//
//	xray       streamSettings.sockopt.dialerProxy = "<previous hop's tag>"
//	sing-box   "detour": "<previous hop's tag>"
//
// In both, the routing rule points at the LAST hop, because each hop reaches its
// own server through the one before it. Pointing the rule at the first hop
// instead is the natural-looking mistake, and it produces a single-hop tunnel
// that works — which is why it would go unnoticed.
//
// Hops are rendered with the panel's own parser and renderers, so a chain
// supports exactly the protocols and transports the panel already understands,
// including REALITY, XHTTP and the full TLS surface. A second, chain-specific
// renderer is how the two would drift and a hop would quietly lose its uTLS
// fingerprint or its REALITY short id.

import (
	"fmt"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// chainTag names one hop. The chain index keeps two chains apart; the hop index
// keeps the hops within a chain apart and, read in a log, says how deep the hop
// is.
func chainTag(chainIndex, hop int) string {
	return fmt.Sprintf("egress-%d-%d", chainIndex, hop)
}

// xrayChainOutbounds renders a chain into Xray outbounds, first hop first.
//
// Every hop after the first carries sockopt.dialerProxy pointing at its
// predecessor, so Xray opens the connection to hop N through hop N-1.
func xrayChainOutbounds(chain model.EgressChain, chainIndex int) ([]jobj, error) {
	if chain.Empty() {
		return nil, fmt.Errorf("chain is empty")
	}
	out := make([]jobj, 0, len(chain))
	for i, uri := range chain {
		hop, err := egressHop(uri, 0)
		if err != nil {
			return nil, fmt.Errorf("hop %d of %d: %w", i+1, len(chain), err)
		}
		hop.Tag = chainTag(chainIndex, i)
		o, err := render.XrayOutbound(hop)
		if err != nil {
			return nil, fmt.Errorf("hop %d of %d: cannot render: %w", i+1, len(chain), err)
		}
		if i > 0 {
			if err := setXrayDialerProxy(o, chainTag(chainIndex, i-1)); err != nil {
				return nil, fmt.Errorf("hop %d of %d: %w", i+1, len(chain), err)
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// setXrayDialerProxy makes an outbound dial through another outbound.
//
// It creates streamSettings and sockopt when the hop's own rendering did not —
// a plain Shadowsocks hop has no stream settings at all, and a chain must not
// require every hop to be a transport-carrying protocol.
func setXrayDialerProxy(o jobj, through string) error {
	ss, _ := o["streamSettings"].(jobj)
	if ss == nil {
		if raw, present := o["streamSettings"]; present {
			m, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("streamSettings has unexpected type %T", raw)
			}
			ss = jobj(m)
		} else {
			ss = jobj{}
		}
		o["streamSettings"] = ss
	}
	sockopt, _ := ss["sockopt"].(jobj)
	if sockopt == nil {
		if raw, present := ss["sockopt"]; present {
			m, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("sockopt has unexpected type %T", raw)
			}
			sockopt = jobj(m)
		} else {
			sockopt = jobj{}
		}
		ss["sockopt"] = sockopt
	}
	sockopt["dialerProxy"] = through
	return nil
}

// singboxChainOutbounds renders a chain into sing-box outbounds, first hop
// first, each later hop detouring through its predecessor.
//
// This is what makes a chained Hysteria2 possible: hy2 is a sing-box protocol,
// so its chain has to be expressed here rather than in the Xray path.
func singboxChainOutbounds(chain model.EgressChain, chainIndex int) ([]jobj, error) {
	if chain.Empty() {
		return nil, fmt.Errorf("chain is empty")
	}
	out := make([]jobj, 0, len(chain))
	for i, uri := range chain {
		hop, err := egressHop(uri, 0)
		if err != nil {
			return nil, fmt.Errorf("hop %d of %d: %w", i+1, len(chain), err)
		}
		hop.Tag = chainTag(chainIndex, i)
		// Plural: a ShadowTLS hop is two outbounds, and rendering it as one
		// produced a hop that completed its TLS mimicry and carried nothing.
		rendered, err := render.SingboxOutbounds(hop)
		if err != nil {
			return nil, fmt.Errorf("hop %d of %d: cannot render for sing-box: %w", i+1, len(chain), err)
		}
		render.RetagOutbounds(rendered, hop.Tag)
		if i > 0 {
			// On the OUTERMOST outbound, not the primary: for a pair the primary
			// already detours through its own camouflage, and a second detour
			// there would replace the first.
			render.SetChainDetour(rendered, chainTag(chainIndex, i-1))
		}
		for _, o := range rendered {
			out = append(out, jobj(o))
		}
	}
	return out, nil
}
