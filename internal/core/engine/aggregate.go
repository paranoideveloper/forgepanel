// Package engine aggregates the panel's inbounds into concrete, complete engine
// configurations (one per core) that the supervisor writes to disk and runs. An
// inbound is routed to Xray or sing-box by render.EngineFor (spec §6).
package engine

import (
	"encoding/json"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

type jobj = map[string]any

// Bundle is the set of per-engine configs materialised from a list of inbounds,
// plus any inbounds that could not be rendered (surfaced to Config Doctor).
type Bundle struct {
	Xray     []byte
	Singbox  []byte
	XrayN    int
	SingboxN int
	Skipped  []SkippedInbound
}

// ReasonNoSupervisedEngine is the skip this builder records for a protocol it
// does not itself render — which is every protocol with a dedicated engine,
// Brook and AmneziaWG and ForgeDNS among them. It is a statement about THIS
// builder, not about the panel: the dispatcher serves those from the adapter
// registry, and it clears this mark for the ones it started. It is a named
// constant so the two sides cannot drift apart on a string literal.
const ReasonNoSupervisedEngine = "no supervised engine"

// SkippedInbound records an inbound that no engine here could serve.
type SkippedInbound struct {
	Remark string `json:"remark"`
	Reason string `json:"reason"`
}

// Build produces the engine bundle. Each engine gets a standard freedom/direct
// outbound and an aggregate of its inbounds. Configs are always valid JSON even
// when there are zero inbounds (so `-test`/`check` still pass on an empty panel).
func Build(nodes []*model.Node, xrayAPIPort int) (*Bundle, error) {
	b := &Bundle{}
	var xin, sin, sep []any
	for _, n := range nodes {
		switch render.EngineFor(n.Protocol) {
		case "xray":
			in, err := render.XrayInbound(n)
			if err != nil {
				b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, err.Error()})
				continue
			}
			xin = append(xin, in)
			b.XrayN++
		case "sing-box":
			if render.IsSingboxEndpoint(n) { // WireGuard -> endpoints[]
				ep, err := render.SingboxEndpoint(n)
				if err != nil {
					b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, err.Error()})
					continue
				}
				sep = append(sep, ep)
				b.SingboxN++
				continue
			}
			ins, err := render.SingboxInbounds(n)
			if err != nil {
				b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, err.Error()})
				continue
			}
			for _, in := range ins {
				sin = append(sin, in)
			}
			b.SingboxN++
		default:
			b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, "no supervised engine (brook/forgedns handled elsewhere)"})
		}
	}

	xrayCfg := jobj{
		"log":   jobj{"loglevel": "warning"},
		"api":   jobj{"tag": "api", "services": []string{"HandlerService", "StatsService"}},
		"stats": jobj{},
		"inbounds": append([]any{
			// local gRPC API listener for hot add/remove + stats (spec §6).
			jobj{"tag": "api", "listen": "127.0.0.1", "port": xrayAPIPort, "protocol": "dokodemo-door",
				"settings": jobj{"address": "127.0.0.1"}},
		}, xin...),
		"outbounds": []any{
			jobj{"tag": "direct", "protocol": "freedom"},
			jobj{"tag": "block", "protocol": "blackhole"},
		},
		"routing": jobj{"rules": []any{
			jobj{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		}},
	}
	raw, err := json.MarshalIndent(xrayCfg, "", "  ")
	if err != nil {
		return nil, err
	}
	b.Xray = raw

	singboxCfg := jobj{
		"log":       jobj{"level": "warn"},
		"inbounds":  orEmpty(sin),
		"outbounds": []any{jobj{"type": "direct", "tag": "direct"}},
	}
	if len(sep) > 0 {
		singboxCfg["endpoints"] = sep
	}
	sraw, err := json.MarshalIndent(singboxCfg, "", "  ")
	if err != nil {
		return nil, err
	}
	b.Singbox = sraw
	return b, nil
}

func orEmpty(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}
