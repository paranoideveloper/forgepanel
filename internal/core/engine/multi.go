package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// ClientCred is one user's credential materialised onto a shared inbound. Email
// is the stats key (Xray reports user>>>email>>>traffic>>>up/downlink), so the
// poller can attribute traffic per user (spec §11).
type ClientCred struct {
	Email    string
	UUID     string
	Password string
	Flow     string
}

// InboundSpec is an inbound template plus every user permitted on it. This is
// the correct multi-user materialisation: unlike a subscription (which stamps
// one user's identity), the SERVED inbound must contain a client per user or
// those users cannot authenticate.
type InboundSpec struct {
	Node    *model.Node
	Clients []ClientCred
}

// BuildMulti aggregates inbound specs into engine configs, expanding each xray
// inbound to carry one client per user and enabling per-user stats. sing-box
// inbounds get a users array likewise. Falls back to the template's own
// credential when an inbound has no bound users (so a bare inbound still works).
func BuildMulti(specs []InboundSpec, xrayAPIPort int, certPath, keyPath string) (*Bundle, error) {
	b := &Bundle{}
	var xin, sin, sep []any
	statsUsed := false
	for _, sp := range specs {
		n := sp.Node
		injectCert(n, certPath, keyPath)
		if n.Tag == "" {
			n.Tag = fmt.Sprintf("in-%d", n.Port) // ports are unique -> tags are unique
		}
		switch render.EngineFor(n.Protocol) {
		case "xray":
			in, err := render.XrayInbound(n)
			if err != nil {
				b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, err.Error()})
				continue
			}
			if len(sp.Clients) > 0 {
				applyXrayClients(in, n, sp.Clients)
				statsUsed = true
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
			if len(sp.Clients) > 0 {
				applySingboxUsers(ins[0], n, sp.Clients)
			}
			for _, in := range ins {
				sin = append(sin, in)
			}
			b.SingboxN++
		default:
			b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, "no supervised engine"})
		}
	}

	xrayCfg := jobj{
		"log":      jobj{"loglevel": "warning"},
		"api":      jobj{"tag": "api", "services": []string{"HandlerService", "StatsService"}},
		"stats":    jobj{},
		"policy":   jobj{"levels": jobj{"0": jobj{"statsUserUplink": statsUsed, "statsUserDownlink": statsUsed}}, "system": jobj{"statsInboundUplink": true, "statsInboundDownlink": true}},
		"inbounds": append([]any{jobj{"tag": "api", "listen": "127.0.0.1", "port": xrayAPIPort, "protocol": "dokodemo-door", "settings": jobj{"address": "127.0.0.1"}}}, xin...),
		"outbounds": []any{
			jobj{"tag": "direct", "protocol": "freedom"},
			jobj{"tag": "block", "protocol": "blackhole"},
		},
		"routing": jobj{"rules": []any{jobj{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}},
	}
	raw, err := json.MarshalIndent(xrayCfg, "", "  ")
	if err != nil {
		return nil, err
	}
	b.Xray = raw

	// No stats API is configured for sing-box, and that is a limitation of the
	// upstream binary rather than an oversight. Per-user counters would come from
	// experimental.v2ray_api, which the OFFICIAL sing-box release archives are not
	// built with — starting one errors with "v2ray api is not included in this
	// build, rebuild with -tags with_v2ray_api". binmgr pins those official
	// archives by SHA-256, so the panel cannot enable it without taking over the
	// build. clash_api (which official builds do include) reports live
	// connections, not cumulative per-user totals, so polling it would undercount
	// every connection that closes between polls — worse than no accounting,
	// because quotas would appear enforced while silently leaking traffic.
	//
	// The user names emitted above are still correct and required: sing-box
	// attributes traffic to them internally and in its own logs. What is missing
	// is panel-side COLLECTION, so quota enforcement currently covers Xray-served
	// protocols only. See docs/PROTOCOLS.md.
	singboxCfg := jobj{"log": jobj{"level": "warn"}, "inbounds": orEmpty(sin), "outbounds": []any{jobj{"type": "direct", "tag": "direct"}}}
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

// applyXrayClients rewrites an xray inbound's settings.clients to one entry per
// user, keyed by email for per-user stats.
func applyXrayClients(in jobj, n *model.Node, clients []ClientCred) {
	settings, _ := in["settings"].(jobj)
	if settings == nil {
		return
	}
	var arr []any
	for _, cl := range clients {
		switch n.Protocol {
		case model.ProtoVLESS:
			e := jobj{"id": cl.UUID, "email": cl.Email}
			if cl.Flow != "" {
				e["flow"] = cl.Flow
			} else if n.Flow != "" {
				e["flow"] = n.Flow
			}
			arr = append(arr, e)
		case model.ProtoVMess:
			arr = append(arr, jobj{"id": cl.UUID, "email": cl.Email, "alterId": 0})
		case model.ProtoTrojan:
			arr = append(arr, jobj{"password": cl.Password, "email": cl.Email})
		default:
			// SS/SOCKS/HTTP are single-credential in this build; keep template.
			return
		}
	}
	if len(arr) > 0 {
		settings["clients"] = arr
	}
}

// applySingboxUsers rewrites a sing-box inbound's users array per user.
func applySingboxUsers(in jobj, n *model.Node, clients []ClientCred) {
	var arr []any
	seen := map[string]int{}
	for i, cl := range clients {
		name := singboxUserName(cl, i, seen)
		switch n.Protocol {
		case model.ProtoVLESS:
			e := jobj{"uuid": cl.UUID, "name": name}
			if cl.Flow != "" {
				e["flow"] = cl.Flow
			} else if n.Flow != "" {
				e["flow"] = n.Flow
			}
			arr = append(arr, e)
		case model.ProtoVMess:
			arr = append(arr, jobj{"uuid": cl.UUID, "name": name, "alterId": 0})
		case model.ProtoTrojan:
			arr = append(arr, jobj{"password": cl.Password, "name": name})
		case model.ProtoHysteria2, model.ProtoTUIC:
			// Hysteria2/TUIC also carry a name so sing-box can attribute per-user
			// traffic stats — without it these protocols reported no per-user data.
			e := jobj{"password": cl.Password, "name": name}
			if cl.UUID != "" {
				e["uuid"] = cl.UUID
			}
			arr = append(arr, e)
		case model.ProtoAnyTLS:
			// AnyTLS + ShadowTLS were previously skipped (default: return), so every
			// panel user shared the inbound's single template password with no
			// per-user attribution. Emit one entry per user with a stable name.
			pw := cl.Password
			if pw == "" {
				pw = n.Password
			}
			arr = append(arr, jobj{"name": name, "password": pw})
		case model.ProtoShadowTLS:
			pw := cl.Password
			if pw == "" && n.ShadowTLS != nil {
				pw = n.ShadowTLS.Password
			}
			arr = append(arr, jobj{"name": name, "password": pw})
		default:
			return
		}
	}
	if len(arr) > 0 {
		in["users"] = arr
	}
}

// singboxUserName returns a stable, non-empty, inbound-unique name used as the
// per-user stats tag: the client email when set, else a deterministic fallback
// derived from the UUID or index. Collisions within an inbound are de-duplicated
// with a numeric suffix, and no secret is exposed as the visible name.
func singboxUserName(cl ClientCred, i int, seen map[string]int) string {
	name := strings.TrimSpace(cl.Email)
	if name == "" {
		// Derive a stable tag from a DIGEST of the UUID/password rather than the
		// raw UUID: the name appears in sing-box logs/stats, and the UUID is the
		// client's auth secret — it must not leak there.
		if cl.UUID != "" || cl.Password != "" {
			sum := sha256.Sum256([]byte(cl.UUID + "\x00" + cl.Password))
			name = "user-" + hex.EncodeToString(sum[:4])
		} else {
			name = fmt.Sprintf("user-%d", i)
		}
	}
	k := seen[name]
	seen[name] = k + 1
	if k > 0 {
		name = fmt.Sprintf("%s-%d", name, k)
	}
	return name
}

// injectCert gives a TLS/QUIC/AnyTLS inbound a server certificate if it lacks one,
// so the inbound actually serves TLS. Imported certs (already set) are respected.
func injectCert(n *model.Node, certPath, keyPath string) {
	if certPath == "" {
		return
	}
	needs := n.Security.Type == model.SecTLS || n.Protocol.IsQUICBased() || n.Protocol == model.ProtoAnyTLS
	if needs && n.Security.CertificateFile == "" {
		n.Security.CertificateFile = certPath
		n.Security.KeyFile = keyPath
	}
}
