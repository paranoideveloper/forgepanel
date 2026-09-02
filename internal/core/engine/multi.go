package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/forgepanel/forgepanel/internal/protocol/parse"
	"sort"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// ClientCred is one user's credential materialised onto a shared inbound. Email
// is the stats key (Xray reports user>>>email>>>traffic>>>up/downlink), so the
// poller can attribute traffic per user (spec §11).
type ClientCred struct {
	Email    string
	Username string // SOCKS/HTTP account login (matches the subscription's user field)
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
	// CertPath/KeyPath override the build-wide self-signed fallback for THIS
	// inbound, and are how a real Let's Encrypt certificate reaches the engines.
	// The resolver lives in the caller (which owns the certificate store); the
	// builder stays a pure function of what it is handed.
	CertPath string
	KeyPath  string
}

// BuildMulti aggregates inbound specs into engine configs, expanding each xray
// inbound to carry one client per user and enabling per-user stats. Sing-box
// inbounds get a users array likewise. An inbound without assigned users gets
// an empty Xray allow-list, so a template credential can never bypass access
// assignment.
// SingboxAPIPort is the loopback port the generated sing-box config exposes its
// v2ray stats API on. Zero disables it entirely, which is correct when the
// installed sing-box was built without with_v2ray_api: enabling the section on a
// binary that cannot serve it is a startup failure, and it would take every
// sing-box inbound down rather than merely leaving them unmetered.
var SingboxAPIPort int

func BuildMulti(specs []InboundSpec, xrayAPIPort int, certPath, keyPath string) (*Bundle, error) {
	return BuildMultiWithRouting(specs, xrayAPIPort, certPath, keyPath, nil, nil, nil)
}

// BuildMultiWithRouting is BuildMulti plus the operator's own outbounds and
// routing rules.
//
// See routing.go for why the rules are placed AFTER the per-inbound egress
// rules: it is a safety decision, not an ordering detail.
func BuildMultiWithRouting(specs []InboundSpec, xrayAPIPort int, certPath, keyPath string,
	outbounds []OutboundSpec, rules []RuleSpec, groups []GroupSpec) (*Bundle, error) {
	return BuildMultiFor(specs, xrayAPIPort, SingboxAPIPort, certPath, keyPath, outbounds, rules, groups)
}

// BuildMultiFor is BuildMultiWithRouting with the sing-box stats port passed
// EXPLICITLY rather than read from the package global.
//
// The global is the panel's own port, decided by whether the PANEL's local
// sing-box supports metering. A remote node has a different binary and a
// different answer, so a config built for a node has to be told — reading the
// global gave every node the panel's answer, which is wrong in both directions:
// it omitted the stats section on a control-plane-only panel (leaving capable
// nodes unmetered forever) and would emit it for a node whose stock binary
// refuses to start with it.
func BuildMultiFor(specs []InboundSpec, xrayAPIPort, singboxAPIPort int, certPath, keyPath string,
	outbounds []OutboundSpec, rules []RuleSpec, groups []GroupSpec) (*Bundle, error) {
	b := &Bundle{}
	var xin, sin, sep []any
	statsUsed := false
	// Egress chains: upstream hop URI -> outbound tag, plus the inbound tags
	// routed through it. Built as we walk the specs and emitted after, so two
	// inbounds sharing one upstream share a single outbound rather than dialling
	// it twice.
	egressTag := map[string]string{}
	var egressOutbounds []any
	var egressRules []any
	// The same three, for sing-box. Kept separate because the tag namespaces and
	// the config documents are separate; a shared counter would let one engine's
	// index gap confuse the other's logs.
	sbEgressTag := map[string]string{}
	var sbEgressOutbounds []any
	var sbEgressRules []any
	for _, sp := range specs {
		// Work on a COPY. injectCert and the tag assignment below both write to
		// the node, and specs carry pointers straight out of the store, so
		// building a config used to mutate the caller's objects -- stamping a
		// self-signed certificate path onto an inbound that had none, which a
		// later save would then persist as though the operator had chosen it.
		n := sp.Node.Clone()
		if sp.CertPath != "" {
			injectCert(n, sp.CertPath, sp.KeyPath)
		}
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
			applyXrayClients(in, n, sp.Clients)
			if len(sp.Clients) > 0 {
				statsUsed = true
			}
			if !n.Egress.Empty() {
				key := n.Egress.Key()
				tag, ok := egressTag[key]
				if !ok {
					outs, err := xrayChainOutbounds(n.Egress, len(egressTag))
					if err != nil {
						// A broken upstream must not silently become a direct
						// exit: that would leak traffic straight out of the box
						// the operator explicitly told to relay it.
						b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, "egress: " + err.Error()})
						continue
					}
					// Route to the LAST hop: each hop dials through the one
					// before it, so the exit is the tag traffic is sent to.
					tag, _ = outs[len(outs)-1]["tag"].(string)
					egressTag[key] = tag
					for _, o := range outs {
						egressOutbounds = append(egressOutbounds, o)
					}
				}
				egressRules = append(egressRules, jobj{
					"type": "field", "inboundTag": []string{n.Tag}, "outboundTag": tag,
				})
			}
			xin = append(xin, in)
			b.XrayN++
		case "sing-box":
			if render.IsSingboxEndpoint(n) { // WireGuard -> endpoints[]
				if !n.Egress.Empty() {
					// A WireGuard endpoint is a kernel/userspace tunnel device,
					// not a routed inbound: sing-box has nowhere to attach a
					// per-inbound detour. Accepting the chain and ignoring it
					// would leak exactly the traffic the chain exists to hide.
					b.Skipped = append(b.Skipped, SkippedInbound{n.Remark,
						"egress: a WireGuard endpoint cannot be chained through an upstream hop; " +
							"chain the peer's own allowed-ips upstream instead"})
					continue
				}
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
			if !n.Egress.Empty() {
				key := n.Egress.Key()
				tag, ok := sbEgressTag[key]
				if !ok {
					outs, err := singboxChainOutbounds(n.Egress, len(sbEgressTag))
					if err != nil {
						b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, "egress: " + err.Error()})
						continue
					}
					tag, _ = outs[len(outs)-1]["tag"].(string)
					sbEgressTag[key] = tag
					for _, o := range outs {
						sbEgressOutbounds = append(sbEgressOutbounds, o)
					}
				}
				// A protocol may render as SEVERAL inbounds (ShadowTLS is a
				// handshake listener plus the detour it fronts). Every one of
				// them has to be routed, or the chain applies to part of the
				// traffic and the rest exits directly.
				inTags := make([]string, 0, len(ins))
				for _, in := range ins {
					if t, _ := in["tag"].(string); t != "" {
						inTags = append(inTags, t)
					}
				}
				if len(inTags) == 0 {
					b.Skipped = append(b.Skipped, SkippedInbound{n.Remark,
						"egress: the inbound has no tag to route from"})
					continue
				}
				sbEgressRules = append(sbEgressRules, jobj{
					"inbound": inTags, "action": "route", "outbound": tag,
				})
			}
			for _, in := range ins {
				sin = append(sin, in)
			}
			b.SingboxN++
		default:
			b.Skipped = append(b.Skipped, SkippedInbound{n.Remark, ReasonNoSupervisedEngine})
		}
	}

	// Operator outbounds and rules. A failure here fails the whole build: a
	// routing table that renders "mostly" is a routing table sending some
	// traffic somewhere nobody chose.
	userOutbounds, err := RenderOutbounds(outbounds)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{"direct": true, "block": true}
	for _, sp := range outbounds {
		known[strings.TrimSpace(sp.Tag)] = true
	}
	// Egress tags count as known so a rule may deliberately target a relay
	// chain, which is the one way an operator can route INTO one.
	for _, t := range egressTag {
		known[t] = true
	}
	// Failover groups are rendered BEFORE the rules that target them, because
	// RenderRules has to know which tags are balancers: the core spells that
	// target "balancerTag", and a rule that hands it "outboundTag" instead
	// validates cleanly and then drops every connection it matches.
	balancers, observatory, err := RenderBalancers(groups, known)
	if err != nil {
		return nil, err
	}
	balancerTags := make(map[string]bool, len(groups))
	for _, sp := range groups {
		balancerTags[strings.TrimSpace(sp.Tag)] = true
	}
	userRules, err := RenderRules(rules, known, balancerTags)
	if err != nil {
		return nil, err
	}

	xrayCfg := jobj{
		// access:"" sends the access log to STDOUT, which the supervisor already
		// reads. That is what feeds the presence tracker: who is connected, from
		// which address, on which inbound. A file would have to be rotated,
		// would grow without bound on a busy node, and would leave connection
		// metadata on disk after a restart — none of which buys anything, since
		// the panel owns the process's output pipe already.
		"log":      jobj{"loglevel": "warning", "access": ""},
		"api":      jobj{"tag": "api", "services": []string{"HandlerService", "StatsService"}},
		"stats":    jobj{},
		"policy":   jobj{"levels": jobj{"0": jobj{"statsUserUplink": statsUsed, "statsUserDownlink": statsUsed}}, "system": jobj{"statsInboundUplink": true, "statsInboundDownlink": true}},
		"inbounds": append([]any{jobj{"tag": "api", "listen": "127.0.0.1", "port": xrayAPIPort, "protocol": "dokodemo-door", "settings": jobj{"address": "127.0.0.1"}}}, xin...),
		// "direct" stays FIRST: Xray uses the first outbound for anything no rule
		// matched, and demoting it would silently change where unmatched traffic
		// goes for every existing installation.
		"outbounds": append(append([]any{
			jobj{"tag": "direct", "protocol": "freedom"},
			jobj{"tag": "block", "protocol": "blackhole"},
		}, egressOutbounds...), userOutbounds...),
		// ORDER MATTERS AND IS DELIBERATE (see routing.go):
		//  1. api      — keeps the local gRPC listener reachable.
		//  2. egress   — an inbound with a relay chain sends ALL of its traffic
		//                through it. Placing operator rules above this would let
		//                an ordinary "send this domain direct" rule pull traffic
		//                out of a chain and expose the server's real address.
		//  3. operator rules.
		//  4. unmatched falls through to the default direct outbound, so an
		//     installation with no rules behaves exactly as before.
		"routing": jobj{"rules": append(append([]any{
			jobj{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		}, egressRules...), userRules...)},
	}
	if len(balancers) > 0 {
		// Both keys are added only when a group exists, so a panel that uses no
		// groups still generates the config it always did — byte for byte.
		xrayCfg["routing"].(jobj)["balancers"] = balancers
		// burstObservatory is a TOP-LEVEL app, not part of routing. Nesting it
		// under routing is silently ignored by the core, and the balancer then
		// grades every member equally healthy for the life of the process:
		// failover that reports itself as working and moves nothing.
		xrayCfg["burstObservatory"] = observatory
	}
	raw, err := json.MarshalIndent(xrayCfg, "", "  ")
	if err != nil {
		return nil, err
	}
	b.Xray = raw

	// FAILOVER GROUPS DO NOT CROSS INTO SING-BOX, deliberately. The operator's
	// outbounds are stored as the core's own JSON verbatim — Xray's JSON — and
	// none of them is rendered into the sing-box document, so a sing-box
	// "urltest" over their tags would select outbounds this config does not
	// define. sing-box refuses the whole document for that, which takes every
	// hysteria2, TUIC, AnyTLS, ShadowTLS and WireGuard inbound on the box down.
	// Operator routing has always been Xray-only for the same reason; groups
	// inherit it rather than pretending otherwise.
	//
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
	singboxCfg := jobj{
		"log":       jobj{"level": "warn"},
		"inbounds":  orEmpty(sin),
		"outbounds": append([]any{jobj{"type": "direct", "tag": "direct"}}, sbEgressOutbounds...),
	}
	// Per-user counters for the protocols only sing-box serves — hysteria2,
	// tuic, anytls, shadowtls, wireguard — which were metered by nothing at all,
	// so their users' quotas were never enforced.
	//
	// The lists are NOT optional: with `stats: {enabled: true}` alone, sing-box
	// collects nothing and the API returns an empty response, which is
	// indistinguishable from "no traffic yet". Every tracked name has to be
	// enumerated, which is why this is built from the specs rather than a flag.
	if singboxAPIPort > 0 && len(sin) > 0 {
		if stats := singboxStatsSection(specs, sin, sbEgressOutbounds); stats != nil {
			singboxCfg["experimental"] = jobj{
				"v2ray_api": jobj{
					"listen": fmt.Sprintf("127.0.0.1:%d", singboxAPIPort),
					"stats":  stats,
				},
			}
		}
	}
	if len(sbEgressRules) > 0 {
		// "final" keeps every unchained inbound on the direct outbound, so
		// adding a chain to one inbound cannot alter any other.
		singboxCfg["route"] = jobj{"rules": sbEgressRules, "final": "direct"}
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

// applyXrayClients rewrites an xray inbound's settings.clients to one entry per
// user, keyed by email for per-user stats.
func applyXrayClients(in jobj, n *model.Node, clients []ClientCred) {
	settings, _ := in["settings"].(jobj)
	if settings == nil {
		return
	}
	// SOCKS/HTTP authenticate with username:password accounts (settings.accounts),
	// not a clients[] list. Emit one account per client that has a username, so
	// every assigned user has their own login instead of the single template
	// account the render produced (which the subscription's per-user credential
	// could never match). Clients without a username — e.g. an inbound-own cred on
	// a no-auth inbound — are skipped.
	if n.Protocol == model.ProtoSOCKS || n.Protocol == model.ProtoHTTP {
		var accts []any
		seen := map[string]bool{}
		for _, cl := range clients {
			if cl.Username == "" || cl.Password == "" || seen[cl.Username] {
				continue
			}
			seen[cl.Username] = true
			accts = append(accts, jobj{"user": cl.Username, "pass": cl.Password})
		}
		if len(accts) == 0 {
			return // no credentialled users; keep the rendered (noauth/template) config
		}
		settings["accounts"] = accts
		if n.Protocol == model.ProtoSOCKS {
			settings["auth"] = "password"
		}
		return
	}
	var arr = []any{}
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
		case model.ProtoShadowsocks:
			// Only SS-2022 (2022-blake3-*) carries a per-user identity header, so
			// only it can authenticate distinct users. A non-2022 method is one
			// shared key for everyone — keep the rendered template untouched.
			if _, is2022 := model.KeySizeForMethod(n.Method); !is2022 {
				return
			}
			// The inbound keeps the SERVER PSK (settings.password); each client
			// gets its own derived user PSK keyed by email for per-user stats. A
			// client authenticates with "serverPSK:userPSK".
			arr = append(arr, jobj{"password": model.DeriveSSUserPSK(cl.Email, n.Method), "email": cl.Email})
		default:
			return
		}
	}
	settings["clients"] = arr
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
		case model.ProtoHysteria2:
			// sing-box hysteria2 users are {name, password} ONLY. A uuid field is
			// rejected by sing-box's strict decoder ("json: unknown field uuid"),
			// which fails the whole config load and takes the sing-box engine down —
			// so a hysteria2 inbound with any assigned user silently stops serving.
			// The name is still carried for per-user attribution in sing-box's logs.
			arr = append(arr, jobj{"password": cl.Password, "name": name})
		case model.ProtoTUIC:
			// sing-box tuic users are {name, uuid, password} — uuid is part of the
			// TUIC identity here, unlike hysteria2 above.
			arr = append(arr, jobj{"uuid": cl.UUID, "password": cl.Password, "name": name})
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
		case model.ProtoShadowsocks:
			// Only SS-2022 has a per-user identity header; a non-2022 method is a
			// single shared key, so leave the rendered inbound untouched.
			if _, is2022 := model.KeySizeForMethod(n.Method); !is2022 {
				return
			}
			// Inbound-level password stays the SERVER PSK; each user carries its
			// own derived PSK. sing-box requires the same "serverPSK:userPSK" from
			// the client. Seed the derivation on cl.Email so it matches xray and
			// the subscription exactly.
			arr = append(arr, jobj{"name": name, "password": model.DeriveSSUserPSK(cl.Email, n.Method)})
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

// egressHop parses and validates an upstream-hop URI, returning the node with
// its chain tag already set. Both engines share it so a hop means the same thing
// whichever core happens to serve the inbound that uses it.
func egressHop(uri string, index int) (*model.Node, error) {
	hop, err := parse.URI(uri)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the upstream hop: %w", err)
	}
	hop.Normalize()
	if err := hop.Validate(); err != nil {
		return nil, fmt.Errorf("upstream hop is not usable: %w", err)
	}
	// A distinct tag per upstream so several chains can coexist.
	hop.Tag = fmt.Sprintf("egress-%d", index)
	return hop, nil
}

// egressOutbound turns an upstream-hop URI into an Xray outbound.
//
// The URI is parsed with the panel's own link parser and rendered with its own
// outbound renderer, so a chain hop supports exactly the protocols and
// transports the panel already understands — including REALITY, XHTTP and the
// full TLS surface. Writing a second, chain-specific renderer here is how the
// two would drift and a hop would quietly lose its uTLS fingerprint or its
// REALITY short id.
func egressOutbound(uri string, index int) (jobj, error) {
	hop, err := egressHop(uri, index)
	if err != nil {
		return nil, err
	}
	out, err := render.XrayOutbound(hop)
	if err != nil {
		return nil, fmt.Errorf("cannot render the upstream hop: %w", err)
	}
	return out, nil
}

// singboxStatsSection enumerates what the v2ray stats collector must track.
//
// sing-box will not infer the list: with stats merely enabled it collects
// nothing and reports an empty result, which reads exactly like an idle server.
// Returning nil when there are no users is deliberate — a stats section that
// tracks nothing is the same silent hole in a different place.
func singboxStatsSection(specs []InboundSpec, inbounds []any, egress []any) jobj {
	seenUser := map[string]bool{}
	var users []string
	for _, sp := range specs {
		if sp.Node == nil || render.EngineFor(sp.Node.Protocol) != model.EngineSingBox {
			continue
		}
		for _, cl := range sp.Clients {
			name := strings.TrimSpace(cl.Email)
			if name == "" || seenUser[name] {
				continue
			}
			seenUser[name] = true
			users = append(users, name)
		}
	}
	if len(users) == 0 {
		return nil
	}
	sort.Strings(users) // deterministic, so a reload with no change produces no diff

	tags := func(list []any) []string {
		out := make([]string, 0, len(list))
		for _, e := range list {
			if m, ok := e.(jobj); ok {
				if t, _ := m["tag"].(string); t != "" {
					out = append(out, t)
				}
				continue
			}
			if m, ok := e.(map[string]any); ok {
				if t, _ := m["tag"].(string); t != "" {
					out = append(out, t)
				}
			}
		}
		sort.Strings(out)
		return out
	}

	return jobj{
		"enabled":   true,
		"users":     users,
		"inbounds":  tags(inbounds),
		"outbounds": append([]string{"direct"}, tags(egress)...),
	}
}
