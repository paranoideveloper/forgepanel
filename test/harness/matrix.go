//go:build harness

// matrix.go declares what the harness attempts to prove. A Case is one
// protocol × transport × security combination (or one policy rule), together
// with the payload the panel is asked to create and the probes that must pass.
//
// The list is deliberately data, not code: the results file is a direct
// projection of it, so "which combinations are proven" is answerable by reading
// one table rather than by reading the runner.
package harness

import "fmt"

// Expectation of a case: does traffic have to flow, or has to be refused.
type Expectation string

const (
	// ExpectAllow means a client built from the emitted config must carry traffic.
	ExpectAllow Expectation = "allow"
	// ExpectDeny means the tunnel must refuse — used for the policy cases.
	ExpectDeny Expectation = "deny"
)

// Case is one row of the connectivity matrix.
type Case struct {
	ID        string      `json:"id"`
	Protocol  string      `json:"protocol"`
	Transport string      `json:"transport"`
	Security  string      `json:"security"`
	Method    string      `json:"method,omitempty"` // shadowsocks cipher
	Expect    Expectation `json:"expect"`
	// Policy names the lifecycle rule a deny-case exercises. Empty for
	// connectivity cases.
	Policy string `json:"policy,omitempty"`
	// UDP requests the DNS-through-the-tunnel probe in addition to the TCP one.
	UDP bool `json:"udp"`
	// Extra merges into the created node, for knobs the combination needs.
	Extra map[string]any `json:"-"`
	// Why documents a combination the panel itself declares unsupported, so the
	// results file explains a red cell rather than just showing one.
	Why string `json:"why,omitempty"`
}

// Engine is the core the panel routes this protocol to. It mirrors
// render.EngineFor; the harness keeps its own copy so the results file can be
// grouped by engine without importing the renderer.
func (c Case) Engine() string {
	switch c.Protocol {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http":
		return "xray"
	case "hysteria2", "tuic", "anytls", "shadowtls", "ssh", "wireguard":
		return "sing-box"
	case "brook":
		return "brook"
	case "amneziawg":
		return "amneziawg"
	default:
		return "unknown"
	}
}

// InboundPayload builds the model.Node JSON the panel's create endpoint takes.
// Address is deliberately omitted: the panel defaults it to 0.0.0.0 and
// substitutes the reachable host at export time, which is the path a real
// operator uses and therefore the one worth testing.
func (c Case) InboundPayload(port int, realityDest string) map[string]any {
	n := map[string]any{
		"remark":   c.ID,
		"protocol": c.Protocol,
		"port":     port,
	}
	transport := map[string]any{"network": c.Transport}
	switch c.Transport {
	case "ws", "httpupgrade":
		transport["path"] = "/" + c.Protocol + "-probe"
	case "xhttp":
		transport["path"] = "/" + c.Protocol + "-probe"
		transport["xhttp_mode"] = "auto"
	case "grpc":
		transport["service_name"] = "HarnessProbe"
	}
	n["transport"] = transport

	security := map[string]any{"type": c.Security}
	if c.Security == "reality" && realityDest != "" {
		host := realityDest
		for i := 0; i < len(realityDest); i++ {
			if realityDest[i] == ':' {
				host = realityDest[:i]
				break
			}
		}
		security["server_name"] = host
		security["reality"] = map[string]any{
			"dest":         realityDest,
			"server_names": []string{host},
		}
	}
	n["security"] = security

	if c.Protocol == "shadowsocks" && c.Method != "" {
		n["method"] = c.Method
	}
	for k, v := range c.Extra {
		n[k] = v
	}
	return n
}

// ConnectivityCases is the standard matrix: every protocol the panel offers,
// every transport it claims for the Xray family, and every security layer that
// is legal for that transport. It is the set run by default.
func ConnectivityCases() []Case {
	var out []Case
	add := func(c Case) {
		if c.ID == "" {
			c.ID = fmt.Sprintf("%s/%s/%s", c.Protocol, c.Transport, c.Security)
		}
		if c.Expect == "" {
			c.Expect = ExpectAllow
		}
		out = append(out, c)
	}

	// --- VLESS: the full legal transport × security grid. ------------------
	// REALITY is legal only over raw TCP, XHTTP and gRPC (model.Validate).
	for _, tr := range []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"} {
		for _, sec := range []string{"none", "tls", "reality"} {
			if sec == "reality" && tr != "tcp" && tr != "grpc" && tr != "xhttp" {
				continue
			}
			add(Case{Protocol: "vless", Transport: tr, Security: sec, UDP: tr == "tcp"})
		}
	}
	// VLESS + Vision is the panel's default for REALITY over raw TCP; assert the
	// non-Vision variant explicitly too, since flow changes the wire format.
	add(Case{ID: "vless/tcp/reality-noflow", Protocol: "vless", Transport: "tcp", Security: "reality",
		Extra: map[string]any{"flow": ""}, UDP: true})

	// --- VMess ------------------------------------------------------------
	for _, tr := range []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"} {
		for _, sec := range []string{"none", "tls"} {
			add(Case{Protocol: "vmess", Transport: tr, Security: sec, UDP: tr == "ws"})
		}
	}

	// --- Trojan (TLS by design, but the panel permits security=none) -------
	for _, tr := range []string{"tcp", "ws", "grpc", "xhttp"} {
		add(Case{Protocol: "trojan", Transport: tr, Security: "tls", UDP: tr == "tcp"})
	}
	add(Case{Protocol: "trojan", Transport: "tcp", Security: "none"})

	// --- Shadowsocks: one case per cipher family the panel advertises ------
	for _, m := range []string{
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
		"aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	} {
		add(Case{ID: "shadowsocks/tcp/none/" + m, Protocol: "shadowsocks", Transport: "tcp",
			Security: "none", Method: m, UDP: m == "2022-blake3-aes-128-gcm"})
	}

	// --- Plain proxies -----------------------------------------------------
	add(Case{Protocol: "socks", Transport: "tcp", Security: "none", UDP: true})
	add(Case{Protocol: "http", Transport: "tcp", Security: "none"})

	// --- QUIC / sing-box protocols ----------------------------------------
	// Hysteria2 and TUIC are QUIC, so every byte they carry — including the TCP
	// payload probe — already travels over UDP; the DNS probe additionally
	// proves UDP relay *inside* the tunnel.
	add(Case{Protocol: "hysteria2", Transport: "tcp", Security: "tls", UDP: true})
	add(Case{ID: "hysteria2/tcp/tls+salamander", Protocol: "hysteria2", Transport: "tcp", Security: "tls", UDP: true,
		Extra: map[string]any{"hysteria2": map[string]any{"obfs_type": "salamander", "obfs_password": "harness-obfs"}}})
	add(Case{Protocol: "tuic", Transport: "tcp", Security: "tls", UDP: true})
	add(Case{Protocol: "anytls", Transport: "tcp", Security: "tls", UDP: true})
	add(Case{Protocol: "shadowtls", Transport: "tcp", Security: "none", UDP: true})

	// --- Protocols with no client leg the panel can hand out --------------
	// These are attempted, not assumed: the runner records what actually
	// happens (create rejected, engine skipped, or client core refuses).
	add(Case{Protocol: "ssh", Transport: "tcp", Security: "none"})
	add(Case{Protocol: "wireguard", Transport: "tcp", Security: "none"})
	add(Case{Protocol: "brook", Transport: "tcp", Security: "none"})
	add(Case{Protocol: "amneziawg", Transport: "tcp", Security: "none"})

	// --- Transports the model rejects outright ----------------------------
	// Asserting the rejection is part of the contract: a panel that silently
	// accepted these would ship an unstartable engine config.
	for _, tr := range []string{"h2", "quic", "kcp"} {
		add(Case{Protocol: "vless", Transport: tr, Security: "none",
			Why: "removed in Xray 26; model.Validate must refuse it at create time"})
	}
	return out
}

// PolicyCases are the enforcement rules: an account or inbound that should stop
// carrying traffic. Each one first proves the tunnel works, then applies the
// change and proves it stops.
func PolicyCases() []Case {
	base := func(id, policy string) Case {
		return Case{ID: id, Protocol: "vless", Transport: "tcp", Security: "reality",
			Expect: ExpectDeny, Policy: policy}
	}
	return []Case{
		base("policy/user-disabled", "user-disabled"),
		base("policy/user-expired", "user-expired"),
		base("policy/user-over-quota", "user-over-quota"),
		base("policy/inbound-disabled", "inbound-disabled"),
		base("policy/inbound-removed", "inbound-removed"),
		base("policy/wrong-credential", "wrong-credential"),
		base("policy/sub-token-unknown", "sub-token-unknown"),
	}
}

// QuickCases is the smoke subset: the five paths that must never regress, one
// per engine/transport family, used for fast iteration and PR gating.
func QuickCases() []Case {
	want := map[string]bool{
		"vless/tcp/reality": true,
		"trojan/tcp/tls":    true,
		"shadowsocks/tcp/none/2022-blake3-aes-128-gcm": true,
		"vmess/ws/none":     true,
		"hysteria2/tcp/tls": true,
	}
	var out []Case
	for _, c := range ConnectivityCases() {
		if want[c.ID] {
			out = append(out, c)
		}
	}
	return out
}
