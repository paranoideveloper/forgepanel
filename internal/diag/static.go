package diag

import (
	"encoding/base64"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// StaticValidate runs the instant, offline checks (§3 Layer 1) against one
// inbound and returns coded findings. It never calls the network; environment
// probes and live proof are separate layers. usedPorts maps a port to the remark
// of an inbound already using it (excluding this one) so port conflicts surface.
func StaticValidate(n *model.Node, usedPorts map[int]string) []Finding {
	var f []Finding

	// Port sanity + conflicts.
	if n.Port < 1 || n.Port > 65535 {
		f = append(f, New("FP-PORT-001", "port "+itoa(n.Port)))
	} else if who, clash := usedPorts[n.Port]; clash && who != "" {
		f = append(f, New("FP-PORT-002", "port "+itoa(n.Port)+" also used by "+who))
	}

	// Never present plaintext as secure.
	if n.IsPlaintext() {
		f = append(f, New("FP-TLS-002", n.Remark))
	}

	// TLS without a cert-bearing domain/SNI (best-effort: no domain and no SNI).
	if n.Security.Type == model.SecTLS && strings.TrimSpace(n.Domain) == "" && n.Security.ServerName == "" {
		f = append(f, New("FP-TLS-001", "no domain or SNI set"))
	}

	// vision flow legality: TCP + TLS/REALITY only.
	if n.Flow == "xtls-rprx-vision" {
		tcp := n.Transport.Network == model.NetTCP || n.Transport.Network == ""
		sec := n.Security.Type == model.SecTLS || n.Security.Type == model.SecReality
		if !tcp || !sec {
			f = append(f, New("FP-FLOW-001", "flow with transport="+string(n.Transport.Network)+" security="+string(n.Security.Type)))
		}
	}

	// REALITY dest sanity. Whether the dest actually speaks TLS 1.3 can only be
	// learned by dialling it, which this offline layer never does — but a dest
	// that is missing or is not host:port is the far more common mistake, and it
	// is fully checkable here. Xray simply omits an empty dest from the inbound
	// and then refuses to start, which surfaces as "the core keeps restarting".
	if n.Security.Type == model.SecReality {
		if dest := realityDest(n); dest == "" {
			f = append(f, New("FP-REALITY-001", "no dest set"))
		} else if !hostPortShaped(dest) {
			f = append(f, New("FP-REALITY-001", "dest "+dest+" is not host:port"))
		}
	}

	// REALITY shortId hex length (<=16, even).
	if n.Security.Type == model.SecReality && n.Security.Reality != nil {
		for _, sid := range n.Security.Reality.ShortIDs {
			if !validShortID(sid) {
				f = append(f, New("FP-REALITY-002", sid))
				break
			}
		}
	}

	// Hysteria2 port hopping: the hop range is handed to the client, which will
	// send traffic to every port in it. Any port another inbound is listening on
	// is therefore stolen from that inbound, and both ends break intermittently
	// — the worst kind of bug to chase, because it only bites after a hop.
	if n.Hysteria2 != nil && n.Hysteria2.PortHopping != "" {
		// Map iteration is unordered, so the lowest clashing port is picked
		// deliberately: the detail line must not change between two runs on
		// identical data, or operators cannot tell one report from another.
		best, bestWho, bestRange := 0, "", hopRange{}
		for _, r := range parseHopRanges(n.Hysteria2.PortHopping) {
			for port, who := range usedPorts {
				if who == "" || port < r.lo || port > r.hi {
					continue
				}
				if best == 0 || port < best {
					best, bestWho, bestRange = port, who, r
				}
			}
		}
		if best != 0 {
			f = append(f, New("FP-PORT-HOP-001",
				"hop range "+itoa(bestRange.lo)+"-"+itoa(bestRange.hi)+" covers port "+itoa(best)+" used by "+bestWho))
		}
	}

	// SS2022 PSK length vs method.
	if n.Protocol == model.ProtoShadowsocks && strings.HasPrefix(n.Method, "2022-") {
		if want := ss2022KeyLen(n.Method); want > 0 {
			if raw, err := base64.StdEncoding.DecodeString(n.Password); err != nil || len(raw) != want {
				f = append(f, New("FP-KEY-001", n.Method))
			}
		}
	}

	// UDP-based protocols: flag that UDP must be permitted (environment layer
	// confirms; static layer surfaces the dependency).
	if n.Protocol.IsQUICBased() || n.Protocol == model.ProtoWireGuard {
		f = append(f, New("FP-UDP-001", string(n.Protocol)))
	}

	return f
}

// realityDest returns the REALITY handshake destination, or "" when none is set.
func realityDest(n *model.Node) string {
	if n.Security.Reality == nil {
		return ""
	}
	return strings.TrimSpace(n.Security.Reality.Dest)
}

// hostPortShaped reports whether s looks like host:port — the only form the
// cores accept for a REALITY dest. It deliberately does not resolve anything.
func hostPortShaped(s string) bool {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return false
	}
	host, port := s[:i], s[i+1:]
	// An IPv6 literal must be bracketed, otherwise its own colons read as the
	// port separator.
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return p >= 1 && p <= 65535
}

// hopRange is one inclusive port range from a Hysteria2 port-hopping spec.
type hopRange struct{ lo, hi int }

// parseHopRanges reads a Hysteria2 port-hopping spec — comma-separated single
// ports and "lo-hi" ranges, e.g. "20000-50000,60000" — and returns the ranges
// it could make sense of. Unparseable pieces are skipped rather than guessed at:
// this check exists to report a real overlap, not to re-validate the field.
func parseHopRanges(spec string) []hopRange {
	var out []hopRange
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		lo, hi, isRange := strings.Cut(part, "-")
		a, okA := atoiPort(lo)
		if !okA {
			continue
		}
		if !isRange {
			out = append(out, hopRange{a, a})
			continue
		}
		b, okB := atoiPort(hi)
		if !okB || b < a {
			continue
		}
		out = append(out, hopRange{a, b})
	}
	return out
}

func atoiPort(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

func validShortID(s string) bool {
	if len(s) == 0 || len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func ss2022KeyLen(method string) int {
	switch {
	case strings.Contains(method, "aes-128"):
		return 16
	case strings.Contains(method, "aes-256"), strings.Contains(method, "chacha20"):
		return 32
	}
	return 0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
