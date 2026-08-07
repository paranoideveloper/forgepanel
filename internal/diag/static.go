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

	// REALITY shortId hex length (<=16, even).
	if n.Security.Type == model.SecReality && n.Security.Reality != nil {
		for _, sid := range n.Security.Reality.ShortIDs {
			if !validShortID(sid) {
				f = append(f, New("FP-REALITY-002", sid))
				break
			}
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
