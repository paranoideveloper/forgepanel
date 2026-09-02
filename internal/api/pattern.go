package api

import (
	"net/url"
	"strings"
)

// The "pattern" (patterniha) variant adds Xray's unsafe-uTLS anti-DPI knobs to a
// VLESS/Trojan/VMess link: a custom cipher-suite list (cs), the two-stage TLS
// fragment (fm), and fp=unsafe. Critically, fp=unsafe ships NO ciphers of its
// own — it sends exactly what cs= lists — so cs MUST always accompany it, which
// is the single thing that made the hand-rolled configs fail. These defaults are
// the community "patterniha" preset; only recent Xray cores (v2rayNG ≥ 1.9,
// v2rayN, Husi) read them, older clients ignore the extra params harmlessly.
const (
	patternCS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:" +
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	// Compact JSON (no whitespace) so URL-encoding is clean and unambiguous; the
	// client parses it identically to the spaced form.
	patternFM = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],"delays":["0"],"maxSplit":"0"}},` +
		`{"type":"fragment","settings":{"packets":"1-1","lengths":["109","1"],"delays":["1"],"maxSplit":"355"}}]}`
)

// applyPattern rewrites a VLESS/Trojan/VMess (URI form) link that uses TLS to add
// the unsafe-uTLS pattern params. Links that are not TLS, or are base64 VMess
// (no query), are returned unchanged.
func applyPattern(uri string) string {
	if !strings.HasPrefix(uri, "vless://") &&
		!strings.HasPrefix(uri, "trojan://") &&
		!strings.HasPrefix(uri, "vmess://") {
		return uri
	}
	body, frag := uri, ""
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		body, frag = uri[:i], uri[i:]
	}
	q := strings.IndexByte(body, '?')
	if q < 0 {
		return uri // base64 VMess or no query — nothing to stamp
	}
	head, query := body[:q], body[q+1:]
	vals, err := url.ParseQuery(query)
	if err != nil || vals.Get("security") != "tls" {
		return uri
	}
	vals.Set("fp", "unsafe")
	vals.Set("cs", patternCS)
	vals.Set("fm", patternFM)
	return head + "?" + vals.Encode() + frag
}

// tagRemark appends " · Patt" to a link's #remark so a "both" subscription can be
// told apart in the client's server list.
func tagRemark(uri string) string {
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		return uri + url.PathEscape(" · Patt")
	}
	return uri + "#" + url.PathEscape("Patt")
}

// patternMode is how a subscription should emit links: normal, pattern-only, or
// both (each node once normal + once patterned).
type patternMode int

const (
	patternOff  patternMode = iota // normal links only
	patternOnly                    // every applicable link patterned
	patternBoth                    // normal + patterned copy of each node
)

// parsePatternMode reads ?patt= (1/on/true = only, both = both), falling back to
// the operator default.
func parsePatternMode(q string, dflt patternMode) patternMode {
	switch strings.ToLower(strings.TrimSpace(q)) {
	case "1", "on", "true", "yes", "patt", "only":
		return patternOnly
	case "both", "2":
		return patternBoth
	case "0", "off", "false", "no", "normal":
		return patternOff
	}
	return dflt
}
