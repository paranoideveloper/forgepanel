package api

import (
	"net/url"
	"strings"

	"github.com/forgepanel/forgepanel/internal/config"
)

// stampDesync adds PingNG's Desync fields — png, and pngargs for a Custom
// profile — to a VLESS or Trojan link whose security is a TLS hello (tls or
// reality), the only traffic ByeDPI's --proto=tls acts on. Every other link,
// base64 VMess included, is returned unchanged, as is every link when d is the
// zero value (any deployment that is not Railway).
//
// The fields are appended to the raw query instead of re-encoding it, and must
// be applied AFTER applyPattern, which does re-encode: url.Values.Encode writes
// a space as '+', and PingNG decodes '+' as a literal plus, so a re-encoded
// pngargs reaches ByeDPI as one unparseable argument.
func stampDesync(uri string, d config.Desync) string {
	if d.Profile == "" {
		return uri
	}
	if !strings.HasPrefix(uri, "vless://") && !strings.HasPrefix(uri, "trojan://") {
		return uri
	}
	body, frag := uri, ""
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		body, frag = uri[:i], uri[i:]
	}
	q := strings.IndexByte(body, '?')
	if q < 0 {
		return uri
	}
	vals, err := url.ParseQuery(body[q+1:])
	if err != nil || vals.Has("png") {
		return uri
	}
	if sec := vals.Get("security"); sec != "tls" && sec != "reality" {
		return uri
	}
	body += "&png=" + uriComponent(d.Profile)
	if d.Profile == "Custom" && d.Args != "" {
		body += "&pngargs=" + uriComponent(d.Args)
	}
	return body + frag
}

// uriComponent escapes a query value the way PingNG decodes it: '+' becomes
// %2B, a space %20 and '=' %3D. PingNG takes a field's value as the text
// between its first and second '=', so a bare '=' cuts --proto=tls short, and
// it maps '+' to a literal plus before decoding, so url.QueryEscape's '+' for a
// space would survive as a plus.
func uriComponent(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
