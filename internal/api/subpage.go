package api

import (
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	qrcode "github.com/skip2/go-qrcode"
)

// qrSVG renders content as a self-contained, scalable SVG QR code (black modules
// on white, quiet zone included). SVG keeps the page tiny and crisp at any size
// with no client-side library — the phone's VPN app scans it to import. Returns
// "" on failure so a card simply shows no QR rather than breaking the page.
func qrSVG(content string) string {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return ""
	}
	bm := q.Bitmap()
	n := len(bm)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" width="150" height="150">`, n, n)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if bm[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// hostSubBase builds the absolute subscription URL (no format suffix) from the
// incoming request, so the landing page's links point back at this exact host and
// port. The panel serves TLS, so the scheme is https unless a reverse proxy in
// front terminated it and says otherwise.
func hostSubBase(c *gin.Context) string {
	scheme := "https"
	if p := c.GetHeader("X-Forwarded-Proto"); p == "http" {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host + "/sub/" + c.Param("token")
}

// isBrowserSubRequest reports whether a /sub request came from a human in a web
// browser rather than a proxy client, so we can serve a friendly landing page
// without ever handing a client the wrong body. It is deliberately conservative:
// it requires a browser-shaped User-Agent, an explicit text/html Accept, and the
// ABSENCE of any known proxy-client token — proxy clients do not ask for HTML.
func isBrowserSubRequest(ua, accept string) bool {
	if !strings.Contains(strings.ToLower(accept), "text/html") {
		return false
	}
	l := strings.ToLower(ua)
	if !strings.Contains(l, "mozilla") {
		return false
	}
	for _, c := range []string{
		"clash", "sing-box", "singbox", "v2ray", "nekobox", "nekoray", "hiddify",
		"shadowrocket", "stash", "loon", "quantumult", "surge", "v2box",
		"streisand", "karing", "flclash", "mihomo", "sfa", "sfi", "sft", "husi",
	} {
		if strings.Contains(l, c) {
			return false
		}
	}
	return strings.Contains(l, "chrome") || strings.Contains(l, "safari") ||
		strings.Contains(l, "firefox") || strings.Contains(l, "edg") || strings.Contains(l, "gecko")
}

// parseUserinfo pulls download/total/expire out of a Subscription-Userinfo header
// value ("upload=0; download=D; total=T; expire=E").
func parseUserinfo(s string) (used, total, expire int64) {
	for _, part := range strings.Split(s, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, _ := strconv.ParseInt(kv[1], 10, 64)
		switch kv[0] {
		case "download":
			used = n
		case "total":
			total = n
		case "expire":
			expire = n
		}
	}
	return
}

func humanBytes(b int64) string {
	const u = 1024.0
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	f := float64(b)
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	i := -1
	for f >= u && i < len(units)-1 {
		f /= u
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// subLandingPage renders the browser-facing subscription page: a usage summary
// and, per client family, a one-click import button plus a copy-the-link button.
// base is the subscription URL without a format suffix.
func subLandingPage(base, userinfo string) []byte {
	used, total, expire := parseUserinfo(userinfo)
	var usage string
	if total > 0 {
		usage = fmt.Sprintf("%s of %s (%d%%)", humanBytes(used), humanBytes(total), int(used*100/total))
	} else {
		usage = humanBytes(used) + " used · unlimited"
	}
	expiry := "never expires"
	if expire > 0 {
		expiry = "expires " + time.Unix(expire, 0).UTC().Format("2006-01-02")
	}

	enc := func(u string) string { return url.QueryEscape(u) }
	v2ray := base
	clash := base + "/clash"
	singbox := base + "/sing-box"
	xray := base + "/xray"

	// (title, subtitle, import-deep-link-or-empty, copy-url). The QR always
	// encodes the copy URL — the raw subscription link a client's "scan QR to
	// add" imports — so scanning gives that app the right format.
	cards := []struct{ name, sub, deep, copy string }{
		{"v2rayNG / NekoBox", "v2rayNG, NekoBox, v2rayN, V2Box", "", v2ray},
		{"Hiddify", "Hiddify Next", "hiddify://import/" + enc(v2ray), v2ray},
		{"Streisand", "Streisand (iOS/macOS)", "streisand://import/" + enc(v2ray), v2ray},
		{"Clash / Mihomo", "Clash Meta, FlClash, Stash", "clash://install-config?url=" + enc(clash) + "&name=ForgePanel", clash},
		{"sing-box", "sing-box, SFA, SFI, Karing", "sing-box://import-remote-profile?url=" + enc(singbox), singbox},
		{"Xray JSON", "clients that import a raw Xray config", "", xray},
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1"><title>ForgePanel — Subscription</title>`)
	b.WriteString(`<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0B0F17;color:#E5E7EB;font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:28px 18px}
h1{font-size:20px;margin:0 0 4px;display:flex;align-items:center;gap:10px}
.muted{color:rgba(255,255,255,.55)}
.usage{background:#141A24;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:16px 18px;margin:18px 0}
.usage .row{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px}
.card{background:#141A24;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:16px;display:flex;flex-direction:column;align-items:center;text-align:center}
.card h3{margin:0 0 2px;font-size:15px}
.card p{margin:0 0 12px;font-size:12px;color:rgba(255,255,255,.5)}
.qr{background:#fff;border-radius:10px;padding:8px;line-height:0;margin:0 0 12px}
.qr svg{display:block;width:150px;height:150px}
.btns{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}
a.btn,button.btn{appearance:none;border:0;cursor:pointer;font:inherit;font-weight:700;font-size:13px;padding:9px 12px;border-radius:9px;text-decoration:none;display:inline-block}
.btn.primary{background:#FF7A1A;color:#1a1204}
.btn.ghost{background:#1A2230;color:#fff;border:1px solid rgba(255,255,255,.1)}
.tip{margin-top:20px;font-size:12px;color:rgba(255,255,255,.45)}
code{background:#0F1420;padding:2px 6px;border-radius:6px;font-size:12px}
</style></head><body><div class="wrap">`)
	b.WriteString(`<h1>⚡ ForgePanel <span class="muted" style="font-size:13px;font-weight:400">subscription</span></h1>`)
	b.WriteString(`<div class="usage"><div class="row"><span>` + html.EscapeString(usage) + `</span><span class="muted">` + html.EscapeString(expiry) + `</span></div></div>`)
	b.WriteString(`<div class="grid">`)
	for _, c := range cards {
		b.WriteString(`<div class="card"><h3>` + html.EscapeString(c.name) + `</h3><p>` + html.EscapeString(c.sub) + `</p>`)
		// The QR encodes the raw sub link — scan it inside the app's "add by QR".
		if svg := qrSVG(c.copy); svg != "" {
			b.WriteString(`<div class="qr" title="Scan in your VPN app to import">` + svg + `</div>`)
		}
		b.WriteString(`<div class="btns">`)
		if c.deep != "" {
			b.WriteString(`<a class="btn primary" href="` + html.EscapeString(c.deep) + `">Import</a>`)
		}
		b.WriteString(`<button class="btn ghost" data-copy="` + html.EscapeString(c.copy) + `">Copy link</button>`)
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	b.WriteString(`<p class="tip">On your phone: open your VPN app, choose “add subscription / import from QR”, and scan the code for your app. On a computer: tap <b>Import</b> to open the app, or <b>Copy link</b> and paste it in. Your link is private — do not share it.</p>`)
	b.WriteString(`<script>
document.querySelectorAll('button[data-copy]').forEach(function(el){
  el.addEventListener('click',function(){
    var t=el.getAttribute('data-copy');
    (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){
      var o=el.textContent;el.textContent='Copied ✓';setTimeout(function(){el.textContent=o},1400);
    }).catch(function(){window.prompt('Copy this subscription link:',t)});
  });
});
</script></div></body></html>`)
	return []byte(b.String())
}
