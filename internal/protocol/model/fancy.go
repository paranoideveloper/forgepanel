package model

import "strings"

// Fancy config generation: the operator picks a fronting domain and one of the
// styled "themes" below, and every node in the subscription is (a) renamed with
// the theme's emoji/Persian/bold remark and (b) fronted per the theme's model.
//
// This is the engine behind the fancy-config wizard. It is deliberately a set of
// pure functions over *Node so it is testable outside the HTTP layer and shares
// the exact same node → link path the rest of the subscription uses — a fancy
// config is a normal config with a nicer name and a camouflage domain, nothing
// more.

// FrontMode is how a theme applies the operator's fronting domain to a node.
type FrontMode string

const (
	// FrontNone leaves the node's addressing untouched — for raw-IP themes
	// (e.g. SS-2022 direct) where there is no domain to hide behind.
	FrontNone FrontMode = "none"
	// FrontSNI is Host + SNI camouflage: the client still dials the node's real
	// address but presents the fronting domain as the TLS SNI and the transport
	// Host header. Works on any server that does not pin its SNI, and on REALITY
	// (whose client serverName is a borrowed site anyway). This is the common
	// "Iranian-domain camouflage" case (aparat/nobat/… Reality + XHTTP + Vision).
	FrontSNI FrontMode = "sni"
	// FrontCDN is full domain-fronting: set only the transport Host header to the
	// fronting domain and route by it through a Host-aware CDN, leaving the
	// security layer as the inbound defined it (often plaintext WS behind a
	// domestic CDN, e.g. the taskulu.com VMess examples). The real address stays.
	FrontCDN FrontMode = "cdn"
)

// ParseFrontMode maps a string to a FrontMode, defaulting to FrontSNI for any
// non-empty unknown value (camouflage is the safe default) and FrontNone for "".
func ParseFrontMode(s string) FrontMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "off":
		return FrontNone
	case "cdn", "front", "domain-front", "domainfront":
		return FrontCDN
	default:
		return FrontSNI
	}
}

// ApplyFront rewrites n so it fronts behind frontDomain per mode. It mutates
// only the camouflage-relevant fields and never the credentials or the real
// dial address, so the node still reaches the same server. A blank domain or
// FrontNone is a no-op.
func ApplyFront(n *Node, frontDomain string, mode FrontMode) {
	d := strings.TrimSpace(frontDomain)
	if n == nil || d == "" || mode == FrontNone {
		return
	}

	// The Host header (and, for h2/gRPC, the authority) rides the fronting
	// domain wherever the transport actually carries one. tcp/kcp/quic do not.
	switch n.Transport.Network {
	case NetWS, NetHTTPUpgrade, NetH2, NetGRPC, NetXHTTP:
		n.Transport.Host = d
	}

	if mode == FrontSNI {
		// Present the fronting domain in the handshake. For real TLS this is the
		// SNI; for REALITY the client serverName is the borrowed site, so the
		// fronting domain becomes the site it impersonates. SecNone has no
		// handshake to camouflage, so it only gets the Host header above.
		if n.Security.Type == SecTLS || n.Security.Type == SecReality {
			n.Security.ServerName = d
		}
	}
}

// FancyTheme is one styled naming preset. Template is a name-template string (it
// interpolates the same {NAME}/{FLAG}/… tokens ExpandNameTemplate understands),
// and Front is the fronting model the theme is built for. Proto is a hint for
// the UI so a theme can be suggested for the matching inbound protocol; it does
// not restrict where a theme may be applied.
type FancyTheme struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Template string    `json:"template"`
	Front    FrontMode `json:"front"`
	Proto    string    `json:"proto"`
	Sample   string    `json:"sample"`
}

// fancyThemes is the curated catalogue, modelled on the styles Iranian channels
// actually ship (aparat/nobat/taskulu/snapp/baman/akharin camouflage). {NAME} is
// the inbound's own short remark (e.g. "s3"), appended after the styled brand.
var fancyThemes = []FancyTheme{
	// VMess-WS domestic-CDN fronting (plaintext WS behind a Host-routing CDN).
	{ID: "taskulu-ws", Label: "Taskulu · WS front", Front: FrontCDN, Proto: "vmess",
		Template: "🇮🇷 taskulu-front | @free · {NAME}"},
	{ID: "baman-ws", Label: "Baman · WS", Front: FrontCDN, Proto: "vmess",
		Template: "🐏 𝐁𝐚𝐦𝐚𝐧 𝐖𝐒 📡 @v2rayng_iran · {NAME}"},
	{ID: "nobat-ws", Label: "Nobat · WS Domestic", Front: FrontCDN, Proto: "vmess",
		Template: "👉🆔 𝐍𝐨𝐛𝐚𝐭 𝐖𝐒 ©️ Domestic · {NAME}"},
	{ID: "vmess-aparat", Label: "Aparat · VMess", Front: FrontSNI, Proto: "vmess",
		Template: "🇮🇷𝐕𝐌𝐞𝐬𝐬➤𝐀𝐩𝐚𝐫𝐚𝐭📡®️ · {NAME}"},
	{ID: "aparat-line", Label: "Aparat-line", Front: FrontSNI, Proto: "vmess",
		Template: "🇮🇷✨ آپارات‑لاین ✨🇮🇷 · {NAME}"},
	{ID: "snapp-camo", Label: "Snapp · camouflage", Front: FrontSNI, Proto: "vmess",
		Template: "🚕💨 اسنپ‑کاموفلاژ 💨🚕 · {NAME}"},
	{ID: "join-free", Label: "Join · @free", Front: FrontSNI, Proto: "vmess",
		Template: "♾️𝗝𝗼𝗶𝗻➠🆔@free 🇮🇷384🌐 · {NAME}"},

	// VLESS-XHTTP (Reality) camouflage.
	{ID: "nobat-xhttp", Label: "Nobat · XHTTP", Front: FrontSNI, Proto: "vless",
		Template: "🚀 nobat-xhttp 🅿️ed · {NAME}"},
	{ID: "eshkaftak-xhttp", Label: "Eshkaftak · XHTTP", Front: FrontSNI, Proto: "vless",
		Template: "🦅 اِشکفتک〜XHTTP 🦅 · {NAME}"},
	{ID: "aparat-xhttp", Label: "Aparat · XHTTP ParsPack", Front: FrontSNI, Proto: "vless",
		Template: "🇮🇷 𝐀𝐩𝐚𝐫𝐚𝐭 𝐗𝐇𝐓𝐓𝐏 ®️ ParsPack · {NAME}"},
	{ID: "taskulu-xhttp", Label: "Taskulu · XHTTP", Front: FrontSNI, Proto: "vless",
		Template: "🕊️ 𝐓𝐚𝐬𝐤𝐮𝐥𝐮 ✦ XHTTP ✦ 🇮🇷 · {NAME}"},
	{ID: "akharin-xhttp", Label: "Akharin · XHTTP", Front: FrontSNI, Proto: "vless",
		Template: "📰 𝐀𝐤𝐡𝐚𝐫𝐢𝐧 🔵 XHTTP 🇮🇷 · {NAME}"},
	{ID: "baman-xh", Label: "Baman · XH @freenet", Front: FrontSNI, Proto: "vless",
		Template: "🌙 𝐁𝐚𝐦𝐚𝐧 ✦ 𝐗𝐇 ✦ @freenet · {NAME}"},
	{ID: "xh-camo", Label: "XH · Camo Domestic", Front: FrontSNI, Proto: "vless",
		Template: "🕊️𝐗𝐇➤𝐂𝐚𝐦𝐨📰®️Domestic · {NAME}"},

	// VLESS-Vision (Reality) camouflage.
	{ID: "vision-aparat", Label: "Aparat · Vision 443", Front: FrontSNI, Proto: "vless",
		Template: "🇮🇷 𝐕𝐢𝐬𝐢𝐨𝐧 ✦ 𝐀𝐩𝐚𝐫𝐚𝐭 ✦ 443 ®️ · {NAME}"},
	{ID: "nobat-vision", Label: "Nobat · Vision", Front: FrontSNI, Proto: "vless",
		Template: "🔵 𝐍𝐨𝐛𝐚𝐭 𝐕𝐢𝐬𝐢𝐨𝐧 🇮🇷 ©️ · {NAME}"},

	// SS-2022 raw-IP (no fronting).
	{ID: "ss2022-parspack", Label: "SS-2022 · ParsPack", Front: FrontNone, Proto: "shadowsocks",
		Template: "🐏 𝐒𝐒-𝟐𝟎𝟐𝟐 ✦ ParsPack ✦ 🇮🇷 · {NAME}"},
	{ID: "ss2022-raw", Label: "SS-2022 · raw-ip", Front: FrontNone, Proto: "shadowsocks",
		Template: "🇮🇷 SS2022 raw-ip ☃️ · {NAME}"},
}

// FancyThemes returns the catalogue with the {NAME} token expanded to a sample
// node label, so the UI can preview each style without a live node.
func FancyThemes() []FancyTheme {
	out := make([]FancyTheme, len(fancyThemes))
	for i, t := range fancyThemes {
		t.Sample = ExpandNameTemplate(t.Template, NameFields{Name: "s3"})
		out[i] = t
	}
	return out
}

// FancyThemeByID returns the theme with the given id and whether it was found.
func FancyThemeByID(id string) (FancyTheme, bool) {
	id = strings.TrimSpace(id)
	for _, t := range fancyThemes {
		if t.ID == id {
			return t, true
		}
	}
	return FancyTheme{}, false
}
