// Package diag is ForgePanel's Validation & Proof engine (round-2 §3). It turns
// every problem the panel can detect into a structured Finding with a stable
// code, a severity, plain-language English AND Farsi text, the reason it matters,
// the exact fix, and — where possible — a machine-applicable FixAction the UI can
// wire to a one-click "Fix It" button. Raw errors are never shown to the user;
// they are logged separately.
package diag

// Severity ranks a finding. The UI colours and sorts by it; nothing is signalled
// by colour alone (each finding also carries text).
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Finding is one diagnostic result. Code is stable and searchable
// (docs/DIAGNOSTICS.md); TitleEN/TitleFA are one-line summaries; Why explains the
// impact; Fix is the exact remedy; FixAction, when non-empty, names an action the
// panel can apply automatically.
type Finding struct {
	Code      string   `json:"code"`
	Severity  Severity `json:"severity"`
	TitleEN   string   `json:"title_en"`
	TitleFA   string   `json:"title_fa"`
	Why       string   `json:"why"`
	Fix       string   `json:"fix"`
	FixAction string   `json:"fix_action,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// catalogEntry is a code's fixed metadata; a Finding is an instance of one.
type catalogEntry struct {
	Severity Severity
	TitleEN  string
	TitleFA  string
	Why      string
	Fix      string
	Action   string
}

// Catalogue is the stable registry of every diagnostic code. Adding a check
// means adding an entry here first, so docs/DIAGNOSTICS.md and the UI stay in
// sync and every code is documented.
var Catalogue = map[string]catalogEntry{
	"FP-PORT-001": {SevCritical, "Port out of range", "پورت خارج از محدوده",
		"A TCP/UDP port must be between 1 and 65535; the core will refuse to start.",
		"Choose a port between 1 and 65535.", ""},
	"FP-PORT-002": {SevCritical, "Port already in use by another inbound", "پورت توسط ورودی دیگری استفاده شده",
		"Two inbounds cannot bind the same port; the second fails to start and its users cannot connect.",
		"Pick a free port, or hop this protocol onto a different one.", ""},
	"FP-TLS-001": {SevWarning, "TLS enabled but no certificate for this SNI", "TLS فعال است اما گواهی برای این SNI وجود ندارد",
		"Without a matching certificate the panel serves a self-signed one, and strict clients reject the connection.",
		"Register the domain and enable one-click ACME, or import a certificate.", "issue_acme"},
	"FP-TLS-002": {SevCritical, "Plaintext inbound presented as secure", "ورودی بدون رمز به‌عنوان امن نمایش داده شده",
		"security=none over a cleartext transport carries traffic in the clear; showing it as secure misleads the operator and exposes users.",
		"Switch to REALITY (no domain needed) or enable TLS on a domain.", "convert_reality"},
	"FP-REALITY-001": {SevCritical, "REALITY dest missing or not TLS 1.3", "مقصد REALITY نامعتبر یا بدون TLS 1.3",
		"REALITY borrows the dest site's TLS 1.3 handshake; a dest that is not reachable on TLS 1.3 breaks the handshake.",
		"Point dest at a site that serves TLS 1.3 (e.g. www.cloudflare.com:443).", ""},
	"FP-REALITY-002": {SevCritical, "Invalid REALITY shortId length", "طول shortId نامعتبر است",
		"shortId must be an even-length hex string of at most 16 characters (8 bytes) or the client cannot authenticate.",
		"Regenerate the shortId.", "regen_shortid"},
	"FP-FLOW-001": {SevCritical, "xtls-rprx-vision requires TCP + TLS/REALITY", "vision فقط با TCP و TLS/REALITY کار می‌کند",
		"The vision flow is only valid over raw TCP with TLS or REALITY; other transports produce a config the core rejects.",
		"Remove the flow, or set transport=tcp with TLS/REALITY.", "clear_flow"},
	"FP-KEY-001": {SevCritical, "Shadowsocks-2022 key length wrong for method", "طول کلید SS2022 با روش هم‌خوان نیست",
		"SS2022 requires a base64 PSK whose decoded length matches the method (16 bytes for aes-128, 32 for aes-256/chacha20).",
		"Regenerate the pre-shared key for the chosen method.", "regen_psk"},
	"FP-CLOCK-001": {SevCritical, "System clock is out of sync", "ساعت سیستم هماهنگ نیست",
		"REALITY and TLS reject handshakes when the clock skews more than a few seconds — a classic silent failure.",
		"Enable NTP (timedatectl set-ntp true) and resync.", ""},
	"FP-UDP-001": {SevWarning, "UDP may be blocked for this protocol", "ممکن است UDP برای این پروتکل مسدود باشد",
		"Hysteria2/TUIC/WireGuard/QUIC need UDP; if the host firewall drops it, clients silently fail to connect.",
		"Open the UDP port on the host firewall.", ""},
	"FP-PORT-HOP-001": {SevWarning, "Hysteria2 port-hop range overlaps another inbound", "بازهٔ پرش پورت با ورودی دیگری هم‌پوشانی دارد",
		"An overlapping hop range steals ports from another inbound, breaking one or both.",
		"Choose a hop range that does not overlap other inbounds.", ""},
	"FP-DNS-001": {SevWarning, "Domain does not resolve to this server", "دامنه به این سرور اشاره نمی‌کند",
		"ACME cannot issue a certificate and clients dialing the domain will not reach this server.",
		"Point the domain's A/AAAA record at this server's public IP.", ""},
	"FP-VERIFY-OK": {SevInfo, "Verified — traffic proven end to end", "تأیید شد — عبور ترافیک اثبات شد",
		"A real client core connected through this inbound and carried traffic.",
		"", ""},
	"FP-VERIFY-FAIL": {SevCritical, "Verification failed — no traffic carried", "تأیید ناموفق — ترافیکی عبور نکرد",
		"A real client core could not carry traffic through this inbound, so it will not work for users.",
		"Open the captured client log, fix the reported cause, and re-verify.", ""},
}

// New builds a Finding from a catalogue code, attaching optional detail.
func New(code, detail string) Finding {
	e, ok := Catalogue[code]
	if !ok {
		return Finding{Code: code, Severity: SevWarning, TitleEN: code, Detail: detail}
	}
	return Finding{
		Code: code, Severity: e.Severity, TitleEN: e.TitleEN, TitleFA: e.TitleFA,
		Why: e.Why, Fix: e.Fix, FixAction: e.Action, Detail: detail,
	}
}
