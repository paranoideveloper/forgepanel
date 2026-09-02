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
	"FP-TLS-002": {SevCritical, "Plaintext inbound presented as secure", "ورودی بدون رمز به\u200cعنوان امن نمایش داده شده",
		"security=none over a cleartext transport carries traffic in the clear; showing it as secure misleads the operator and exposes users.",
		"Switch to REALITY (no domain needed) or enable TLS on a domain.", "convert_reality"},
	"FP-REALITY-001": {SevCritical, "REALITY dest missing or not TLS 1.3", "مقصد REALITY نامعتبر یا بدون TLS 1.3",
		"REALITY borrows the dest site's TLS 1.3 handshake; a dest that is not reachable on TLS 1.3 breaks the handshake.",
		"Point dest at a site that serves TLS 1.3 (e.g. www.cloudflare.com:443).", ""},
	"FP-REALITY-002": {SevCritical, "Invalid REALITY shortId length", "طول shortId نامعتبر است",
		"shortId must be an even-length hex string of at most 16 characters (8 bytes) or the client cannot authenticate.",
		"Regenerate the shortId.", "regen_shortid"},
	"FP-FLOW-001": {SevCritical, "xtls-rprx-vision requires TCP + TLS/REALITY", "vision فقط با TCP و TLS/REALITY کار می\u200cکند",
		"The vision flow is only valid over raw TCP with TLS or REALITY; other transports produce a config the core rejects.",
		"Remove the flow, or set transport=tcp with TLS/REALITY.", "clear_flow"},
	"FP-KEY-001": {SevCritical, "Shadowsocks-2022 key length wrong for method", "طول کلید SS2022 با روش هم\u200cخوان نیست",
		"SS2022 requires a base64 PSK whose decoded length matches the method (16 bytes for aes-128, 32 for aes-256/chacha20).",
		"Regenerate the pre-shared key for the chosen method.", "regen_psk"},
	"FP-CLOCK-001": {SevCritical, "System clock is out of sync", "ساعت سیستم هماهنگ نیست",
		"REALITY and TLS reject handshakes when the clock skews more than a few seconds — a classic silent failure.",
		"Enable NTP (timedatectl set-ntp true) and resync.", ""},
	"FP-UDP-001": {SevWarning, "UDP may be blocked for this protocol", "ممکن است UDP برای این پروتکل مسدود باشد",
		"Hysteria2/TUIC/WireGuard/QUIC need UDP; if the host firewall drops it, clients silently fail to connect.",
		"Open the UDP port on the host firewall.", ""},
	"FP-PORT-HOP-001": {SevWarning, "Hysteria2 port-hop range overlaps another inbound", "بازهٔ پرش پورت با ورودی دیگری هم\u200cپوشانی دارد",
		"An overlapping hop range steals ports from another inbound, breaking one or both.",
		"Choose a hop range that does not overlap other inbounds.", ""},
	"FP-DNS-001": {SevWarning, "Domain does not resolve to this server", "دامنه به این سرور اشاره نمی\u200cکند",
		"ACME cannot issue a certificate and clients dialing the domain will not reach this server.",
		"Point the domain's A/AAAA record at this server's public IP.", ""},
	"FP-CLOCK-002": {SevWarning, "No time synchronisation running", "همگام\u200cسازی زمان اجرا نمی\u200cشود",
		"Nothing is disciplining this host's clock, so it will drift until REALITY/TLS and VMess AEAD start rejecting handshakes.",
		"Install and enable a time daemon: timedatectl set-ntp true (systemd-timesyncd), or install chrony.", ""},
	"FP-CLOCK-003": {SevInfo, "Clock could not be checked", "امکان بررسی ساعت نبود",
		"No NTP server was reachable and no local time daemon could vouch for the clock, so its accuracy is unknown — this is not a pass.",
		"Allow outbound UDP/123 to an NTP server, or enable systemd-timesyncd/chrony so the host can report its sync state.", ""},
	"FP-VERIFY-OK": {SevInfo, "Verified — traffic proven end to end", "تأیید شد — عبور ترافیک اثبات شد",
		"A real client core connected through this inbound and carried traffic.",
		"", ""},
	"FP-VERIFY-DEGRADED": {SevWarning, "Verified, but the tunnel is very slow", "تأیید شد اما تونل بسیار کند است",
		"Traffic did arrive, but a loopback round trip took seconds — on a real network path that is unusable, and it usually means the core is starved of CPU or the transport is misconfigured.",
		"Check host load and the transport/obfuscation settings, then re-verify.", ""},
	"FP-VERIFY-UNPROVABLE": {SevInfo, "Cannot be proven here — test from a real client", "قابل اثبات در این\u200cجا نیست — با کلاینت واقعی آزمایش کنید",
		"REALITY needs a live TLS 1.3 destination and the UDP/QUIC protocols never open the TCP port this loopback harness waits on, so no honest verdict can be reached locally. This is NOT a failure.",
		"Connect with a real client from outside this server to confirm.", ""},
	"FP-VERIFY-CORE-DOWN": {SevCritical, "The proxy core did not run", "هستهٔ پروکسی اجرا نشد",
		"The sing-box core was missing, refused to start, or never opened its port, so nothing could be verified — the inbound itself was never reached.",
		"Check the core binary and the panel's engine status, then re-verify.", ""},
	"FP-VERIFY-CONFIG": {SevCritical, "Config could not be built for this inbound", "ساخت پیکربندی برای این ورودی ممکن نبود",
		"The panel could not render a core config from this node, so the link it hands to clients cannot work either.",
		"Fix the reported field, or recreate the inbound from a preset.", ""},
	"FP-VERIFY-NET-UNREACHABLE": {SevCritical, "Could not reach the inbound", "دسترسی به ورودی ممکن نبود",
		"The connection to the inbound's port was refused, reset, or timed out — traffic never got as far as the protocol, so this is a listener/firewall problem, not a credential one.",
		"Confirm the core is listening on that port and that the host firewall permits it.", ""},
	"FP-VERIFY-HANDSHAKE": {SevCritical, "TLS/REALITY handshake failed", "دست\u200cدهی TLS/REALITY ناموفق بود",
		"The connection reached the inbound but the transport handshake was rejected, so no user data could ever flow. Certificate, SNI, ALPN and clock skew are the usual causes.",
		"Check the certificate/SNI pair and the host clock (FP-CLOCK-001), then re-verify.", ""},
	"FP-VERIFY-AUTH": {SevCritical, "Credentials rejected by the inbound", "اعتبارنامه توسط ورودی رد شد",
		"The transport came up but the inbound refused the client's identity, so the link the panel exports does not match the inbound's users.",
		"Re-issue the client link for this user, or fix the UUID/password/method on the inbound.", ""},
	"FP-VERIFY-NO-DATA": {SevCritical, "Tunnel opened but carried no data", "تونل باز شد اما داده\u200cای عبور نکرد",
		"The client connected and authenticated, yet the payload never arrived intact — routing, the transport path, or an egress hop is swallowing traffic.",
		"Check the inbound's routing/egress chain and any sniffing or transport settings, then re-verify.", ""},
	"FP-VERIFY-FAIL": {SevCritical, "Verification failed — no traffic carried", "تأیید ناموفق — ترافیکی عبور نکرد",
		"A real client core could not carry traffic through this inbound, so it will not work for users. The evidence did not point at one specific cause.",
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
