# ForgePanel Diagnostics Catalogue

Every finding the Validation & Proof engine (§3) can raise has a stable code
so messages are searchable. Each carries English + Farsi text, why it matters,
and the exact fix; some have a one-click Fix It action.

| Code | Severity | Meaning (EN) | معنی (FA) | Why | Fix | Fix action |
|------|----------|--------------|-----------|-----|-----|------------|
| `FP-CLOCK-001` | critical | System clock is out of sync | ساعت سیستم هماهنگ نیست | REALITY and TLS reject handshakes when the clock skews more than a few seconds — a classic silent failure. | Enable NTP (timedatectl set-ntp true) and resync. | — |
| `FP-DNS-001` | warning | Domain does not resolve to this server | دامنه به این سرور اشاره نمی‌کند | ACME cannot issue a certificate and clients dialing the domain will not reach this server. | Point the domain's A/AAAA record at this server's public IP. | — |
| `FP-FLOW-001` | critical | xtls-rprx-vision requires TCP + TLS/REALITY | vision فقط با TCP و TLS/REALITY کار می‌کند | The vision flow is only valid over raw TCP with TLS or REALITY; other transports produce a config the core rejects. | Remove the flow, or set transport=tcp with TLS/REALITY. | clear_flow |
| `FP-KEY-001` | critical | Shadowsocks-2022 key length wrong for method | طول کلید SS2022 با روش هم‌خوان نیست | SS2022 requires a base64 PSK whose decoded length matches the method (16 bytes for aes-128, 32 for aes-256/chacha20). | Regenerate the pre-shared key for the chosen method. | regen_psk |
| `FP-PORT-001` | critical | Port out of range | پورت خارج از محدوده | A TCP/UDP port must be between 1 and 65535; the core will refuse to start. | Choose a port between 1 and 65535. | — |
| `FP-PORT-002` | critical | Port already in use by another inbound | پورت توسط ورودی دیگری استفاده شده | Two inbounds cannot bind the same port; the second fails to start and its users cannot connect. | Pick a free port, or hop this protocol onto a different one. | — |
| `FP-PORT-HOP-001` | warning | Hysteria2 port-hop range overlaps another inbound | بازهٔ پرش پورت با ورودی دیگری هم‌پوشانی دارد | An overlapping hop range steals ports from another inbound, breaking one or both. | Choose a hop range that does not overlap other inbounds. | — |
| `FP-REALITY-001` | critical | REALITY dest missing or not TLS 1.3 | مقصد REALITY نامعتبر یا بدون TLS 1.3 | REALITY borrows the dest site's TLS 1.3 handshake; a dest that is not reachable on TLS 1.3 breaks the handshake. | Point dest at a site that serves TLS 1.3 (e.g. www.cloudflare.com:443). | — |
| `FP-REALITY-002` | critical | Invalid REALITY shortId length | طول shortId نامعتبر است | shortId must be an even-length hex string of at most 16 characters (8 bytes) or the client cannot authenticate. | Regenerate the shortId. | regen_shortid |
| `FP-TLS-001` | warning | TLS enabled but no certificate for this SNI | TLS فعال است اما گواهی برای این SNI وجود ندارد | Without a matching certificate the panel serves a self-signed one, and strict clients reject the connection. | Register the domain and enable one-click ACME, or import a certificate. | issue_acme |
| `FP-TLS-002` | critical | Plaintext inbound presented as secure | ورودی بدون رمز به‌عنوان امن نمایش داده شده | security=none over a cleartext transport carries traffic in the clear; showing it as secure misleads the operator and exposes users. | Switch to REALITY (no domain needed) or enable TLS on a domain. | convert_reality |
| `FP-UDP-001` | warning | UDP may be blocked for this protocol | ممکن است UDP برای این پروتکل مسدود باشد | Hysteria2/TUIC/WireGuard/QUIC need UDP; if the host firewall drops it, clients silently fail to connect. | Open the UDP port on the host firewall. | — |
| `FP-VERIFY-FAIL` | critical | Verification failed — no traffic carried | تأیید ناموفق — ترافیکی عبور نکرد | A real client core could not carry traffic through this inbound, so it will not work for users. | Open the captured client log, fix the reported cause, and re-verify. | — |
| `FP-VERIFY-OK` | info | Verified — traffic proven end to end | تأیید شد — عبور ترافیک اثبات شد | A real client core connected through this inbound and carried traffic. |  | — |
