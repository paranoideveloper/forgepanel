# ForgePanel v1.5.3 — Release Notes

Adds **bulk inbound operations** (multi-select → enable/disable/delete) on top of
v1.5.2, and ships the full set of install artifacts (static binaries + `.deb` /
`.rpm` packages + `install.sh`). Verified: 9/9 Playwright tests against the built,
embedded binary; every protocol carries real traffic from an external client.

---

# ForgePanel v1.5.2 — Release Notes

The 1.5 line rebuilt the browser experience and fixed the things that stopped a
config from actually working. Everything below was verified in a real browser
against the built, `go:embed`'d binary and with real client cores carrying
traffic from an external machine — not isolated unit tests.

## Highlights

- **A real Inbounds section + Config Studio.** Create any of the 13 protocols from
  a schema-driven form (every option, Generate keys/UUIDs/PSKs), with a live
  four-format preview (client link · Xray · sing-box · Clash) and a working Save.
  List, **edit**, clone, enable/disable, delete; copy the client link or QR.
- **Every protocol carries traffic.** Inbounds now include their own credential,
  so VLESS/VMess/Trojan/REALITY authenticate and pass traffic — previously a
  standalone inbound rendered an empty client list and only Shadowsocks worked.
- **Reachable by default.** The panel auto-opens the host firewall (ufw) for each
  inbound port, and warns in the UI when a port is blocked despite a green Verify.
- **Users, groups & assignment.** Create users, **assign inbounds to a user or a
  group**, edit status/group/data-limit/expiry, reset credentials, hand out
  per-user subscription links.
- **HTTPS by default** — self-signed with no domain, automatic Let's Encrypt with
  one. First-run administrator setup happens in the browser.
- **Panel Doctor + Paste-Anything importer** reachable in the UI.

## Fixes

- "Only Shadowsocks worked" — inbound auth lists were built solely from assigned
  users, so unassigned inbounds rejected every connection. Fixed.
- "Verify is green but it fails on my phone" — the loopback Verify never touched
  ufw's default-deny; proxy ports were firewalled. The panel now opens them and
  the UI reports reachability honestly.
- Panel served plain HTTP; the primary create flow was an empty shell; tests
  passed on empty panes. All rebuilt and re-verified end to end.

## Known limitations

- REALITY and QUIC inbounds cannot be *Verified* on a loopback (they need a real
  network); the badge says so instead of faking a pass — they do work externally.
- A cloud-provider firewall (Linode/AWS/…) must still be opened separately; the
  panel can only manage the host firewall.
- Remote **nodes** support enroll/delete only (no in-place edit).

## Install

See the README and `docs/INSTALL.md`. Fresh install: run the binary/installer,
open the printed `https://HOST:2053/panel/<secret>` URL (self-signed cert — accept
the browser warning), and create the administrator with the one-time setup token.

---

# ForgePanel v1.4.0 — Release Notes

## What was broken, and how it was fixed

The panel did not work end to end. The root causes, in the order a user hit them:

1. **The UI never loaded.** `GET /` returned the app shell, but every JavaScript
   and CSS asset it referenced (`/_app/immutable/...`) returned 404, so the
   SvelteKit app could not boot. There was no working panel at all. Fixed by
   serving the embedded build with correct MIME types and an SPA fallback.
2. **You could not log in.** The frontend called `POST /api/auth/login` and read
   `{token}`; the backend serves `POST /api/login` and returns `{access_token}`.
   Login silently failed. Fixed, along with three more endpoint mismatches
   (`/health`, `/usergroups`, `/presets`) that broke the dashboard, users and
   studio views. A script now audits every frontend call against the routes.
3. **Subscriptions were subtly wrong.** The sing-box output was rejected by the
   real sing-box core (two outbounds shared the `proxy` tag), and the usage
   header reported unlimited quota to everyone. Both fixed and proven by feeding
   the output back into `sing-box check` and `xray run -test`.
4. **No domain, no TLS, nowhere to set one.** There is now a Domains section: set
   a domain once and it cascades to the SNI, the Host header, certificate
   selection, the client-link address and the subscription base. One-click ACME
   issues the certificate with an honest preflight. With no domain the panel says
   so loudly and steers you to REALITY (which needs none), in English and Farsi —
   it never shows a plaintext inbound as if it were secure.
5. **Inbounds could not be edited safely.** Editing now warns before a change
   that would invalidate existing client configs, and supports clone,
   enable/disable, bulk actions and one-level undo.

## What is now proven working

`docs/E2E_REPORT.md` has the real, pasted command output. In short:

- **20 protocol × transport × security combinations carry real bytes** end to end
  through the actual cores (VLESS ws/grpc/xhttp/httpupgrade/vision-tls, VMess
  tcp/ws/grpc, Trojan tcp/ws/grpc, Shadowsocks incl. 2022, SOCKS, HTTP, Hysteria2,
  TUIC, AnyTLS) — 24 total with the 4 REALITY variants, which are verified on a
  public IP because their steal-handshake cannot complete on loopback.
- The **live Verify** engine carries traffic through one canonical node (vmess,
  shadowsocks proven in ~3 ms).
- **Playwright** drives the real browser through login, the bilingual Domains
  banner and the inbound edit→undo lifecycle, on desktop and mobile — 6/6.
- **ForgeEdge**: 316 worker tests pass; typecheck clean.
- CI is green: `staticcheck`/`govulncheck` clean, the full non-`-short` Go matrix,
  frontend (39 tests), e2e and docker all pass.

## Known limitations

- **REALITY** relays its handshake to a real steal-site and cannot be verified on
  a loopback interface; it is verified against a public deployment IP.
- **VMess over gRPC** works but is deprecated upstream: xray-core 26 warns that
  both VMess and the gRPC transport are deprecated. It carries traffic in the
  matrix; prefer VLESS for new deployments.
- **Per-user traffic accounting** covers Xray-served protocols; sing-box protocols
  (Hysteria2/TUIC/AnyTLS/ShadowTLS/WireGuard) are not metered because the official
  sing-box release is built without `v2ray_api` (see `docs/PROTOCOLS.md`).
- **DNS providers**: Cloudflare, ArvanCloud and deSEC are implemented; the other
  six are registry entries that fail loudly with "not available in this build".

## Installation

Both a systemd binary install and the GHCR container image are cut from the same
commit; see `docs/INSTALL.md`.
