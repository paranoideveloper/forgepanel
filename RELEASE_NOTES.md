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
