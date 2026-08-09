# Changelog

## v1.13.1 — NAT64 retry uses the best prefix

### Fixed
- The NAT64 escape hatch (for reaching Cloudflare-hosted destinations the edge
  can't `connect()` to directly) now uses the **first** configured prefix
  deterministically instead of a random one, and the default prefix list is
  ordered best-first. A random pick landed on a dead public gateway ~2/3 of the
  time and hung ~19s. NAT64 stays **off by default** on purpose — measured live,
  even the reachable public gateway answers only ~25% of the time, which is
  worse than a fast failure; enable it only with a reliable gateway or an
  SNI-routing relay on your own fleet (`proxyIPMode: 'proxyip'`).

## v1.13.0 — edgetunnel serverless + smart-fragment configs

### Added (Xray-only DPI-evasion, for Iran)
- **Serverless / workerless configs** (`/sub/<token>?serverless=cf|google`) — a
  proxy-LESS Xray config whose `freedom` outbounds fragment the TLS ClientHello
  on a DIRECT connection, slipping past an SNI-matching DPI box when every proxy
  IP is blocked but the destination is only filtered (not null-routed). QUIC
  (udp/443) is blocked so it can't bypass the fragmenter. Verified end-to-end:
  `xray -test` OK and traffic flows direct-with-fragmentation (exit = the host's
  own IP, no proxy).
- **Smart-fragment sweep** (`/sub/<token>?smartfrag=1`) — the worker's own VLESS
  proxy fanned across 20 fragment lengths in one leastPing group, so the client
  auto-pins whichever length beats the local DPI box. Verified: `xray -test` OK
  and tunnelled through the live worker (exit AS13335).

## v1.12.0 — Fancy config wizard

### Added
- **Fancy config wizard** on Users & Subscriptions: set a camouflage domain,
  pick a styled theme, and every config in the subscription is renamed with the
  theme and fronted behind that domain — the look Iranian channels ship
  (aparat / nobat / taskulu / snapp / baman / akharin, emoji + Persian + bold).
  - 18-theme catalogue across VMess-WS / XHTTP-Reality / Vision-Reality / SS-2022.
  - Two fronting models, chosen per theme: **SNI** (keep the real dial address,
    present the domain as TLS SNI + Host header — works on any server and on
    REALITY) and **CDN** (set only the Host header for a Host-routing domestic
    CDN, the plaintext-WS pattern). Applied in `subscriptionNodes` before naming.
  - New settings `sub_front_domain` / `sub_front_mode`; the GET settings endpoint
    exposes the theme catalogue and POST applies a theme in one step.
  - Verified at three layers: model unit tests, an exporter test that renders a
    fronted node to a real `vless://` link, and an api test proving the settings
    flow end-to-end into the rendered subscription.

## v1.11.0 — ForgeEdge relay fix + Iran survivability

### Fixed (the ForgeEdge Worker never actually tunnelled)
- **The edge Worker accepted connections but relayed nothing** — every emitted
  config showed "n/a"/no-TLS and clients got `unexpected eof while reading`.
  Three bugs in the ws↔remote relay (`deploy/cloudflare/forgeedge/src/protocols/`):
  1. **Deadlock** — the client→remote pump was `await`ed inside the first
     chunk's `sink.write()`, but it awaited the *entire* remote→ws relay
     (resolves only when the remote closes), so no further client bytes could
     flow and every multi-round-trip TLS handshake to the destination stalled.
     The remote→ws pump now runs in the background, matching the proven
     edgetunnel flow; the open WebSocket keeps the isolate alive.
  2. **Response truncation** — the client→remote pipe's `catch` force-closed the
     WebSocket, dropping the buffered response. It now lets the client close the
     socket after it has read the response.
  3. **Benign unhandled exception** — the `connect()` socket's `.closed` promise
     rejects with "Network connection lost" on normal client disconnect; a no-op
     catch keeps it out of the Worker's error metrics.
  Verified end-to-end through a live Worker (xray client → curl --socks5):
  google 204, AWS checkip 200, ip-api, microsoft 201 KB, wikipedia 2.7 MB — all
  tunnelled, exit AS13335. Unit tests never caught it (no workerd sockets).

### Added (edgetunnel-inspired, for Iran)
- **Fancy emoji remarks** on the edge's own nodes ("☁️ ForgeEdge N · ⚡ VLESS ·
  Domain : 443"), with a `remarkStyle: 'plain'|'fancy'` toggle and a
  `remarkPrefix` brand override. Machine-readable tokens are preserved.
- **Multi-port by default** — the edge now advertises across all six Cloudflare
  TLS ports (443, 8443, 2053, 2083, 2087, 2096) instead of only 443, so a
  client's best-ping group survives 443 throttling/blocking.

## v1.4.0 — Round-2 remediation & expansion

### Fixed (the broken fundamentals)
- **Panel UI was completely dead**: the SvelteKit build's `/_app/*` assets were
  never served (404), so the app could not boot. Now served with correct MIME
  types + SPA fallback.
- **Blank panel at the secret path**: even with assets served, opening
  `/panel/<secret>` (no trailing slash) left SvelteKit's `base` collapsed to
  `/panel`, so its relative `./_app/…` assets resolved to `/panel/_app/…` (served
  as the HTML shell → rejected as a bad module) and the router matched no route.
  The bare path now 301s to `<path>/` and `_app/…` assets are served under any
  prefix. Verified in a real browser: login + dashboard render with 0 console
  errors. Found by deploying to a real server.
- **Login was broken**: the SPA called `/api/auth/login` returning `{token}`; the
  backend serves `/api/login` returning `{access_token}`. Reconciled, plus the
  `/health`→`/admin/overview`, `/usergroups`→`/groups`, `/presets`→
  `/protocols/presets` mismatches. A path-audit script now keeps them in sync.
- **Subscriptions**: the sing-box output was rejected by the real core (duplicate
  `proxy` tag); the `Subscription-Userinfo` header reported all-zeros regardless
  of the user's real quota/expiry. Both fixed and proven against `sing-box check`.
- **BUG-3 — Domains**: a first-class Domains registry, a domain that cascades to
  SNI / Host / cert / client-link address / subscription, one-click ACME with an
  honest preflight, and the no-domain path that steers to REALITY (EN+FA) instead
  of silently emitting plaintext.
- **BUG-4 — inbound editing**: safe-edit warnings on breaking changes, clone,
  enable/disable, bulk actions, and one-level undo. Covered by Playwright.
- **BUG-2 — emitted configs now carry real traffic** (the §4 connectivity harness
  drives the real cores over every emitted config; 24/24 protocol inbounds pass,
  only the 4 REALITY variants skipped on loopback):
  - The shipped **alpine image could not exec the glibc sing-box** release binary
    (exit 127) — Hysteria2/TUIC/AnyTLS/ShadowTLS/WireGuard/SSH were all dead in
    the container. Added `gcompat`; proven by running the pinned sing-box inside
    the built image.
  - **QUIC no longer carries a `utls` block** sing-box rejects: `fingerprint=chrome`
    was stamped on every TLS node and turned into `utls`, which Hysteria2/TUIC
    refuse. Now suppressed for QUIC at both the render and defaults layers.
  - **Self-signed TLS is auto-pinned** for xray-core 26 (which removed
    `allowInsecure`): the subscription now carries `pinnedPeerCertSha256` of the
    exact cert the engine serves. Proven by a real xray TLS round-trip.
  - **Shadowsocks keeps its inbound PSK** in the subscription: stamping the user's
    base64url password broke SS-2022 (needs exact-length standard base64) and
    handed clients a key the single-key server never held.
  - The **sing-box subscription is runnable as delivered**: it now ships a local
    mixed inbound + route instead of an outbounds-only document that carried
    nothing.
  - **ShadowTLS carries traffic**: the subscription emits the required
    Shadowsocks→ShadowTLS `detour` chain instead of a bare shadowtls outbound
    that camouflages TLS but proxies nothing. Proven by `sing-box check`.
- **Over-quota users are cut off**: `enabledInboundSpecs` and the ForgeEdge feed
  skipped only Disabled/Expired, so a user past their data limit (`StatusLimited`)
  kept transferring until the next engine reload. Both planes now agree.
- **Inbounds can be disabled without deletion**: `POST /inbounds/:id/toggle`
  clears `Enabled`, which `enabledInboundSpecs` honours, so a disabled inbound
  stops serving immediately (previously only deletion removed it).
- **ForgeDNS reassembly no longer deadlocks**: a full reorder buffer used to
  reject the in-order head frame that would have drained it, stalling the session
  permanently on its own missing head. The head is now always accepted.
- **Live Verify works on a clean install**: the §3 diagnostic looked for sing-box
  on `$PATH`, but binmgr installs it under `<dataDir>/bin`, so every verification
  failed with "sing-box binary not available" even though the core was downloaded
  and serving. It now runs the exact binary the supervisor uses. Found by
  deploying to a real server and re-proven there (Shadowsocks 2 ms, VMess-WS 3 ms).
- **CI workflow was invalid YAML**: all seven `Test Suite: …` job names carried an
  unquoted colon, which GitHub rejects for the whole file. Quoted; a real carried
  fix for main (the workflow could never have run as written).

### Added
- Subscription formats: `xray` (validated by `xray run -test`), `surge`, `loon`,
  `quantumultx`, `shadowrocket`; `clash-meta`; a golden-file matrix over all.
- **Validation & Proof engine** (`internal/diag`): static checks with a coded,
  bilingual diagnostics catalogue (`docs/DIAGNOSTICS.md`), a live Verify that
  carries real traffic through one canonical node, and a Panel Doctor.
- **§4 connectivity harness** (`test/harness/`, build-tagged): docker-compose
  proof of real traffic per protocol, with an experimental-flagging matrix.
- **§5 DNS automation wizard** (`internal/dns`): Cloudflare-first (+ ArvanCloud,
  deSEC) token verification with precise scope diagnostics, zone/subdomain CRUD,
  parent-zone/delegation handling, ACME preflight, rotation pool, clean-IP
  scanner, and `forgectl provision`.
- **§6 ForgeEdge** (`deploy/cloudflare/forgeedge/`): a Cloudflare Worker sharing
  the canonical model — VLESS/Trojan over WS, DoH, WARP, chain proxy, fragment,
  routing rules, and Backend Mode to a VPS node.
- **§6 ForgeEdge Go-side** (`internal/edge`, `internal/api/edge*.go`,
  `internal/store` `EdgeDeployment`, `forgectl edge`): the panel now feeds the
  canonical model to registered Workers — a redacted push/pull feed so one
  subscription URL carries VPS inbounds *and* edge entries, Cloudflare
  OAuth+PKCE (and `--api-token`) deploy/update/delete/status/push/rotate-path, and
  a CI drift guard that regenerates the golden fixtures from the real Go exporters
  and asserts the TypeScript mirror is byte-identical.

### CI / build
- Fixed the red CI: govulncheck (x/net, x/text, go 1.25.12) and shellcheck; the
  invalid workflow YAML (unquoted colons in job names); and a `.gitignore` pattern
  (`forgectl`) that was silently ignoring the whole `cmd/forgectl/` source dir.
- All fixes on one branch; `make check`, `staticcheck ./...` and `govulncheck
  ./...` clean; the full non-`-short` Go matrix, race detector, frontend (39),
  ForgeEdge worker (316) + drift guard, e2e, cross-compile and docker all green.
