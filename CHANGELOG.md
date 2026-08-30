# Changelog

## v1.20.0 — Remote nodes, two languages, and a panel that knows where it is running

The largest release so far: 175 commits since v1.19.1. The headline is that
ForgePanel stopped being a single-server panel — it now enrols and supervises
other servers over an mTLS control plane, runs on managed platforms as well as a
VPS, and speaks Persian.

### Added — the panel itself

- **Remote nodes with an mTLS control plane.** Enrol other servers and run
  inbounds on them. The permanent enrol token is gone: each node gets a
  client certificate, and the panel meters traffic per user on the node as it
  does locally. Nodes run **sing-box as well as xray**, carry a lifecycle status
  machine, and report *why* they are unhealthy rather than one bit.
- **Persian, and right-to-left.** The whole panel is translated (EN/FA) with the
  layout mirrored, guarded by tests that fail on any hard-coded string and on key
  drift between the two catalogues.
- **A light theme.** Colours are design tokens now rather than 531 literals
  restated across 29 files, with a three-state switch (System / Light / Dark).
- **Deployment-aware settings.** The panel detects Railway, Render, Fly and Koyeb
  and *removes* the controls those platforms own — certificates, domains, ports,
  host tuning — instead of showing controls that cannot work. Each removal says
  why, and says how to get the capability back where that is possible.
- **Cloudflare WARP as a managed outbound**, with WARP+ licence activation and
  scheduled endpoint rotation.
- **Scoped, hashed, expiring API tokens**, and a Prometheus scrape at
  `/admin/metrics`.
- **Webhooks** for lifecycle events, so alerts have a sink that is not a chat
  app, plus Telegram push alerts that warn people *before* they are cut off.
- **Wildcard certificates** via the DNS-01 challenge.
- **Per-client WireGuard peers**, so several users can share one inbound.
- **Per-inbound public endpoints (hosts)** and **saved plans**.
- **Backups to S3**, because the only copies used to live on the machine being
  backed up.
- **A foreign-panel importer** that actually imports, and records provenance so a
  re-import recognises what it already has.
- **Reverse-tunnel backends (bridge)**, managed from the panel.
- **Operator-selectable core versions**, with a real pin and a rollback target.
- **Failover groups in routing**, so one dead relay no longer takes its users
  with it.
- Every subscription now leads with a **latency-tested group** ("Best Ping" /
  `auto`), first in the selector and its default, so an untouched client picks
  the fastest node instead of whichever was generated first. Verified against
  sing-box 1.13.2 and Mihomo 1.19.21.

### Added — setup that does not need fixing afterwards

- **An IP-only install can still get a real certificate.** With no domain the
  installer offers a magic-DNS hostname (`<ip>.sslip.io`), which Let's Encrypt
  will issue for — so the panel opens with no browser warning on a server that
  owns no domain. Offered rather than imposed, with its cost stated: sslip.io is
  not on the Public Suffix List, so its certificate quota is shared globally.
- **The preset wizard checks its prerequisites first.** Token, zone, zone SSL
  mode, WebSockets and every CDN port are verified before anything is created,
  so a failing setup is one round of fixes instead of one per attempt.
- **The preset verifies the CDN half instead of announcing it.** Cloudflare's own
  5xx codes are translated into the thing to fix — 521 nothing listening, 522 a
  filtered port, 525 an origin not serving TLS, 526 Full (Strict) against a
  self-signed origin.
- **REALITY dests are measured, not guessed.** A hardcoded list of four names is
  replaced by a probe that connects and reports TLS 1.3, X25519, ALPN and the
  certificate chain size. That list was wrong in both directions: it blocked
  `www.amazon.com`, which works, and allowed `www.microsoft.com`, which does not
  — its 8126-byte certificate chain is too large for REALITY to relay, so the
  client authenticates and the tunnel then carries nothing.

### Added — ForgeEdge

- **A real panel for the Cloudflare Worker.** Sixty-odd settings that were
  reachable only through a raw JSON textarea now have grouped controls, search,
  a light and dark theme, and a save bar; the raw JSON remains as an Expert tab.
- **ForgeEdge Bot** — a new standalone single-binary Telegram bot

### Added
- **ForgeEdge Bot** — a new standalone single-binary Telegram bot
  (`forgeedge-bot`) that does what the panel's Worker Wizard does, but entirely
  from chat and with **no panel required**. It is a separate process with its own
  AES-GCM-encrypted state, yet reuses the panel's `internal/edge` engine and the
  same embedded Worker bundle, so a Worker it deploys is byte-for-byte the panel's.
  - **Request-and-approve access.** One owner (`FORGEEDGE_BOT_OWNER`) is the root
    approver: when anyone messages the bot they become *pending* and the owner
    gets an inline ✅ Approve / ❌ Deny (also `/approve` `/deny` `/revoke`
    `/users`). Each approved user brings **their own** Cloudflare token with `/cf`
    (the bot deletes that message immediately; the token is stored encrypted) and
    sees only **their own** Workers.
  - **Full config editor in chat.** `/deploy` `/list` `/status` `/sub` `/config`
    `/update` `/rotate` `/destroy`; clean-IPs + fronting (`/addip` `/rmip` `/ips`
    `/probeip` `/refreships` `/sni` `/cdnhost` `/cdnaddr`); transport/obfuscation
    (`/ports` `/fingerprint` `/fragment` `/proxyip` `/nat64` `/chain`
    `/protocols`); `/backend` `/extsub` `/domain`; and WARP (`/warp` `/warpconf`,
    serving WireGuard + AmneziaWG nodes). Config edits are read-modify-write and
    validated by the Worker, which relays any rejection verbatim.
  - The bot never needs a Worker's admin password — it authenticates to each
    Worker with that Worker's machine credential (the feed push token) captured at
    deploy. It makes only outbound HTTPS, so it runs as an unprivileged systemd
    dynamic user. Ships as a release binary with a hardened systemd unit + env
    template; full setup in [docs/EDGE_BOT.md](docs/EDGE_BOT.md).
- On the panel side, `internal/edge` gained a config editor on the Worker client
  (`GetConfigRaw`/`PutConfigRaw`) plus clean-IP refresh/probe and external-sub
  refresh helpers, all authenticated by the machine push token.

### Fixed — the ones worth naming

- A **Railway deploy came up with no working config**, three ways at once; the
  PaaS image also stopped building at one point and nothing in the suite could
  see it. Both are now guarded by tests that read the Dockerfiles.
- An **inbound the panel could not bind was dropped silently** — enabled in the
  UI, nothing listening, and no log line anywhere.
- **REALITY links carried an SNI the server refuses**, and an imported
  subscription could kill the core.
- **ShadowTLS clients connected, mimicked TLS perfectly, and carried nothing.**
- **Brook inbounds that had crashed were reported as running**, and nothing
  brought back an inbound that went away on its own.
- **A wedged core was supervised forever as "running".**
- The panel's **own outbound calls went direct**, failing on exactly the networks
  the proxy exists for, and it would fetch any address an operator typed —
  including the cloud metadata service.
- **The navigation showed everyone everything**: the panel knew who was signed in
  and offered every tab regardless of role.
- **Telegram reported every send as successful**, and its token could only be set
  by restarting.
- The **TLS-fragment toggle was on and sing-box subscribers got no fragmentation**.
- **Traffic accounting threw away the uplink/downlink split**, and one user
  tripping a quota dropped every connection on the node.


## v1.19.1 — Telegram bot setup made discoverable

### Fixed / docs
- The built-in **Telegram bot** (manage the panel from chat — `/sub`, and for
  admins `/adduser` `/deluser` `/enable` `/disable` `/reset` `/limit` `/extend`
  `/stats` `/user`, with every change reloading the running cores) was fully
  implemented and started at boot, but nothing told operators how to turn it on.
  Now the installer seeds `/etc/forgepanel/forgepanel.env` with a commented,
  ready-to-fill Telegram block, and CONFIGURATION.md + the operator guide give the
  exact 3-step setup (@BotFather token → @userinfobot chat id → env vars +
  restart). Verified live that the documented steps bring the bot up (the panel
  connects to api.telegram.org and polls). No behaviour change to the bot itself.

## v1.19.0 — config fan-out: the full camouflage range

### Added
- **The subscription now fans each inbound into its whole camouflage range**,
  instead of one config per inbound — the breadth the sample configs show:
  - a **REALITY** inbound with several borrowed SNIs → **one config per SNI**
    (default on, `sub_expand_sni`);
  - a **CDN-frontable TLS** inbound → **one config per clean Cloudflare edge IP**
    (`sub_front_cleanip` + `sub_clean_ips`).
  The Preset Wizard seeds an Iran-reachable clean-IP list and turns both on, so a
  freshly-built server's subscription grew **8 → 38 → 56 configs**. Verified live:
  a REALITY config on each rotated SNI, and a CDN config fronted on
  `188.114.96.3`, all tunnelled. A single-SNI / no-clean-IP inbound still yields
  exactly one config.

## v1.18.0 — Preset Wizard: one call builds a whole working server

### Added
- **Preset Wizard** (`POST /api/admin/wizard/preset`, and a one-click card in the
  Setup Wizard). From a domain + an optional Cloudflare token it creates one
  inbound per config family and wires every one so none need the manual firewall
  / certificate / DNS steps that usually break a hand-built server:
  - REALITY-Vision (443), REALITY-XHTTP (8443) and REALITY-Brutal (8444) — direct
    to the IP, sharing one keypair, borrowing a rotation of real SNIs (Iranian +
    global); no certificate needed.
  - VLESS-WS / VLESS-XHTTP / VMess-WS over TLS (2096/2087/2083) fronted behind a
    proxied Cloudflare sub-domain the wizard creates via the token; the edge
    terminates TLS so the origin only needs a self-signed cert. **One API token
    does both the DNS record and the trusted certificate.**
  - Shadowsocks-2022 (8388), with a correctly-sized std-base64 PSK.
  Ports never collide; the firewall is opened and xray hot-reloaded. An invalid
  token is a warning with the exact record to add, not a failure.
  Verified live end-to-end: REALITY-Vision, Shadowsocks-2022 and the
  Cloudflare-fronted VLESS-WS all carried traffic (HTTP 204) through the
  created inbounds.
- **Complete operator guide** (`docs/PANEL_GUIDE.md`) covering every part of the
  panel, with the Preset Wizard documented in depth.

## v1.17.0 — worker panel: Share-with-family + external-subs controls

### Added
- The Worker's own panel now surfaces the shipped features so they're managed
  without editing raw JSON: a **"Share with family"** section (import-page URL +
  subscription URL with copy buttons, plus quick links to the serverless /
  smart-fragment DPI fallbacks), and an **"External subscriptions"** section with
  a one-click refresh and a live merged-config count. The `status` endpoint now
  returns the share links and the external-subs count.

## v1.16.0 — external subscription merge

### Added
- **External subscription merge** — list other subscription URLs (your own fleet
  subs, a community feed) in `externalSubs` and every config in them is merged
  into this one, so a family member imports a single URL and gets everything.
  Fetched configs are parsed into the same canonical nodes as the rest of the
  pipeline (vless/vmess/trojan/ss/socks/http incl. reality + transports), so they
  render in every format and ride the best-ping groups under their own "External"
  group. Unparseable lines are skipped; caps at 200/sub and 600 total. Refreshed
  on the cron and on demand (`POST api/external/refresh`); serving never blocks
  on a slow upstream. Verified live: 200 configs from a fleet sub merged into the
  subscription.

## v1.15.0 — end-user landing/import page

### Added
- **End-user landing page** at `/<securePath>/import/<sub_token>` — one-tap import
  into v2rayNG, Streisand, Hiddify, sing-box, Clash Meta, Mihomo Party and
  Shadowrocket, plus direct per-format links and a **self-contained SVG QR** of
  the subscription URL (Project Nayuki's encoder, vendored MIT). Built from the
  subscriber's own token, so it exposes no admin secret. Onboarding a family
  member becomes "open link, tap your app". The QR is verified correct by
  rasterizing the emitted SVG and decoding it back to the exact sub URL.

## v1.14.0 — CF-CIDR clean-IP randomizer + proxyIP relay

### Added
- **CF-CIDR clean-IP randomizer** — each clean-IP refresh now mints fresh random
  Cloudflare edge IPs (default 10, `cleanIPRandomCount`) from the ranges that
  actually serve HTTP (104.16/13, 104.24/14, 162.159/16, 172.64/13,
  188.114.96/20). Cloudflare is anycast, so any live edge IP fronts the Worker —
  a blocklist of yesterday's seed hostnames does nothing against a literal picked
  at random today. ~30-50% of picks are live; the client's best-ping group keeps
  the winners. Verified: a minted literal fronts workers.dev and tunnels
  end-to-end.
- **proxyIP SNI-relay docs** (`docs/PROXYIP_RELAY.md`) — the reliable way to reach
  Cloudflare-hosted destinations the edge can't `connect()` to directly: run a
  gost `sni://:PORT` relay and set `proxyIPMode: 'proxyip'`. Verified live
  (`cloudflare.com` 200 in ~0.5s through the edge, vs. a hang without it) — the
  dependable alternative to the flaky public NAT64.

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
