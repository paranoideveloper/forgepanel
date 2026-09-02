# Changelog

## v1.22.0 — The tunnels that connected and carried nothing

Nine commits. Most of them are one story: a WireGuard or AmneziaWG inbound
could complete a handshake, answer a ping to its own gateway, and reach
nothing on the internet. Four separate causes, each found by connecting a
real client to the panel's own exported config rather than by reading code.

### Fixed — WireGuard and AmneziaWG

- **No egress NAT.** The generated server config had no `PostUp`, so no
  MASQUERADE was ever installed and every forwarded packet left the box with
  a private source address. Adding only that rule by hand took an AmneziaWG
  inbound from nothing to 21.7 MB/s, which is what identified it. Both kernel
  server configs now carry the NAT, the FORWARD accepts (a DROP policy
  discards the packet *after* NAT, which looks identical to having no NAT)
  and `ip_forward`, with a `PostDown` that removes exactly what `PostUp`
  added.
- **sing-box cannot serve WireGuard.** Its `endpoints[].type=wireguard` is an
  *outbound* construct: as a server it completes a handshake and answers
  traffic addressed to its own tunnel address — so it looks alive and a client
  can ping the gateway — but it forwards nothing onward. Verified against
  sing-box 1.13.21 with fresh keys in an isolated namespace under no route,
  `route.final`, `auto_detect_interface`, an explicit inbound rule, a sniff
  action, and a `0.0.0.0/0` peer. A control run proved the same instance and
  the same direct outbound reached the internet through a socks inbound.
  **WireGuard now defaults to the kernel datapath** wherever the host can run
  it; a host without the module still gets the sing-box endpoint.
- **`AllowedIPs = 0.0.0.0/0, ::/0` on an IPv4-only tunnel.** Clients installed
  a `::/0` route into an interface with no IPv6 address, so every IPv6
  destination blackholed. Invisible on an IPv4-only test host — it survived a
  namespace test, a Linux client and a live external check — and severe on a
  real dual-stack device, where happy-eyeballs prefers AAAA. The export now
  offers only the families the tunnel has an address for.
- **Every tunnel inbound got the same subnet.** WireGuard was hard-coded to
  `10.66.66.0/24` and AmneziaWG to `10.67.67.0/24`, so a *second* inbound of
  either protocol produced two interfaces holding the same address, two routes
  for one prefix, and two peers on the same client IP. The kernel answers for
  one; the other handshakes and its return traffic leaves by the wrong
  interface. Each inbound now takes the next free `/24` from its protocol's
  block, and the first keeps its historical prefix so an upgrade never moves a
  tunnel whose config has already been handed out.

Measured end to end from an external client after the fixes: WireGuard
60.7 MB/s, AmneziaWG 50.7 MB/s — both had been carrying zero bytes.

### Fixed — security

- **A reseller could delete any user in the panel**, including another
  reseller's customers or the owner's. `handleDeleteUser` went straight to
  `DeleteUserCascade` on the raw path id while all six other user routes scope
  through `userOr404` first, and `/api/admin/users` is `tenantMgmt`. Deletion
  is the one operation in that set with nothing to undo it. It now 404s,
  matching the other routes, so a reseller cannot probe which user ids exist
  outside their tenancy.
- **Engine state is owner+admin for reads, not just mutations.** It sat in the
  dashboard-read set, and its payload carries each core's recent log lines —
  for Xray, per-connection accept lines with client addresses and
  destinations.

### Fixed — supervision

- **A Brook process that died instantly lost the message saying why.** The
  reaper called `cmd.Wait()` while both output pumps were still reading;
  `StdoutPipe`/`StderrPipe` are explicit that `Wait` closes the pipes, so when
  `Wait` won the race the crash output was dropped — and for a process that
  dies on startup that is the entire diagnosis. It surfaced as a supervisor
  test timing out under load rather than as a wrong answer, so it read like a
  slow machine and had already had its patience raised to sixty seconds.
  Proven by reverting the ordering under a 40-run test: run 4 kept none of the
  output.

### Added

- **`forgectl update --from-dir` and `--mirror`.** The hosts this panel runs on
  are frequently behind a restrictive egress filter; one reaches Cloudflare,
  the Ubuntu archives and Launchpad but cannot open a socket to any GitHub
  host. There was no supported way to update such a box at all — only placing
  binaries by hand, which skips every checksum the online path enforces. Both
  new modes keep all of it.
- **A "Direct configs" section** on the subscription page for the protocols a
  subscription URL cannot carry, each card headed by its protocol and naming
  the client that can read it. AmneziaVPN and the standalone AmneziaWG app are
  different clients with different formats, and only the latter imports a
  `.conf`.

### Fixed — the updater

- **An upgrade discarded the panel's own port and domain.**
  `load_existing_config` saw `panel.json`, set a flag and returned without
  reading it, so a non-interactive upgrade ran the wizard defaults, replaced
  the binaries, health-checked port 2053 and rolled back reporting only
  "Installation did not pass validation". Every box on a non-default port was
  un-updatable, and the failure named nothing.
- **The release shipped a stale sing-box.** `.singbox-stage/` lives outside
  `dist/`, so `--clean` never touched it and the upload glob is a version
  wildcard; v1.21.0 went out carrying both 1.13.21 and a leftover 1.13.15.

### Fixed — the form

- **Save is refused while the server says the config is invalid.**
  `/studio/preview` already ran the same `model.Validate()` as the create
  endpoint and returned `ok: false` with the reason; the form ignored that
  field and left Save live, so the operator pressed it and got a toast
  repeating a message they had scrolled past. Only the server's own verdict
  refuses — never an advisory warning, never a preview still in flight or one
  that failed to reach the server. No validation rule is duplicated in the
  frontend.

## v1.21.0 — Presets that actually connect, AmneziaWG 3.1, and a dashboard

Eight commits. The theme is the gap between "the panel wrote a config file"
and "something can connect to it".

### Added

- **Six new presets** — Hysteria2, TUIC v5, AnyTLS, ShadowTLS+SS2022,
  WireGuard and AmneziaWG — taking the catalogue from 7 to 13. Each is gated
  on what the deployment can actually carry, so a UDP protocol is not created
  on a platform that routes no UDP.
- **AmneziaWG 2.0, 3.0 and 3.1.** The panel could only generate 1.5-era
  configs, so against any 3.x server it produced something that never
  completes a handshake. Adds S3/S4 and the I1–I3 custom junk packets,
  `HeaderProtectionKey`, `ContentPaddingAddition`, the rekey/keepalive timing
  ranges, `AdvancedSecurity`, and 3.1's `RandomTrailers` and `DisableCookies`.
  H1–H4 became ranges, which an int could not hold. A generation selector
  decides which keys are written, because these parameters are two-sided: a
  3.x key in a 1.5 peer's config does not degrade, it stops the handshake.
- **An Engines page.** `/api/admin/engines` had always reported live core
  state — pid, restarts, responsiveness, recent log lines, kernel interfaces —
  and the only way to read any of it was curl.
- **An operational Overview.** CPU, memory, disk, network, uptimes, account
  and inbound counts, protocol distribution, read from `/proc` and the
  database.
- **Kernel WireGuard as a selectable datapath** (`kernel-wg`), and the
  per-inbound engine override it needed: `Registry.EngineChoice` had existed
  since the registry was written and nothing ever set the hook.
- **Native client configs** for the protocols a subscription URL cannot carry,
  with a QR of the config itself.

### Fixed

- **ShadowTLS could never authenticate anyone.** The served inbound keyed each
  user on their own password while the subscription handed out the inbound's
  template password, so every connection died with `hmac mismatch` while the
  port looked open.
- **The CDN presets' 526.** The CDN host was never registered in the domain
  registry, so certificate issuance was refused and the origin served no TLS.
- **A WireGuard share link carried the server's private key.**
- **`WireGuardOptions.Peers` was rendered by nothing**, so an inbound with five
  users assigned still served one peer.
- **ForgeDNS could only ever run one of its three backends**, which all bound
  the same port.

### Changed

- sing-box 1.13.15 → 1.13.21, with the ForgePanel build carrying
  `with_v2ray_api` rebuilt to match. Without it, hysteria2, TUIC, AnyTLS,
  ShadowTLS and WireGuard are unmetered.


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
