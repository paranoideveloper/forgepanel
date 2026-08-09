# ForgePanel v1.10.0 — Release Notes

## Feature: "Pattern" (unsafe-uTLS) subscription variant — normal + patt

Both the **user subscription** and the **ForgeEdge worker subscription** can now
serve the anti-DPI "patterniha" variant of VLESS/Trojan/VMess links, alongside
the normal ones.

The pattern adds three params to a TLS link: **`cs`** (a custom cipher-suite
list), **`fm`** (the two-stage TLS fragment), and **`fp=unsafe`**. The one thing
that makes hand-rolled configs fail is shipping `fp=unsafe` *without* `cs=` —
the unsafe fingerprint carries no ciphers of its own, so an empty cipher list
kills the handshake. ForgePanel always emits `cs` with it, so the variant works.

- **Per-link**: `…/sub/<token>/links?patt=1` (pattern only) or `?patt=both`
  (normal + a `· Patt` copy of each link). Works on the base64/v2ray format too.
- **Default**: a **Pattern (unsafe-uTLS)** selector in Users → Subscription
  defaults (Off / Pattern only / Both), plus `sub_pattern_default`.
- Applies only to TLS VLESS/Trojan/VMess; other protocols and non-TLS links are
  untouched. Needs a recent Xray client (v2rayNG ≥ 1.9 / v2rayN / Husi); older
  clients ignore the extra params.

The edge worker mirrors the exact same params (shared preset), so a user's single
link behaves identically whether it comes from the VPS or the Cloudflare edge.
Verified: the generated link carries `fp=unsafe` + the full 13-cipher `cs` + the
two-stage `fm`, decodes cleanly, and the Go↔TS drift golden still matches.

---

# ForgePanel v1.9.7 — Release Notes

## Docs & repo hygiene (release fully in sync with main)

- **Fixed the install-command version.** The copy-paste install snippets in the
  README and `docs/INSTALL.md` were pinned to an old `v1.8.0` (each release only
  rewrote the *previous* version, so they never advanced). They now track the
  current release.
- **Documented everything from the 1.9 line.** `docs/API.md` gains the ForgeEdge
  (`/api/admin/edge/*`), geoip (`/api/admin/geoip`) and subscription-settings
  endpoints, and describes the browser subscription landing page. `docs/CONFIGURATION.md`
  gains a **Telegram bot** section (env vars + every admin command). The README
  feature list now reflects per-user Shadowsocks, online/last-seen, the QR sub
  page, naming templates + geoip, ForgeEdge WARP/AmneziaWG, and Telegram management.
- **Re-synced the tracked `install.sh.sha256`** with the current `install.sh`
  (it had drifted after a shellcheck fix; the released asset was always
  regenerated correctly, so downloads were never affected).

No code or binary behaviour change — this release only brings the docs, the
install instructions and the tag in line with `main`.

---

# ForgePanel v1.9.6 — Release Notes

## Maintenance: green CI + docs, release in sync with main

A sync release so the tagged build and binaries match `main`:

- **CI is fully green again.** Fixed the ForgeEdge worker `tsc --noEmit` type-check
  (a `CryptoKey | CryptoKeyPair` cast in the WARP key generator) and the Code
  Hygiene job (a `shellcheck` unused-variable + `A && B || true` in `install.sh`,
  a `staticcheck` ST1018 on an invisible character, and `gofmt`). No functional
  change — the WARP fix is TS-only (erased at build) and the installer behaves
  identically.
- **README refreshed** to list everything shipped in the 1.9 line: per-user
  Shadowsocks (SS-2022), online/last-seen presence, the QR subscription landing
  page, node-naming templates + country auto-detect, the ForgeEdge one-click
  Cloudflare edge with free WARP + AmneziaWG, and Telegram user management.

Nothing to change on an existing install beyond the normal
`sudo bash install.sh --update`.

---

# ForgePanel v1.9.5 — Release Notes

## Feature: manage users from Telegram

The built-in Telegram bot was read-only (`/stats`, `/user`, `/sub`). It now does
full **user management** from chat, so you can run the panel from your phone:

- `/adduser <name>` — create a user (returns its subscription token)
- `/deluser <name>` — delete a user
- `/enable <name>` · `/disable <name>` — cut a user off or restore them
- `/reset <name>` — zero their traffic (and lift an over-quota cap)
- `/limit <name> <GB>` — set the data cap (0 = unlimited)
- `/extend <name> <days>` — extend expiry (from the later of now / current expiry)

Every command is **admin-only** (the chat IDs in `FORGEPANEL_TELEGRAM_ADMINS`),
validates its arguments, and reports "user not found" rather than failing
silently. A change made from Telegram **reloads the running cores immediately** —
exactly like an edit from the web panel — so a disabled or deleted user stops
being served at once, and status transitions (reset lifts a limited user, extend
revives an expired one) match the web panel's semantics.

Enable the bot by setting `FORGEPANEL_TELEGRAM_TOKEN` (from @BotFather) and
`FORGEPANEL_TELEGRAM_ADMINS` (comma-separated Telegram chat IDs), then restart.

Verified: the command router (auth-gating, arg validation, every mutation) is
unit-tested, and the store integration is exercised end-to-end (create → disable
→ limit → reset → extend → delete, plus not-found and duplicate paths).

---

# ForgePanel v1.9.4 — Release Notes

## Feature: country auto-detect (one-click flag for naming templates)

The inbound form's Country field now has a **Detect** button: it geolocates the
inbound's address (or the panel's own IP when the address is blank) and fills in
the ISO code, so `{FLAG}`/`{COUNTRY}` in the naming template need no manual entry.

- Uses public, key-less geoip services (ipwho.is, ipapi.co, ip-api.com) tried in
  order with fallback — **no database bundled, no license, no binary bloat**.
- Runs on the panel host (not the browser), so it works regardless of CORS and
  uses the server's own network.
- A host that resolves to a **private/LAN address** (panel behind NAT) is never
  sent to a provider — it geolocates the panel's real egress IP instead.
- Graceful: if every provider is unreachable (a locked-down network), the button
  says so and the operator just types the 2-letter code — nothing breaks.

Verified: live lookups return the right country (8.8.8.8 → US, 1.1.1.1 → AU),
provider fallback works, a non-alpha-2 answer is rejected, a private IP is not
leaked, and the `/admin/geoip` endpoint returns the code + flag. New endpoint
`GET /admin/geoip?host=<addr>`.

---

# ForgePanel v1.9.3 — Release Notes

## Feature: node-naming templates ({FLAG} {NAME} {COUNTRY} …)

Every config in a subscription can now be named from a template instead of just
the inbound's remark — the flag-and-name style clients show in their server list.

- A **Config name template** field (Users → Subscription defaults) with tokens:
  `{FLAG} {COUNTRY} {NAME} {PROTOCOL} {NET} {TLS} {PORT} {HOST} {USER} {NUM} {DATE}`.
  e.g. `{FLAG} {NAME} · {NET}` → **🇩🇪 Berlin · ws**.
- A **Country** field per inbound (ISO 2-letter, e.g. `DE`) drives `{FLAG}` and
  `{COUNTRY}` — the flag is built from the code with no geoip database or network
  lookup (Regional Indicator emoji), so it is instant and offline.
- **Opt-in and safe**: a blank template leaves every node's own remark exactly as
  before; unknown tokens are left verbatim so a typo is visible, and an empty
  flag never leaves a stray gap.

The template is applied when the subscription is built, after every field it can
interpolate (address, port, protocol, transport) is final, so the names are
always accurate. The flag rides in the link's `#fragment` percent-encoded — the
standard form every client decodes back to the emoji.

Verified: `{FLAG} {NAME} · {PROTOCOL}` on a `DE` inbound renders **🇩🇪 Berlin ·
vless** in the served subscription; model + end-to-end tests cover the flag
mapping, token expansion, and the opt-in default.

---

# ForgePanel v1.9.2 — Release Notes

## Feature: QR codes on the subscription landing page

Opening your subscription link in a browser already showed a friendly page with
per-client import buttons. It now shows a **scannable QR code on every client
card** — the natural way to import on a phone: open your VPN app, choose “add
subscription / scan QR”, and point the camera at the code for your app.

- One QR per client (v2rayNG/NekoBox, Hiddify, Streisand, Clash/Mihomo,
  sing-box, Xray JSON), each encoding that app's exact subscription link, so a
  scan imports the right format.
- Added **Streisand** one-tap import; kept Hiddify / Clash / sing-box deep-links.
- A short **Persian** help line for family who prefer Farsi.

The QR is a self-contained inline SVG rendered server-side — crisp at any size,
no client-side library, no external requests. Verified end-to-end: the QR the
server emits **decodes back to the exact subscription URL** (checked with a real
QR decoder), and every client card carries one.

Proxy clients are unaffected — the page is served only to a real browser (browser
User-Agent + `text/html` Accept + no proxy-client token); `?raw=1` opts out.

---

# ForgePanel v1.9.1 — Release Notes

## Feature: online / last-seen status per user

The Users table now shows a live presence dot per user — green when they are
online, grey when not — with a hover tooltip ("active 12s ago", "last seen 4m
ago", "never seen").

"Online" is derived from a new `last_seen_at`, which the traffic-poll cycle
stamps whenever a user actually moves bytes. That makes it **core-agnostic** —
it works identically for xray and sing-box and every protocol, instead of
depending on a core-specific connection API. The Users view refreshes the rows
every 30s so the dots stay live without a page reload; the field is exposed on
`GET /admin/users` as `last_seen_at`.

Verified: the poll cycle stamps `last_seen_at` only for users with a non-zero
traffic delta (an idle user is not marked online), and the field round-trips
through the API. Existing installs get the column on the next start (auto-migrated).

---

# ForgePanel v1.9.0 — Release Notes

## Feature: true per-user Shadowsocks (SS-2022 multi-PSK)

Shadowsocks was the last protocol still handing every user one shared key — so
you could not attribute traffic, apply per-user quota, or revoke one user without
rotating everyone. SS-2022 (`2022-blake3-*`) carries a per-user identity header
(EIH), and ForgePanel now uses it:

- Each user on an SS-2022 inbound gets their own PSK, derived deterministically
  from their identity, materialized into the served inbound (xray `clients[]`,
  sing-box `users[]`) keyed by email for per-user stats and quota.
- Their subscription hands out `serverPSK:userPSK`, so the link authenticates as
  that user and no one else. Revoking or limiting one user no longer touches the
  others.
- A non-2022 method (aes-256-gcm, chacha20, …) has no identity header and stays a
  single shared key — unchanged.

Verified end-to-end against the real cores (xray v26.3.27 and sing-box 1.13.15):
a single SS-2022 inbound with two users authenticates each with their own PSK,
tunnels real traffic, and rejects a wrong PSK — cross-core (xray client ↔
sing-box server) too. The full-matrix connectivity test now exercises the
per-user path.

## Hardening: over-quota enforcement lifecycle

Added regression coverage for the two halves of quota that actually cut a user
off and let them back in: a limited/disabled/expired user is excluded from the
built engine config (the core refuses their traffic on the next reload), and a
periodic quota reset reactivates a limited user — but never resurrects one past
their expiry. No behavior change; the path was already correct.

---

# ForgePanel v1.8.3 — Release Notes

## Polish: the Worker's own panel WARP section is now honest and usable

Following v1.8.2 (WARP self-registration is impossible from a Worker — Cloudflare
refuses the edge→WARP-API request), the Worker's built-in panel still showed a
"register" button that could only ever fail. It is replaced with:

- a clear note that ForgePanel provisions WARP for you (Deploy → ⚡ WARP + Amnezia), and
- a **paste-accounts** box so a *standalone* Worker (deployed without ForgePanel)
  is still usable: register WARP anywhere (e.g. `wgcf`) and paste the accounts
  JSON to store them — the same import endpoint ForgePanel drives.

No functional change to the ForgePanel flow; this only fixes the standalone
Worker's own panel. 323 worker tests + Go suites pass.

---

# ForgePanel v1.8.2 — Release Notes

## Feature: free WARP + AmneziaWG from the ForgeEdge panel (one click)

The ForgeEdge tab now provisions **free Cloudflare WARP** and **AmneziaWG**
(DPI-obfuscated WireGuard) straight into a deployed edge's subscription — the
BPB/Nova headline feature, driven entirely from ForgePanel:

- **⚡ WARP + Amnezia** per deployment registers a WARP account pair and the
  edge's subscription immediately starts serving the WireGuard + AmneziaWG nodes
  (the feed is re-pushed automatically).
- **Amnezia .conf / WG .conf** download buttons hand you the wg-quick config for
  import straight into the Amnezia app or any WireGuard client.

### Why registration runs on the panel, not the Worker
A Cloudflare Worker cannot register WARP itself: a `fetch()` to
`api.cloudflareclient.com` (a Cloudflare-owned host) is refused by the edge
(error 1104) — the same CF→CF block that stops a Worker connecting to a
Cloudflare IP. Verified against the live edge. So ForgePanel registers WARP on
the VPS (which reaches the WARP API fine) and pushes the accounts into the
Worker's KV. To make that machine-to-machine call possible without the Worker's
admin password, the deploy now injects a `FEED_PUSH_TOKEN` binding the panel
knows up front — which also fixes feed-push for freshly deployed edges.

Verified end-to-end against a live Cloudflare Worker: the panel registers two
real WARP accounts, pushes them to the edge, the Amnezia .conf carries the junk
params with `S1=S2=0` (handshake-safe for WARP's non-Amnezia server), and the
edge's Clash subscription serves `amnezia-wg-option` alongside WireGuard and
VLESS. 323 worker tests + the Go edge/api suites pass.

---

# ForgePanel v1.8.1 — Release Notes

## Fix: WARP "Pro" (AmneziaWG) configs now actually connect and reach Clash

The edge already registered Cloudflare WARP accounts and emitted an AmneziaWG
"Pro" node (WireGuard + junk-packet DPI obfuscation) — but two bugs made that
node look present while being unusable:

- **`s1`/`s2` were clobbered to 86/574, corrupting the WARP handshake.** WARP's
  server is not AmneziaWG-aware, so the tunnel deliberately sets `S1=S2=0` (only
  the standalone junk *packets* Jc/Jmin/Jmax are safe; init-packet junk is not).
  Config normalization tested `if (!a.s1)`, which treats the intentional `0` as
  "unset" and overwrote it — so every WARP-Pro config carried non-zero init junk
  and never completed a handshake. Normalization now preserves an explicit `0`.
- **Clash dropped AmneziaWG entirely.** The Clash renderer had no `amneziawg`
  case, so the node threw `ClashUnsupportedError` and vanished from every Clash
  subscription. Clash.Meta/mihomo *does* support it — the renderer now emits a
  `wireguard` proxy with an `amnezia-wg-option` block (Jc/Jmin/Jmax/S1/S2/H1–H4).

Verified against Cloudflare's live consumer API: two real WARP accounts register,
the Pro node carries `s1=s2=0`, and the subscription renders VLESS + Trojan
everywhere, plain WireGuard WARP in links/clash/sing-box/xray/json, and AmneziaWG
in Clash (`amnezia-wg-option`) + the canonical JSON. sing-box and xray correctly
omit AmneziaWG (those cores cannot express it). 320/320 worker tests pass.

---

# ForgePanel v1.8.0 — Release Notes

## Feature: ForgeEdge in the panel — one-click Cloudflare edge

ForgePanel already had a full ForgeEdge subsystem (a Cloudflare Worker that
terminates **VLESS + Trojan over WebSocket** at the edge, serves DoH, and serves
the **same canonical subscription your VPS does** — so a user's single link works
even where your server IPs are throttled). It had no way to use it from the UI.

- **New ForgeEdge panel section.** Paste a Cloudflare API token (a button opens
  the token-creation page pre-filled with the exact scopes) + your account ID,
  and **deploy with one click** — then manage deployments, push the current feed,
  open the worker's panel, and delete. The token is used per-request and never
  stored on the panel.
- **The worker bundle is embedded in the panel binary.** Deploy no longer
  requires a checked-out Worker source or a JS toolchain; `POST /admin/edge/deploy`
  defaults to the compiled-in bundle (regenerated with `make edge-bundle`). New
  endpoints: `GET /admin/edge/token-url` and `/admin/edge/bundle`.

Verified end-to-end: a deploy from the panel ships the embedded worker to
Cloudflare (KV namespace created, live on workers.dev, panel reachable) and
delete tears it down; the Worker's own test suite passes 316/316.

---

# ForgePanel v1.7.8 — Release Notes

## Fix

- **Per-user credentials for SOCKS and HTTP inbounds.** `stampIdentity` put each
  user's `username`/`password` in their subscription, but the served config kept
  the single *template* account — so a user's credential was rejected (auth
  mismatch) while only the inbound's own login worked. `applyXrayClients` now
  expands `settings.accounts` to one `{user, pass}` per assigned user (and sets
  SOCKS `auth: password`), so every user authenticates with their own login.
  `ClientCred` carries the username end to end. Verified through the real xray
  core: a SOCKS/HTTP inbound with two users now carries two distinct accounts and
  each user's own credential authenticates.

  Note: per-user *accounting/quota* for SOCKS/HTTP remains an xray limitation —
  its `accounts` have no stats tag, so traffic can't be attributed per user
  (per-user auth works; per-user quota does not). Shadowsocks still uses one
  shared key; true per-user SS needs SS-2022 multi-PSK (tracked next).

---

# ForgePanel v1.7.7 — Release Notes

## Fix

- **The panel now actually opens the host firewall for custom inbound ports.**
  The hardened systemd unit sets `ProtectSystem=full`, which makes `/etc`
  read-only — but `ufw` persists its rules to `/etc/ufw/user.rules`, so every
  `ufw allow` the panel ran at runtime failed with *"/etc/ufw/user.rules is not
  writable"*. The error was swallowed, so a created inbound on a non-default port
  listened but was **silently unreachable from the internet** (ufw dropped it),
  even though a loopback Verify looked green — the "firewalled" badge with no way
  to fix it. The unit now grants `ReadWritePaths=/etc/ufw` (optional, so hosts
  without ufw are unaffected), and `firewall.EnsureOpen` no longer caches a port
  as opened when the `ufw` call failed — so a transient failure is retried and
  logged instead of marked done forever. Existing installs get the unit fix on
  `sudo bash install.sh --update`.

---

# ForgePanel v1.7.6 — Release Notes

## Fixes

- **Hysteria2 inbounds with an assigned user now serve.** The sing-box user list
  put a `uuid` field on Hysteria2 users, but sing-box's Hysteria2 users are
  `{name, password}` only — its strict decoder rejected the unknown `uuid`
  (`json: unknown field "uuid"`), which failed the *entire* sing-box config load
  and took the engine down, so the inbound listened on nothing. Hysteria2 users
  no longer carry `uuid`; TUIC users (which legitimately use it) still do. This
  is what made a created Hysteria2 inbound "not work" with no error anywhere.

- **Salamander obfuscation gets a password automatically.** Creating a Hysteria2
  inbound with `obfs_type: salamander` but no obfs password produced a config
  sing-box refuses to start (`missing obfs password`). The panel now mints an
  obfs password on create (carried into the client link too), and the renderer
  drops an obfs block with no password rather than letting one misconfigured
  inbound take the whole sing-box engine down.

---

# ForgePanel v1.7.5 — Release Notes

## Fixes

- **ForgeDNS binds automatically around `systemd-resolved`.** On a stock systemd
  host, `systemd-resolved` holds `:53` on loopback, so a zone set to bind the
  wildcard `0.0.0.0:53` failed to start and answered nothing — the operator had
  to disable the stub resolver by hand. The panel now detects the loopback stub
  and binds the server's **public IP** instead (rendered `UDP_HOST`, the bind
  probe and the reported listen address all agree), so a delegated DNS tunnel
  comes up on a fresh box with no manual step and the host keeps its own resolver.
  An explicitly configured bind host is still honored as-is.

- **The panel serves its Let's Encrypt certificate instead of "Not Secure".**
  autocert issues per key type; when it held, say, an RSA certificate but a modern
  browser offered ECDSA, it tried to *re-issue* on the handshake — a fresh order
  that stalled and, on failure, dropped back to the self-signed certificate even
  though a perfectly valid Let's Encrypt cert was already on disk. The panel now
  serves the cached certificate directly, so a domain that has issued once is
  presented as trusted. Certificates within their renewal window still route
  through autocert so renewal happens.

- **Panel-certificate priming no longer swallows its error.** `PrimePanelCert`
  discarded the ACME result (`_, _ =`), so a genuinely failing order left the
  panel self-signed with an empty `renewal_error` and nothing in the log. It now
  records the outcome (visible in `forgectl cert status` and the UI) and logs a
  failure to the journal.

---

# ForgePanel v1.7.4 — Release Notes

## Fix

- **ForgeDNS encryption key is now 32 characters, not 64.** `GenerateKey` minted
  32 random bytes hex-encoded (a **64-char** key), but StormDNS / CottenDNS /
  MasterDNS treat `ENCRYPTION_KEY` as a fixed **32-char** secret and their
  **clients reject a 64-char key outright**. The server (with the XOR cipher)
  quietly accepted the long key, so the panel and server *agreed* — but the
  client could never connect, which looked like a key mismatch. Keys are now 16
  bytes → 32 hex chars, matching the format every StormDNS deployment uses.
  Existing zones keep their stored key; recreate a zone (or reset its key) to
  mint a correct-length one.

---

# ForgePanel v1.7.3 — Release Notes

## Fix

- **Installer no longer rolls back on a slow first boot.** `install.sh` probed the
  health endpoint **once**, immediately after `systemctl restart`. Because the unit
  is `Type=simple`, restart returns before the panel has opened its SQLite DB, run
  migrations, initialised the engines and (with a domain) started ACME — so the
  probe raced the listener, saw `connection refused`, and the installer restored
  the previous state. It now **polls the health check for up to 40 s**, and if the
  service has actually failed it stops early and prints the recent `journalctl`
  log instead of a bare rollback.

---

# ForgePanel v1.7.2 — Release Notes

## Honest status (no more false "broken")

- **Verify no longer lies for REALITY / UDP protocols.** A working REALITY, TUIC,
  Hysteria2 or WireGuard inbound showed a red ✗ because the loopback verifier
  can't prove them (REALITY needs a live TLS-1.3 dest; the others listen on UDP,
  which the TCP readiness gate never sees). These now report a neutral **“— n/a”
  (can't prove on loopback — test from a client)** instead of a failure.
- **Firewall badge respects ufw's default policy.** The 🔥 warning fired whenever a
  port wasn't in ufw's explicit allow list — but if the default incoming policy is
  *allow* (many VPS images), the port is reachable anyway. It now only warns when
  the default is deny/reject, so a working inbound stops being flagged.

## ForgeDNS

- **Multiple tunnel domains.** CottenDNS/MasterDNS/StormDNS all handle a `DOMAIN`
  array; the create form now takes additional comma-separated domains (each must
  be delegated to this server), not just one.

## Fixes

- **Accurate transport labels.** WireGuard/AmneziaWG show **udp** and Hysteria2/TUIC
  show **udp/quic** instead of a meaningless `tcp` (WireGuard is a UDP protocol by
  design — it can't be TCP).

---

# ForgePanel v1.7.1 — Release Notes

## Docker without building

- **Prebuilt image on GHCR.** Every release now publishes a multi-arch image at
  `ghcr.io/paranoideveloper/forgepanel:<tag>` (+ `:latest`), built on GitHub's
  runners. On a server whose build network can't reach the Alpine mirrors,
  `docker build` can never succeed — so **pull instead**:
  `docker run … ghcr.io/paranoideveloper/forgepanel:v1.7.1`.
- **Compose pulls by default.** `docker-compose.yml` now points at that GHCR
  image, so `docker compose up -d` pulls a ready-to-run image; pass `--build`
  only when you deliberately want to compile from source. Docs updated to lead
  with the pull path. No application changes from v1.7.0.

---

# ForgePanel v1.7.0 — Release Notes

## New

- **Setup Wizard.** A guided, BPB/Nova-style onboarding (sidebar → ✨ Setup
  Wizard) that walks a new operator through the whole flow in four steps —
  **domain & automatic TLS → create a VLESS+REALITY inbound → create a user →
  share** — ending on a QR code, the subscription link, and one-tap client
  import. It orchestrates the existing endpoints, so there's nothing new to learn.
  Verified end-to-end (desktop + mobile) against the built binary.

## Fixes

- **Node enrollment 404.** The Node Cluster UI handed out `/api/node/install.sh`
  but the script was only served at `/node-install.sh` — so the copy-paste
  one-liner 404'd. That path is now an alias; the enroll command works as shown.
- **System & Security health matrix was blank.** The Subsystem Health Matrix
  rendered coloured dots with no labels (it read `name`/`healthy`/`detail` while
  the API returns `label`/`state`/`summary`). It now shows the real subsystem
  name, status colour and summary.
- **Mobile layout.** Wide tables (Inbounds) now scroll inside their card instead
  of pushing the page sideways; the System page's multi-column grids and the
  change-password / export rows stack on a phone; the firewall badge tooltip is
  clearer about host vs. VPS-provider firewalls.
- **Hands-off packages.** The `.deb`/`.rpm` now declare `ca-certificates` as a
  dependency (soft-recommend the network tools) and **open the firewall in their
  post-install** (panel port, 80, 443, 53) — so a package install provisions TLS
  reachability itself, matching `install.sh`.

---

# ForgePanel v1.6.3 — Release Notes

## Fix

- **Resilient Docker build.** `apk add` in the Dockerfile failed on flaky,
  rate-limited or partly-censored build networks with `temporary error (try again
  later)` (the Alpine CDN is dual-stack via Fastly and some VPSes advertise IPv6
  with no route). Both build stages now **retry across several Alpine mirrors**
  (dl-cdn, Fastly, uk.alpinelinux.org, leaseweb, kernel.org) before failing, so
  `docker compose up -d --build` succeeds anywhere with any working egress instead
  of dying on one bad CDN. If the build network genuinely can't reach any mirror,
  use the prebuilt static binary or `.deb` from this release — they need no build.

---

# ForgePanel v1.6.2 — Release Notes

## New

- **Subscription landing page.** Opening a subscription URL in a **web browser**
  now shows a friendly page — a usage/expiry summary and, per client family
  (Clash/Mihomo, sing-box, Hiddify, v2rayNG/NekoBox, Xray, Base64), a one-click
  **Import** deep-link plus a **Copy link** button — instead of a wall of base64.
  Proxy clients are never affected: the page is served only to a real browser
  (browser User-Agent + `text/html` Accept + no known client token), and `?raw=1`
  always returns the plain subscription.

---

# ForgePanel v1.6.1 — Release Notes

Rounds out the subscription-tuning features and makes them controllable from the
panel.

## New

- **TLS Fragment (Xray).** The BPB-style DPI-evasion trick: every proxy outbound
  dials through a freedom `fragment` outbound that splits the TLS ClientHello into
  small pieces so an SNI filter never sees a whole handshake. Verified valid by
  the real `xray run -test`. Enable per request with `?fragment=1`
  (`fragment_packets` / `fragment_length` / `fragment_interval` tune it) or as an
  operator default.
- **Subscription defaults in the UI.** A new card under **Users & Subscriptions**
  sets the default **routing preset** (Iran / Full / Block-only / Off) and toggles
  **TLS Fragment** for every generated config — backed by
  `GET`/`POST /api/admin/settings/subscription`. Per-link `?routing=` / `?fragment=`
  still override. Verified end-to-end in a browser against the built binary.
- **The release now ships `install.sh` + `install.sh.sha256`** as assets, so the
  documented one-command install (`curl .../install.sh`) actually resolves — it
  did not before.

---

# ForgePanel v1.6.0 — Release Notes

Feature release: the installer and panel now provision themselves, and
subscriptions carry BPB/Nova-style routing presets.

## Self-provisioning

- **The installer opens the firewall.** After the service is healthy, `install.sh`
  opens the ports the panel binds — the panel port, 80, 443 and 53 — on ufw,
  firewalld or (only when there is a restrictive policy) iptables. No more "cert
  won't issue / DNS never answers" because a port was closed. On a host with no
  managed firewall it prints exactly which ports an external firewall must allow.
- **TLS comes up without a restart.** The `:80` ACME HTTP-01 helper is now a
  managed listener: saving a panel domain from the UI starts it and primes the
  certificate immediately, and clearing the domain releases port 80. Previously a
  domain saved after boot needed a manual restart before Let's Encrypt could work.

## Routing presets (sing-box · Xray · Clash)

- Generated **sing-box, Xray and Clash** subscriptions can now carry routing
  rules: **bypass Iran** (domestic domains/IPs go direct), **direct LAN**, **block
  ads/trackers**, **block malware/phishing**, **block adult content**, and **block
  QUIC**. Verified valid by the real `sing-box check` and `xray run -test`.
- sing-box rule-sets download **through the proxy** (`download_detour`), so a
  blocked GitHub from inside Iran is a non-issue; Xray uses the geoip/geosite
  databases clients already bundle (no fetch).
- Controlled by a per-request query string — `?routing=iran|full|block|off` plus
  fine-grained `bypass_iran` / `block_ads` / `block_malware` / `block_porn` /
  `block_quic` / `direct_lan` flags — over an operator default (setting
  `sub_routing_preset`, defaulting to the Iran preset).

---

# ForgePanel v1.5.8 — Release Notes

Honesty fix for the Certificates page after an ACME failure on a server where only
the panel port was open.

## Fix

- **"Browser-trusted" banner no longer lies.** The green "you are viewing over the
  domain — browser-trusted certificate" banner was decided purely by hostname
  match, so it claimed trust even while the browser showed "Not Secure" (ACME
  still pending, self-signed served). It now checks the real cert state: it turns
  green only when a trusted cert is actually live, and otherwise explains that no
  cert has been issued yet and that Let's Encrypt needs **port 80** reachable from
  the internet (and, on Docker, published `80:80`) — plus that a domain saved
  after startup needs one panel restart to start the ACME helper.
- The domain-setup hint now states the port-80 requirement up front.

---

# ForgePanel v1.5.7 — Release Notes

Fixes a silent ForgeDNS tunnel breaker found by running a real MasterDNS zone: the
client config advertised a key the server never used.

## Fix

- **Encryption-key mismatch (client ≠ server).** The panel mints a 32-byte key and
  writes it to the server's `encrypt_key.txt`, but MasterDNS rejects a key whose
  length doesn't fit its cipher, generates its own 16-byte key, and overwrites the
  file on every start. The client bundle kept advertising the panel's key, so the
  two ends could never decrypt each other's traffic. The panel now **reads the
  effective key back** from the running server and adopts it — during the
  post-sync reconcile and again when the delegation bundle is rendered — so the
  client config always carries the key the server actually holds. It converges
  after one sync (the adopted key is a length the upstream keeps, so subsequent
  starts are stable). A partial/garbage key file is never adopted (hex-validated).

---

# ForgePanel v1.5.6 — Release Notes

Follow-up to v1.5.5 after running a real ForgeDNS zone end-to-end on a Docker
host: the tunnel process ran and was correct, but two things bit.

## Fixes

- **Delegation A-record showed the Docker-internal IP.** `detectServerIP()` returns
  the outbound-route local address, which behind Docker/NAT is a private bridge IP
  (e.g. `172.18.0.2`) — useless in a public DNS record. New `publicServerIP()`
  detects that case and resolves the panel's own configured domain (which points
  at the server's real public address) instead. Used for the ForgeDNS delegation
  bundle, the panel-address `server_ipv4`, and the DNS-check "points here" verdict.
- **Setup panel now states the port requirement.** ForgeDNS's authoritative
  listener binds `0.0.0.0:53`, but a zone is unreachable unless **53/udp** is open
  on the host firewall and (under Docker) published to the container. The
  delegation view now says so explicitly — a running listener that never receives
  a query is the most confusing failure mode there is.

---

# ForgePanel v1.5.5 — Release Notes

Fixes the **ForgeDNS — DNS Tunnels** page, which "showed nothing": the wire-format
adapter dropdown was blank and creating a zone silently failed. Root causes were
Go↔TypeScript contract drift, verified end-to-end against the built, embedded
binary (screenshot in `e2e/test-results/forgedns.png`).

## Fixes

- **Blank adapter dropdown.** `/forgedns/adapters` returned a bare `[]string`, but
  the UI renders `{id,name}` objects — so every `<option>` had an empty value and
  label. It now returns the **upstream (bundle-capable) adapters** (CottenDNS,
  StormDNS, MasterDNS) as `{id,name,description}`.
- **Adapter family mismatch.** The dropdown offered native codec names (e.g.
  `forge`) that can't produce a delegation bundle, so "Setup Info" came up empty.
  The dropdown now lists exactly the adapters that yield a working bundle.
- **Zone creation silently failed.** The form POSTed `{domain,…}` but the API keys
  a zone on `{zone,…}`; the view also read `domain`/`active` while the API returns
  `zone`/`enabled`. Aligned the view (and its standalone `/forgedns` twin, now a
  thin wrapper over the shared component) to the real contract.
- **Setup panel wired to the real bundle.** "Setup Info" now fetches
  `/forgedns/zones/:id/bundle` and shows the delegation A/NS records, the
  Cloudflare grey-cloud warning, the client SOCKS5, the full `client_config.toml`
  (with copy), and step-by-step delegation instructions. The bundle's A-record now
  defaults to the server's public IP when no `?ip=` is given.
- Empty-state text and a responsive create row (no more overlapping controls on
  mobile).

---

# ForgePanel v1.5.4 — Release Notes

Fixes the **Certificates & Panel Domain** page so automatic Let's Encrypt TLS is
correct and self-explanatory. The ACME machinery already worked — a real cert is
issued over the domain via HTTP-01 on `:80` — but the page misreported it and the
controls fought the "HTTPS is always on" model. Verified end-to-end against the
built, embedded binary on a live host: `https://<domain>:2053/` serves a
browser-trusted Let's Encrypt certificate (`ssl_verify=0`), while the bare IP
still shows the self-signed fallback (unavoidable — SNI can't match on an IP).

## Fixes

- **Cert status & DNS check now read the real backend fields.** The view consumed
  the wrong JSON keys (`resolved`/`ip` vs. `resolves`/`a`/`points_here`, and the
  imported-cert list vs. the live `panel-address.cert`), so it *always* showed
  "DNS failed to resolve" and "Self-Signed / Indefinite" even when a valid ACME
  cert was live. It now shows the true issuer, expiry, days-remaining, and a
  DNS-points-here verdict.
- **Saving a panel domain enables HTTPS/ACME.** TLS is always served, so attaching
  a domain now implies you want a trusted cert for it — no separate toggle needed.
- **"Force ACME Issue / Renew" no longer requires a vestigial HTTPS flag.** It only
  needs a configured domain; issuance is on-demand for any registered domain.
- **Cert priming at boot.** When a domain is configured the panel issues/renews its
  certificate in the background at startup, so the first visit over the domain is
  already trusted instead of stalling on a first-time order.
- **IP-vs-domain guidance.** The page now states plainly that opening the panel by
  IP will always be marked "Not Secure", and links the domain URL to use instead.
- A domain change is now reported as `restart_required` (the `:80` ACME helper and
  the public URL derive from the boot-time domain).

---

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
