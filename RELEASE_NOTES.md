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
