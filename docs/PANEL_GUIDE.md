# ForgePanel — Complete Operator Guide

ForgePanel is a self-hosted proxy-management panel. It runs and supervises the
proxy engines (xray-core and sing-box) on the same server, generates the client
configs and subscriptions, manages users and their quotas, obtains TLS
certificates, opens the firewall, and can deploy a Cloudflare-Worker edge. This
guide walks through every part of the panel, with the **Preset Wizard** — the
one-click "build me a whole working server" feature — covered first and in depth.

---

## 1. Accessing the panel

After install, the panel prints a secret URL (also saved to
`/var/lib/forgepanel/panel-url.txt`), e.g.:

```
https://your-domain-or-ip:2053/panel/<secret-path>
```

- The `<secret-path>` is your first line of defence — the panel is not reachable
  without it. Keep the URL private.
- Log in with the admin username + password you set at first run.
- The panel always serves HTTPS. With a domain it uses a real Let's Encrypt
  certificate; on a bare IP it uses a self-signed cert (your browser warns once).

**Locked out?** With shell access to the server you can reset the admin password
by stopping the service and updating the database (the panel stores admins as
argon2id hashes in `/var/lib/forgepanel/forgepanel.db`).

---

## 2. The Preset Wizard (one-click full server)

**Where:** Setup Wizard tab → the orange card at the top, *"One-click full server
(Preset Wizard)"*.

**What it does.** From two inputs — a domain and (optionally) a Cloudflare API
token — it creates a complete, working, multi-protocol server in one action:
generating keys, choosing non-colliding ports, opening the firewall, wiring the
Cloudflare DNS record, and hot-reloading xray. It exists to eliminate the manual
firewall / certificate / DNS steps that are the usual reason a hand-built server
"looks configured but nothing connects".

### 2.1 What it creates

| Inbound | Port | How it reaches the client |
|---|---|---|
| **VLESS · REALITY · Vision** | 443 | Direct to the server IP. Borrows a rotation of real SNIs. No certificate. |
| **VLESS · REALITY · XHTTP** | 8443 | Direct. XHTTP transport, `/aux` path. |
| **VLESS · REALITY · Brutal** | 8444 | Direct. A second Vision inbound for redundancy. |
| **VLESS · WS · TLS** | 2096 | Behind Cloudflare (proxied sub-domain, edge TLS). |
| **VLESS · XHTTP · TLS** | 2087 | Behind Cloudflare. |
| **VMess · WS · TLS** | 2083 | Behind Cloudflare. |
| **Shadowsocks-2022** | 8388 | Direct. `2022-blake3-aes-128-gcm` AEAD. |

All three REALITY inbounds **share one keypair and short-ID**, so a client can
move between them (and between all the borrowed SNIs) freely.

### 2.2 The two config models — and why "one API key resolves it"

- **REALITY (direct).** The client dials the server's IP directly and pretends,
  in the TLS handshake, to be visiting a real, unblocked website (the "borrowed
  SNI" — the wizard rotates `www.cloudflare.com`, `aparat.ir`, `digikala.com`,
  `snapp.ir`, `discord.com`, `chatgpt.com`, and more). A censor sees a normal
  visit to that site. REALITY needs **no domain and no certificate** — this is
  the most censorship-resistant option and the recommended default for Iran.
- **CDN (behind Cloudflare).** The client connects to a Cloudflare edge, which
  terminates TLS with a valid certificate and forwards to your server on the
  matching port. This is why **one Cloudflare API token is all you need**: the
  same token that creates the DNS record also gives you a trusted edge
  certificate automatically — you never run ACME or copy cert files for these.

The wizard puts the CDN inbounds on Cloudflare origin-pull ports (2096 / 2087 /
2083) and the REALITY inbounds on direct ports (443 / 8443 / 8444), so nothing
collides with the panel (2053), SSH (22) or the xray control port.

### 2.3 Running it

1. Enter the **domain** you want the CDN configs to front behind (it must be a
   zone on the Cloudflare account whose token you paste — e.g.
   `example.org`). REALITY works even with no domain.
2. Paste a **Cloudflare API token** with **Zone → DNS → Edit** on that zone
   (create one at <https://dash.cloudflare.com/profile/api-tokens>). Optional but
   recommended — with it, the DNS record and edge TLS are automatic.
3. Click **⚡ Build full server**.

It reports the inbounds it created, the shared REALITY public key, and any
warnings. If the token is missing or rejected, it still creates **every** inbound
and tells you the single A-record to add manually (a proxied `A` record pointing
the shown `edge-…` sub-domain at your server IP).

### 2.4 After the wizard

- Go to **Users** → create a user and assign it the inbounds (the Setup Wizard's
  user step binds all of them for you), so its one subscription link carries all
  seven configs.
- Open the **Setup Wizard → Share** step (or the user's row) to get the
  subscription URL + QR to hand out.
- The client (Hiddify, v2rayNG, sing-box, Clash Meta, Streisand, NekoBox) imports
  the link and shows all the configs; its best-ping picker chooses the fastest.

### 2.5 Cloudflare SSL mode (for the CDN inbounds)

The CDN inbounds present a self-signed certificate on the origin; Cloudflare's
edge presents the trusted one to the client. For the origin pull to succeed, the
zone's SSL/TLS mode must be **Full** (not "Flexible", not "Full (strict)"). Most
zones are already on Full. If a CDN config fails to connect while REALITY works,
check this setting in the Cloudflare dashboard (SSL/TLS → Overview).

### 2.6 Troubleshooting the wizard

- **"Cloudflare DNS: Authentication error (403)"** — the token is expired,
  IP-restricted, or lacks *Zone · DNS · Edit*. Create a fresh one; meanwhile add
  the A-record from the warning by hand.
- **A CDN config won't connect but REALITY does** — the DNS record hasn't
  propagated yet, or the zone SSL mode isn't *Full* (see 2.5).
- **Nothing connects at all** — check the firewall really opened the ports
  (System Health), and that the ports aren't blocked upstream by your provider.

---

## 3. Inbounds

**Inbounds** are the server-side listeners. Each is one protocol + transport +
security combination on one port.

- **Create** from a **preset** (VLESS-REALITY-Vision, VLESS-WS-TLS-CDN,
  Trojan-WS-TLS, Shadowsocks-2022, Hysteria2, TUIC, WireGuard, Brook, …) — every
  preset is verified to render and validate against the pinned engine, so the
  panel never offers a combination the engine would reject. All fields stay
  editable afterwards.
- **REALITY quick-start** creates a working REALITY inbound with zero inputs (it
  mints the keypair, short-ID and steal-site itself).
- **One-click TLS** switches a domain-based inbound to a real ACME certificate,
  with an honest pre-flight (does the domain resolve here; is port 80 reachable).
- Inbounds can be **cloned**, **enabled/disabled**, **bulk-edited**, and there is
  **one-level undo** on breaking changes.
- **Address** is the *listen* address and stays `0.0.0.0` (all interfaces); the
  panel substitutes your public address into the exported client links. You do
  not put the public IP in the inbound itself.
- Each inbound's own credential (UUID/password) always authenticates, so its
  share link works even before you assign users.

---

## 4. Users & Subscriptions

- A **user** has a username, an optional **data limit** and **expiry**, and a
  private **subscription token**.
- Assign inbounds to a user **directly** or via a **group**; the user's
  subscription is the union.
- The **subscription link** (`/sub/<token>`) renders in whatever format the
  client asks for: v2ray (base64), Clash / Clash-Meta, sing-box, Xray, Surge,
  Loon, Quantumult X, plain links, or JSON.
- **Subscription defaults** (Users view) apply to every generated config:
  - **Routing preset** (bypass-Iran + block ads/malware, or stricter, or off).
  - **TLS Fragment** (DPI-evasion), with a severity — *light*, *medium* (the
    shipped default) or *aggressive* — and the cores that honour it. Xray dials
    through a freedom `fragment` outbound and takes the severity's packet/length/
    interval values; sing-box sets native `tls.record_fragment`, which is a bool,
    so for it the severity only decides on/off. Clash-Meta has no fragment
    primitive at all and cannot be listed — a Clash subscriber is never
    fragmented.
  - **Pattern (unsafe-uTLS)** — the `cs`/`fm`/`fp=unsafe` anti-DPI meta.
  - **Naming template** and the **Fancy config wizard** (emoji/Persian themes +
    SNI/CDN fronting) for styled, camouflaged config names.
- Over-quota / expired users get an empty (but valid) subscription rather than a
  broken one.

---

## 5. Nodes (multi-server)

A **node** is another server this panel federates. Assign inbounds to a node and
the panel renders the client links against that node's address, so one panel can
hand out configs across a fleet. The local server is the implicit node; remote
nodes run the lightweight `forgenode` agent.

---

## 6. Domains & Certificates

- **Domains** is a first-class registry. Setting a domain on an inbound
  **cascades** to its SNI, transport Host header, the exported client address and
  certificate selection — set it once, everything follows.
- **One-click ACME** obtains a Let's Encrypt certificate over HTTP-01 (needs the
  domain pointing here and port 80 reachable). Until a real cert is available the
  panel serves a self-signed one and marks the links `allowInsecure` rather than
  pretending an unverifiable inbound is securely certified.
- **Certificates** lets you import your own cert/key, list what's active, and see
  expiry. The panel's own control-plane cert renews automatically.

---

## 7. ForgeEdge (Cloudflare Worker edge)

Deploy a Cloudflare-Worker VLESS/Trojan edge from the **ForgeEdge** tab: paste a
Cloudflare token + account id, one-click deploy the embedded worker bundle, and
it publishes on `*.workers.dev`. The worker serves the *same* subscription the
VPS does (worker configs + your VPS feed + WARP), fronts across clean Cloudflare
IPs on multiple ports, and can register WARP/AmneziaWG. It also exposes DPI
fallbacks (`?serverless=`, `?smartfrag=`), an end-user import page
(`/import/<token>` with QR), and external-subscription merging. See the ForgeEdge
docs under `deploy/cloudflare/forgeedge/docs/`.

**Configure** on a deployment opens an editor for that Worker's live
configuration — every field it holds, read from the Worker itself a moment
before: clean IPs, ports and protocols, fingerprint, fragment and UDP noise,
proxyIP/NAT64, chain proxy, CDN fronting, DNS, routing rules, WARP tuning,
backend mode and external subscriptions.

Only the fields you change are sent. They are merged into whatever the Worker
currently holds, which has two consequences worth knowing:

- A field newer than your panel build is never touched. The Worker ships on its
  own cadence, and a panel that wrote its own idea of the whole document would
  silently delete every field it had not heard of — discovered days later, when
  whatever depended on it stopped working. Fields the panel has no layout for
  appear under **Other fields** and are editable there.
- Two admins editing different sections do not undo each other.

The Worker validates, and its rejection is shown as-is. The panel deliberately
keeps no copy of the Worker's schema: a second copy drifts, and the drift shows
up as the panel refusing a value the Worker accepts.

`telegramBotToken` and `feedPullToken` are never sent to the browser — they read
as `__unchanged__` and are left alone unless you type a new value. The VLESS UUID
and trojan password are shown, because they are in every subscription link the
Worker hands out already and they are the fields most often rotated.

**Raw JSON** replaces the whole document, including deleting anything you remove.
The form is the safe path.

---

## 7.5 Telegram bot — run the panel from chat

The panel has a built-in Telegram bot (nothing to install separately). Once
enabled, any subscriber can fetch their link from a DM, and admins manage users
without opening the web panel — and **every change reloads the running cores
immediately**, exactly like an edit from the UI.

**Enable it (≈1 minute):**

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token.
2. Message [@userinfobot](https://t.me/userinfobot) → note your numeric `Id`.
3. Put both in `/etc/forgepanel/forgepanel.env` (the installer leaves them there,
   commented, ready to uncomment) and restart:
   ```sh
   FORGEPANEL_TELEGRAM_TOKEN=123456789:AA-your-bot-token
   FORGEPANEL_TELEGRAM_ADMINS=11111111,22222222
   ```
   ```sh
   sudo systemctl restart forgepanel
   ```

**Commands** — everyone: `/sub <token>`, `/help`. Admins also get: `/stats`,
`/user <name>`, `/adduser <name>` (returns the new sub token), `/deluser <name>`,
`/enable <name>` · `/disable <name>`, `/reset <name>` (zero traffic, lifts an
over-quota cap), `/limit <name> <GB>` (0 = unlimited), `/extend <name> <days>`.
Only the chat IDs in `FORGEPANEL_TELEGRAM_ADMINS` can run the admin commands;
everyone else is limited to `/sub` and `/help`.

## 7.6 Bridges (reverse tunnel into Iran)

A **bridge** is a machine users inside Iran can actually reach — a domestic VPS,
a box on an ISP that is not blocked — that forwards their traffic over a single
outbound tunnel to the real server abroad. The exit never accepts an inbound
connection from Iran, so blocking its address achieves nothing, and the bridge
holds no credentials worth stealing.

Four backends, all checked against their own binaries before being offered:

| backend  | pinned  | notes |
|----------|---------|-------|
| Backhaul | v0.7.2  | built for this problem, most used inside Iran. **Raises the host's rmem_max/wmem_max on start**, which changes networking for everything else on that machine |
| rathole  | v0.5.0  | small and strict — rejects an unknown key rather than ignoring it, so a typo fails at start instead of silently disabling a service |
| frp      | v0.71.0 | most mature, and the only one that validates a config without starting (`frps verify -c`) |
| wstunnel | v10.6.2 | tunnels over WebSocket/HTTP2, so the hop looks like ordinary web traffic and survives a CDN or HTTP proxy in the path |

**All four carry UDP.** That is the property that decides whether Hysteria2,
TUIC and WireGuard survive the hop, and it is not cosmetic: a TCP-only bridge
drops exactly the protocols that work best against Iranian DPI, while the
inbound, the bridge and the panel all keep reporting healthy. Every flag was set
from the tool's own binary — see `internal/bridge/backends_verified.md` for the
commands and their output.

The panel manages the **exit** half only, and supervises it across restarts. The
bridge box is by definition a machine the panel cannot reach, so its half is
handed to you as a bundle: the download URL, the pinned SHA-256 to check it
against before running it as root, the rendered config, and the command. Release
assets are digest-pinned, and an asset whose digest does not match is refused
rather than run.

The shared token is generated for you and never appears in the bridge list. It
is the whole of the tunnel's authentication — anyone holding it can attach to
your exit.

A UDP service also needs its port open **inbound on the bridge**. A firewall
that allows only TCP produces a tunnel that reports connected and carries
nothing; the bundle warns about this per service.

---

## 8. ForgeDNS

A DNS toolkit for anti-censorship: manage DNS providers (Cloudflare, ArvanCloud,
deSEC), rotate clean-IP pools, and run the WhiteDNS/StormDNS tunnelling helpers.
Used to keep the addresses your configs point at reachable as they get blocked.

---

## 9. Studio, Overview & System Health

- **Overview** — traffic, active users, engine state, and quick actions at a
  glance.
- **Studio** — a free-form config editor for advanced, hand-tuned setups.
- **System Health** — the honest diagnostics page: engine status and last error,
  which ports are actually listening and reachable, certificate state, firewall
  state, and disk/DB health. This is the first place to look when something a
  config *should* do isn't happening.

---

## 10. How the pieces fit

```
            ┌─────────────── ForgePanel (this box) ───────────────┐
 admin ───▶ │  Panel UI + API   →   generates engine configs      │
            │        │                     │                      │
            │  Users/Inbounds/Domains  supervises  xray + sing-box │──▶ clients
            │        │                     │                      │
            │   subscriptions ◀───────  firewall + ACME + certs    │
            └──────────────────────────────┬──────────────────────┘
                                           │ optional
                                  ForgeEdge (Cloudflare Worker)
```

Everything the panel manages lives in `/var/lib/forgepanel` (the SQLite database,
certificates, engine binaries and generated configs). Back that directory up and
you can move the whole panel to another box.

---

## 11. Quick recipes

- **"Give me a working Iran server, fast."** Setup Wizard → Preset Wizard →
  enter domain + Cloudflare token → Build → create a user → share the link.
- **"Just one bullet-proof config."** Inbounds → REALITY quick-start → assign to
  a user → share.
- **"A config that survives even when every IP is blocked."** Use the ForgeEdge
  worker's `?serverless=` / `?smartfrag=` fallbacks, or REALITY with the domestic
  borrowed SNIs (`aparat.ir`, `digikala.com`, `snapp.ir`).
- **"Add a trusted certificate to an existing inbound."** Domains → set the
  domain on the inbound → one-click TLS.
