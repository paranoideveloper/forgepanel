<div align="center">

# ForgePanel

**A self-hosted, single-binary control panel for running your own multi-protocol proxy servers — one box, a fleet of them, or a managed platform.**

Create, manage and share proxy configs from a clean web UI — the panel downloads and supervises the proxy engines for you, so there's nothing else to install.

</div>

---

## Features

- **13 protocols, one panel** — VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, Hysteria2, TUIC, AnyTLS, ShadowTLS, WireGuard, AmneziaWG (kernel mode), Brook.
- **A fleet, not just this box** — enrol other servers as **remote nodes** over an mTLS control plane and run inbounds on them, with per-user traffic metered on the node. Nodes run sing-box as well as xray, and say *why* they are unhealthy rather than showing one bit.
- **Runs where you put it** — a VPS, or Railway / Render / Fly / Koyeb. The panel detects the platform and **removes the controls that platform owns** (certificates, domains, ports, host tuning) instead of showing switches that cannot work, and each removal says why.
- **English and Persian, with RTL** — the whole panel, not just the labels, with the layout mirrored.
- **Light and dark** — a three-state theme switch (System / Light / Dark) that follows your OS by default.
- **Inbounds section + Config Studio** — create any protocol from a schema-driven form that exposes every option, generate keys/UUIDs/PSKs with a click, and watch a **live four-format preview** (client link · Xray · sing-box · Clash). Edit, clone, enable/disable and delete inbounds; copy the client link or scan its QR.
- **Zero-config creation** — pick a protocol and a port; the panel fills in keys, UUIDs, passwords, REALITY key-pairs and a working steal-site so every config just works. Each inbound authenticates with its own credential out of the box.
- **Reachable by default** — the panel **auto-opens the host firewall (ufw)** for every inbound port, and a per-inbound **Verify** carries real traffic through the core to prove a config works (with an honest warning when a port is firewalled).
- **Users, groups & subscriptions** — create users, **assign inbounds to a user or a group**, set data-limit quotas / expiry, reset credentials, and hand out per-user base64 / Clash / sing-box **subscription** links. Over-quota / expired users are cut off automatically, and a **live online/last-seen** dot shows who is actively connected. **Per-user Shadowsocks** (SS-2022 multi-PSK) gives every user their own key for real per-user attribution.
- **Subscription landing page** — opening a subscription link in a browser shows a friendly page with a **scannable QR and one-tap Import** for each client (v2rayNG, Hiddify, Streisand, Clash, sing-box). **Node-naming templates** (`{FLAG} {NAME} {COUNTRY} …`) name every config, with a per-inbound country and one-click **geoip auto-detect** for the flag.
- **ForgeEdge (Cloudflare Worker)** — deploy a VLESS/Trojan-over-WebSocket edge to Cloudflare **in one click** (the worker is embedded in the panel), serving the same subscription your VPS does, and provision **free Cloudflare WARP + AmneziaWG** (DPI-obfuscated WireGuard) straight into it.
- **Telegram bot** — run the panel from chat: get your subscription link, and (admin) create / delete / enable / disable / reset / limit / extend users — changes reload the running cores immediately. Built into the binary; enable it by putting a @BotFather token + your chat id in `/etc/forgepanel/forgepanel.env` and restarting ([setup](docs/CONFIGURATION.md#telegram-bot)).
- **ForgeEdge Bot (standalone)** — a separate single-binary Telegram bot that deploys and manages ForgeEdge Workers entirely from chat, with **no panel required**. Access is request-and-approve (you approve each user), and every approved user brings **their own** Cloudflare token to deploy and manage **their own** Workers — clean-IPs, SNI/CDN fronting, fragment, WARP, custom domains and more. It reuses the same `internal/edge` engine and embedded Worker as the panel ([guide](docs/EDGE_BOT.md)).
- **Engines managed for you** — it downloads, pins, verifies and supervises `xray`, `sing-box` and `brook` automatically. Configs are validated before they're applied, so a bad edit can never take your traffic down.
- **HTTPS by default, even with no domain** — set a domain and the panel gets an automatic Let's Encrypt certificate. Have no domain, and the installer offers a magic-DNS hostname (`<your-ip>.sslip.io`) that Let's Encrypt will still issue for, so the panel opens **without a browser warning** on a server that owns no domain at all. Admin logins are argon2id + JWT with optional TOTP 2FA and rate-limiting.
- **A setup wizard that checks its own work** — hand it a domain and a Cloudflare token and it builds a whole multi-protocol server. It verifies every prerequisite *before* creating anything (token, zone, the zone's SSL mode, the ports Cloudflare actually proxies), then asks Cloudflare whether it can really reach each CDN-fronted inbound and translates its error codes into the thing to fix. REALITY steal-sites are **measured** rather than guessed from a list.
- **Diagnostics** — a Panel Doctor, a coded bilingual (EN/FA) validation catalogue, and a Paste-Anything importer that turns pasted links / subscriptions / JSON into inbounds.
- **ForgeDNS** — an optional DNS-tunnel subsystem for hard-censorship networks.
- **Ships anywhere** — a single static binary, a systemd service, or Docker.

## Install

Every published mode uses the same release version. Replace `v1.20.0` with the
version you intend to run and keep it pinned in production.

### Verified Linux installer (recommended)

For a systemd VPS, fetch the installer and its checksum before giving it root
access. It installs the three matching binaries, records ownership in an
installation manifest, starts the service, and prints the one-time setup token.

```bash
VERSION=v1.20.0
BASE=https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION
curl -fsSLO "$BASE/install.sh"
curl -fsSLO "$BASE/install.sh.sha256"
sha256sum -c install.sh.sha256 && sudo bash install.sh
```

Use `sudo bash install.sh --update`, `sudo forgectl update --yes`, or
`sudo forgectl repair` for lifecycle operations. `sudo forgectl uninstall`
preserves data by default; `--purge --yes` is explicit.

### Debian and Ubuntu package

```bash
VERSION=v1.20.0
ARCH=$(dpkg --print-architecture)       # amd64 or arm64
ASSET=forgepanel_${VERSION#v}_linux_${ARCH}.deb
curl -fSLO "https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/$ASSET"
sudo apt install "./$ASSET"
```

### Fedora, RHEL, Rocky, and AlmaLinux package

```bash
VERSION=v1.20.0
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac
ASSET=forgepanel_${VERSION#v}_linux_${ARCH}.rpm
curl -fSLO "https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/$ASSET"
sudo dnf install "./$ASSET"
```

### Docker

```bash
VERSION=v1.20.0
git clone --depth 1 --branch "$VERSION" https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
docker build -t forgepanel:$VERSION \
  --build-arg VERSION=$VERSION \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
docker volume create forgepanel-data
docker run -d --name forgepanel --restart unless-stopped \
  -p 2053:2053 -p 2054:2054 -p 2096:2096 \
  -v forgepanel-data:/var/lib/forgepanel \
  forgepanel:$VERSION
docker logs -f forgepanel
```

Publish ports `80` and `443` when using built-in ACME HTTPS, and add
`--cap-add=NET_ADMIN` only for port-hopping or the affected ForgeDNS modes.

### Docker — prebuilt image (recommended)

Every release publishes a multi-arch image to GHCR, so you **pull** it — no local
build, no package downloads. This works even where a build network can't reach the
Alpine mirrors:

```bash
docker run -d --name forgepanel --restart unless-stopped \
  -p 2053:2053 -p 80:80 -p 443:443 -p 2096:2096 -p 53:53/udp \
  -v forgepanel-data:/var/lib/forgepanel \
  ghcr.io/paranoideveloper/forgepanel:v1.20.0
docker logs -f forgepanel
```

### Docker Compose

The checked-in Compose file defaults to the same GHCR image, so `up -d` **pulls**
it (add `--build` only if you deliberately want a local build from source):

```bash
VERSION=v1.20.0
git clone --depth 1 --branch "$VERSION" https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
FORGEPANEL_VERSION=$VERSION docker compose up -d
docker compose logs -f forgepanel
```

### Standalone release binaries

Use this mode for a foreground process, testing, or custom supervision. The
systemd installer or package remains the supported VPS management path.

```bash
VERSION=v1.20.0
ARCH=amd64                         # use arm64 on 64-bit ARM
BASE=https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION
for bin in forgepanel forgectl forgenode; do
  curl -fSLO "$BASE/$bin-linux-$ARCH"
  chmod 0755 "$bin-linux-$ARCH"
done
FORGEPANEL_DATA="$PWD/forgepanel-data" ./forgepanel-linux-$ARCH
```

### Build from source

Requires Go 1.25+ and is intended for development or a custom supervisor.

```bash
git clone https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
git checkout v1.20.0
make build
FORGEPANEL_DATA="$PWD/forgepanel-data" ./bin/forgepanel
```

All modes print a panel URL and one-time setup token on first boot. Open that
URL to create the first administrator account. Detailed deployment, migration,
backup, and recovery instructions are in [docs/INSTALL.md](docs/INSTALL.md).

## How it works

There is exactly one canonical representation of a proxy config — the panel renders it to each engine's native config, exports it to client links / Clash / sing-box, and parses foreign links back into it. Engine routing:

| Engine | Protocols |
|--------|-----------|
| xray | VLESS · VMess · Trojan · Shadowsocks · SOCKS · HTTP |
| sing-box | Hysteria2 · TUIC · AnyTLS · ShadowTLS |
| kernel-wg | WireGuard (kernel mode) |
| brook | Brook (all modes) |
| amneziawg | AmneziaWG (kernel mode) |

**WireGuard runs on the kernel too.** sing-box's `wireguard` endpoint is an
*outbound* construct: as a server it completes a handshake and answers traffic
addressed to its own tunnel address, but it forwards nothing onward — a tunnel
that connects and carries nothing. WireGuard is therefore served by `wg-quick`
and the in-tree `wireguard` module wherever the host can run them, measured at
about 3x the throughput of the userspace path (2.2–2.5 Gbit/s against
0.75–0.85 on one box, same client and destination). A host without the module
or `wireguard-tools` still gets the sing-box endpoint, and the Engines page
says which is serving.

**AmneziaWG (kernel mode).** ForgePanel runs AmneziaWG through the real
[`amneziawg` kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
+ `awg-quick` — not a userspace shim — so tunnels run at full kernel-WireGuard
speed with the obfuscation that evades WireGuard DPI blocks. All four
generations are supported: **1.5** (`Jc/Jmin/Jmax/S1/S2/H1..H4`), **2.0**
(`S3/S4`, the `I1..I3` custom junk packets, and H-value *ranges*), **3.0**
(`HeaderProtectionKey`, `ContentPaddingAddition`, the rekey/keepalive timing
ranges, peer `AdvancedSecurity`) and **3.1** (`RandomTrailers`,
`DisableCookies`). The generation is selected per inbound, because these
parameters are two-sided — a 3.x key in a config whose peer speaks 1.5 does not
degrade, it stops the handshake. Create an AmneziaWG inbound and the panel provisions the keys,
writes the server `awg-quick` config, and brings the interface up; the client
config downloads as a ready-to-import `.conf`. The server needs the `amneziawg`
module + `amneziawg-tools` installed (`modprobe amneziawg`); until then the panel
still generates the configs and reports kernel-mode readiness in engine status.

Full docs are in [`docs/`](docs/) — [Install and local management](docs/INSTALL.md), [Configuration](docs/CONFIGURATION.md), [Protocols](docs/PROTOCOLS.md), [API](docs/API.md), [Security](docs/SECURITY.md), [Troubleshooting](docs/TROUBLESHOOTING.md).

## Security notes

- The panel serves **HTTPS on port 2053** by default. Set a domain and it obtains and renews a Let's Encrypt
  certificate automatically. With no domain the installer offers a magic-DNS hostname
  (`<your-ip>.sslip.io`) so you still get a real certificate and no browser warning; decline that and it
  falls back to a **self-signed** certificate, which your browser warns about once. Plain HTTP to the port
  is refused either way.
- The panel is reached at a **secret path** (`https://HOST:2053/panel/<random>`) printed on first boot — keep it private; it's part of your first line of defense.
- Create the first administrator through the browser using the one-time setup token, and enable TOTP 2FA under System & Security.
- The panel **opens the host firewall (ufw)** for inbound ports it serves. If you run a **cloud-provider firewall** (Linode/AWS/etc.) as well, open the same ports there — the panel cannot manage a firewall outside the host.

## License

MIT — see [LICENSE](LICENSE).
