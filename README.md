<div align="center">

# ForgePanel

**A self-hosted, single-binary control panel for running your own multi-protocol proxy servers.**

Create, manage and share proxy configs from a clean web UI — the panel downloads and supervises the proxy engines for you, so there's nothing else to install.

</div>

---

## Features

- **13 protocols, one panel** — VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, Hysteria2, TUIC, AnyTLS, ShadowTLS, WireGuard, AmneziaWG (kernel mode), Brook.
- **Zero-config creation** — pick a protocol and a port; the panel fills in keys, UUIDs, passwords, REALITY key-pairs and a working steal-site so every config just works.
- **Engines managed for you** — it downloads, pins, verifies and supervises `xray`, `sing-box` and `brook` automatically. Configs are validated before they're applied, so a bad edit can never take your traffic down.
- **Clean web UI** — dark/light themes, live config preview, one-click copy/QR, and a schema-driven form that exposes every option of every protocol.
- **Multi-user** — per-user UUIDs/passwords, data-limit quotas with resets, expiry dates, and per-user subscription links.
- **Subscriptions** — base64 / Clash / sing-box subscription endpoints out of the box.
- **Security built in** — REALITY and TLS (with an auto self-signed fallback), argon2id logins, JWT + optional TOTP 2FA, and login rate-limiting.
- **ForgeDNS** — an optional DNS-tunnel subsystem for hard-censorship networks.
- **Import** — pull existing inbounds in from another panel's SQLite database.
- **Ships anywhere** — a single static binary, a systemd service, or Docker.

## Install

Every published mode uses the same release version. Replace `v1.2.0` with the
version you intend to run and keep it pinned in production.

### Verified Linux installer (recommended)

For a systemd VPS, fetch the installer and its checksum before giving it root
access. It installs the three matching binaries, records ownership in an
installation manifest, starts the service, and prints the one-time setup token.

```bash
VERSION=v1.2.0
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
VERSION=v1.2.0
ARCH=$(dpkg --print-architecture)       # amd64 or arm64
ASSET=forgepanel_${VERSION#v}_linux_${ARCH}.deb
curl -fSLO "https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/$ASSET"
sudo apt install "./$ASSET"
```

### Fedora, RHEL, Rocky, and AlmaLinux package

```bash
VERSION=v1.2.0
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac
ASSET=forgepanel_${VERSION#v}_linux_${ARCH}.rpm
curl -fSLO "https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/$ASSET"
sudo dnf install "./$ASSET"
```

### Docker image

```bash
VERSION=v1.2.0
docker volume create forgepanel-data
docker run -d --name forgepanel --restart unless-stopped \
  -p 2053:2053 -p 2054:2054 -p 2096:2096 \
  -v forgepanel-data:/var/lib/forgepanel \
  ghcr.io/paranoideveloper/forgepanel:$VERSION
docker logs -f forgepanel
```

Publish ports `80` and `443` when using built-in ACME HTTPS, and add
`--cap-add=NET_ADMIN` only for port-hopping or the affected ForgeDNS modes.

### Docker Compose

Requires Docker with the Compose plugin. The checked-in Compose file keeps data
in a named volume and accepts an explicit image version.

```bash
VERSION=v1.2.0
git clone --depth 1 --branch "$VERSION" https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
FORGEPANEL_VERSION=$VERSION docker compose up -d
docker compose logs -f forgepanel
```

### Standalone release binaries

Use this mode for a foreground process, testing, or custom supervision. The
systemd installer or package remains the supported VPS management path.

```bash
VERSION=v1.2.0
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
git checkout v1.2.0
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
| sing-box | Hysteria2 · TUIC · AnyTLS · ShadowTLS · WireGuard |
| brook | Brook (all modes) |
| amneziawg | AmneziaWG (kernel mode) |

**AmneziaWG (kernel mode).** ForgePanel runs AmneziaWG through the real
[`amneziawg` kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
+ `awg-quick` — not a userspace shim — so tunnels run at full kernel-WireGuard
speed with the obfuscation (`Jc/Jmin/Jmax/S1/S2/H1..H4`) that evades WireGuard
DPI blocks. Create an AmneziaWG inbound and the panel provisions the keys,
writes the server `awg-quick` config, and brings the interface up; the client
config downloads as a ready-to-import `.conf`. The server needs the `amneziawg`
module + `amneziawg-tools` installed (`modprobe amneziawg`); until then the panel
still generates the configs and reports kernel-mode readiness in engine status.

Full docs are in [`docs/`](docs/) — [Install and local management](docs/INSTALL.md), [Configuration](docs/CONFIGURATION.md), [Protocols](docs/PROTOCOLS.md), [API](docs/API.md), [Security](docs/SECURITY.md), [Troubleshooting](docs/TROUBLESHOOTING.md).

## Security notes

- The panel serves plain **HTTP on port 2053** by default. For anything beyond a quick trial, put it behind a reverse proxy with TLS (Caddy/Nginx) or bind it to localhost and tunnel in over SSH.
- Change the generated admin password on first login and enable TOTP 2FA in Settings.
- Keep the secret admin path private — it's part of your first line of defense.

## License

MIT — see [LICENSE](LICENSE).
