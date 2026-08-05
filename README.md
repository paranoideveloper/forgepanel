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

## Quick install (Linux, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/paranoideveloper/forgepanel/main/install.sh | sudo bash
```

The installer downloads the latest release binary, creates a `forgepanel` systemd service, starts it, and prints your **panel URL** and a **one-time setup token**. Open the URL and create your administrator account with that token — no password is generated for you. It walks you through the panel port and (optional) domain/HTTPS with plain, coloured prompts; add `--tui` for a full-screen dialog UI.

Then open the URL it prints (e.g. `http://YOUR_SERVER_IP:2053/panel/<secret>`) and complete first-run setup.

**This one command is the recommended install** — it needs no Docker.

## Docker

Requires Docker **with the Compose plugin**. If `docker compose` reports `unknown command`, install it first — `apt-get install -y docker-compose-plugin` (Debian/Ubuntu) — or use the standalone `docker-compose` binary; the commands below fall back to it automatically.

```bash
git clone https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
docker compose up -d      2>/dev/null || docker-compose up -d
docker compose logs -f forgepanel 2>/dev/null || docker-compose logs -f forgepanel
# ^ the container prints your panel URL + one-time setup token on first boot
```

Then open the URL and create your admin account with the setup token.

## Build from source

Requires Go 1.24+.

```bash
git clone https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
make build          # -> bin/forgepanel (server) + bin/forgectl (CLI)
./bin/forgepanel    # first boot prints the panel URL + a one-time setup token
```

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

Full docs are in [`docs/`](docs/) — [Install](docs/INSTALL.md), [Configuration](docs/CONFIGURATION.md), [Protocols](docs/PROTOCOLS.md), [API](docs/API.md), [Security](docs/SECURITY.md), [Troubleshooting](docs/TROUBLESHOOTING.md).

## Security notes

- The panel serves plain **HTTP on port 2053** by default. For anything beyond a quick trial, put it behind a reverse proxy with TLS (Caddy/Nginx) or bind it to localhost and tunnel in over SSH.
- Change the generated admin password on first login and enable TOTP 2FA in Settings.
- Keep the secret admin path private — it's part of your first line of defense.

## License

MIT — see [LICENSE](LICENSE).
