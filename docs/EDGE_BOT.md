# ForgeEdge Bot

A standalone Telegram bot that deploys and manages **ForgeEdge Cloudflare
Workers** from chat — the panel's Worker Wizard, without the panel.

It is a separate program (`forgeedge-bot`) with its own process and its own
encrypted state, but it reuses the panel's `internal/edge` engine, so a Worker it
deploys is byte-for-byte the one the panel deploys, embedding the same Worker
bundle. There is no database and nothing shared with a running panel.

## How access works

Access is **request-and-approve**, so you can hand the bot to a few trusted
people without handing them your Cloudflare account:

1. Someone messages the bot. They become *pending* and you (the **owner**) get a
   notification with **✅ Approve / ❌ Deny** buttons.
2. Once you approve, they store **their own** Cloudflare token with `/cf` and
   deploy/manage only **their own** Workers. Nobody sees anyone else's Workers or
   credentials.

The owner is set once, by Telegram id, in `FORGEEDGE_BOT_OWNER`. The owner is
always approved and can `/users`, `/approve <id>`, `/deny <id>`, `/revoke <id>`.

Every user's Cloudflare token is stored **AES-GCM-encrypted at rest**; the master
key lives beside the state in a 0600 file and never leaves the host.

## Setup

Three environment variables, two of them required:

| Variable | Required | Purpose |
|---|---|---|
| `FORGEEDGE_BOT_TOKEN` | yes | the @BotFather bot token |
| `FORGEEDGE_BOT_OWNER` | yes | your Telegram numeric id (the root approver) |
| `FORGEEDGE_BOT_DATA` | no | state directory (default `/var/lib/forgeedge-bot`) |

**1. Create the bot.** In Telegram, message
[@BotFather](https://t.me/BotFather), send `/newbot`, and copy the token.

**2. Get your id.** Message [@userinfobot](https://t.me/userinfobot); it replies
with your numeric `Id`.

**3. Install and run (systemd).**

```bash
VERSION=v1.20.0
ARCH=amd64                              # arm64 on 64-bit ARM
BASE=https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION
sudo curl -fSL "$BASE/forgeedge-bot-linux-$ARCH" -o /usr/local/bin/forgeedge-bot
sudo chmod 0755 /usr/local/bin/forgeedge-bot

sudo curl -fSL "$BASE/forgeedge-bot.service" -o /etc/systemd/system/forgeedge-bot.service
sudo mkdir -p /etc/forgeedge-bot
sudo curl -fSL "$BASE/forgeedge-bot.env.example" -o /etc/forgeedge-bot/forgeedge-bot.env
sudo chmod 0640 /etc/forgeedge-bot/forgeedge-bot.env
sudo nano /etc/forgeedge-bot/forgeedge-bot.env   # set TOKEN and OWNER

sudo systemctl daemon-reload
sudo systemctl enable --now forgeedge-bot
journalctl -u forgeedge-bot -f
```

You should see `edgebot: connected as @yourbot`. Now message your bot `/start`.

## Commands

Send `/help` in chat for the live list. Summary:

**Setup**
- `/cf <token> [account]` — store your Cloudflare creds (the bot deletes your
  message immediately). The token needs *Workers Scripts·Edit*, *Workers KV·Edit*
  and *Account Settings·Read* — plus *Zone·Read* and *DNS·Edit* if you'll attach a
  custom domain.
- `/whoami` — your account and worker count.

**Workers**
- `/deploy [name] [domain]` — deploy a new edge.
- `/list` · `/status [name]` · `/sub [name]` · `/config [name]`
- `/update [name]` — re-upload the latest Worker build (config/users/path kept).
- `/rotate [name]` — rotate the secret path (kills every old URL).
- `/destroy [name]` — delete a Worker (asks to confirm).

**Clean IPs / CDN fronting**
- `/addip [name] <ip…>` · `/rmip [name] <ip>` · `/ips [name]`
- `/probeip [name] <ip>` · `/refreships [name]`
- `/sni [name] <sni>` · `/cdnhost [name] <host>` · `/cdnaddr [name] <addr…>`

**Transport / obfuscation**
- `/ports [name] <p…>` (443 2053 2083 2087 2096 8443, or http 80 8080 8880 2052
  2082 2086 2095) · `/fingerprint [name] <fp>`
- `/fragment [name] on|off [len a-b] [delay a-b]`
- `/proxyip [name] <ip…>|off` · `/nat64 [name] <[ipv6::]…>|off` · `/chain [name] <uri|off>`
- `/protocols [name] vless,trojan`

**Backends / subscriptions / domain**
- `/backend [name] <url|off> [token]` · `/extsub [name] add|rm|list <url>`
- `/domain [name] <host>` — attach a custom domain (its zone must be in the
  account the token can see).

**WARP (WireGuard + AmneziaWG)**
- `/warp [name]` — register a WARP pair on the bot host and push it to the Worker,
  which then serves WireGuard + AmneziaWG nodes in the subscription.
- `/warpconf [name]` — download the `wg-quick` .conf (plain and obfuscated).

**Owner**
- `/users` · `/approve <id>` · `/deny <id>` · `/revoke <id>`

## Where a command targets

Commands that act on a Worker take an optional `[name]`. If you have exactly one
Worker you can leave it out; with several, name which one (the bot lists them).

## Notes

- The bot never needs a Worker's admin password: it authenticates to each Worker
  with that Worker's machine credential (the feed push token) captured at deploy.
- Config edits are read-modify-write — the bot fetches the live config, changes
  one field and writes it back, and the Worker validates the result. A rejected
  change comes back with the Worker's own reason.
- It only makes outbound HTTPS (Telegram + the Cloudflare API), so it runs as an
  unprivileged systemd dynamic user with no special capabilities.
