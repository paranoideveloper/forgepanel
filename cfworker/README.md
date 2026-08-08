# ForgeEdge — Cloudflare Worker free-config generator

A single-file Cloudflare Worker that is **both**:

1. a **VLESS-over-WebSocket proxy** running on the Cloudflare edge, and
2. a **panel + subscription generator** that hands out ready-to-import configs
   pointing at a rotation of **clean Cloudflare edge IPs** on Cloudflare's TLS
   ports.

Same approach as [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel)
and [Nova-Proxy](https://github.com/IRNova/Nova-Proxy): your traffic rides
`client → clean CF edge IP → this Worker → destination`, so it keeps working on
networks that throttle Cloudflare's default anycast IPs (e.g. Iran). No servers,
no build step, no dependencies — it runs entirely on Cloudflare's free tier.

## Deploy

**Dashboard (no tools):** create a Worker, paste `_worker.js`, Save & Deploy.
Optionally add a `UUID` variable (Settings → Variables) for a private id.

**wrangler:**

```bash
npm i -g wrangler
export CLOUDFLARE_API_TOKEN=...      # a token with "Edit Workers" permission
wrangler deploy                      # ships to forgeedge.<your-subdomain>.workers.dev
```

## Use

Open the panel at:

```
https://<your-worker-host>/<UUID>            # or /<SUBPATH> if you set one
```

It shows every generated config and three subscription links:

- **base64 / v2ray**: `https://<host>/<UUID>/sub` — import into v2rayNG, Hiddify,
  NekoBox, sing-box, Streisand… (auto-updates as you redeploy).
- **sing-box**: `https://<host>/<UUID>/sub/singbox`
- **clash**: `https://<host>/<UUID>/sub/clash`

Everything outside the secret path serves a plain "It works." page — the panel
path is never revealed on the root.

## Variables (all optional)

| Variable | Meaning |
|---|---|
| `UUID` | the VLESS id clients authenticate with. If unset, derived from the hostname (works immediately; set your own to make it private). |
| `PROXYIP` | fallback proxy `host[:port]` for destinations the edge can't reach directly (Cloudflare→Cloudflare is refused). |
| `SUBPATH` | secret path prefix for the panel/subscription (defaults to the UUID). |
| `DNS_RESOLVER` | DoH resolver for UDP/DNS (default `1.1.1.1`). |

## What works / what's next

Works now: VLESS + WS + TLS proxying through the edge, UDP/DNS, clean-IP config
rotation, and v2ray / sing-box / clash subscriptions.

Planned (this is v1): a bring-your-own custom domain flow, TLS fragment settings
baked into the generated configs, WARP egress, Trojan, and one-click deploy +
management from the ForgePanel UI (generate the Worker with your settings and
push it via the Cloudflare API).
