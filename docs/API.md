# ForgePanel REST API (v1)

Base: `https://<panel>`. Admin endpoints require `Authorization: Bearer <access>`
(from `POST /api/login`). The frontend consumes only this public API.

## Auth
| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/login` | `{username,password}` | → `{access_token,refresh_token,role}` |
| POST | `/api/refresh` | `{refresh_token}` | → new token pair |
| GET | `/api/admin/me` | — | current admin claims |

## Config Studio (public, stateless)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/protocols` | protocol/transport/security matrix |
| POST | `/api/studio/preview` | canonical node → `{uri,xray,singbox,clash,errors}` |
| POST | `/api/keygen` | `{kind}` → generated keys |
| POST | `/api/import` | Paste-Anything: links/sub blob → canonical nodes |

## Admin (JWT)
| Method | Path | Purpose |
|---|---|---|
| GET/POST/DELETE | `/api/admin/inbounds[/:id]` | inbound CRUD (hot-reloads engine) |
| GET/POST | `/api/admin/groups` | list / create groups |
| GET/PATCH/DELETE | `/api/admin/groups/:id` | one group with member count / partial update / safe delete |
| GET/POST/DELETE | `/api/admin/users[/:id]` | user CRUD (materialises subscription) |
| GET | `/api/admin/users/:id` | one user with direct + inherited + effective inbounds |
| PATCH | `/api/admin/users/:id` | partial update; never rotates credentials |
| PUT | `/api/admin/users/:id/inbounds` | replace the user's DIRECT inbound assignments |
| POST | `/api/admin/users/:id/reset-credentials` | explicitly rotate uuid / password / sub token |
| GET | `/api/admin/health/detail` | per-subsystem health for the status indicator |
| GET | `/api/admin/stats` | dashboard counts |
| GET | `/api/admin/engines[/config]` | supervised core status + generated config |
| POST | `/api/admin/engines/{validate,reload}` | validate/reload cores |
| GET | `/api/admin/domains/{check,ns-wizard}` | DNS health + delegation wizard |
| GET/POST | `/api/admin/certs[/import]` | cert list / import PEM |
| GET/POST/DELETE | `/api/admin/nodes[/enroll][/:id]` | node registry + enroll |
| GET | `/api/admin/forgedns/adapters` | selectable DNS-tunnel wire formats |
| GET/POST/DELETE | `/api/admin/forgedns/zones[/:id]` | tunnel-zone CRUD (activates listener) |
| POST | `/api/admin/forgedns/zones/:id/toggle` | enable/disable a zone |
| GET | `/api/admin/forgedns/zones/:id/{sessions,client}` | live sessions / client config |
| GET | `/api/admin/forgedns/status` | listener state + served zones |
| GET/POST | `/api/admin/settings/subscription` | subscription defaults: routing preset, TLS fragment (`fragment`, `fragment_level` = light/medium/aggressive, `fragment_cores` = any of `xray, sing-box`), and the node-naming template (`{FLAG} {NAME} {COUNTRY} {PROTOCOL} {NET} {TLS} {PORT} {HOST} {USER} {NUM} {DATE}`) |
| GET | `/api/admin/geoip?host=<addr>` | resolve a host (or the panel's own IP) to `{country_code, flag}` for the inbound Country field |

### ForgeEdge (Cloudflare Worker)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/edge/bundle` | whether the worker bundle is embedded (`{embedded, bytes}`) |
| GET | `/api/admin/edge/token-url` | a Cloudflare API-token page pre-filled with the exact scopes |
| POST | `/api/admin/edge/deploy` | one-click deploy the embedded worker (`{api_token, account_id, name?}`) |
| DELETE | `/api/admin/edge/deploy/:name` | delete a worker (`?api_token=&account_id=`) |
| GET/POST | `/api/admin/edge/deployments[/:id]` | list / register / manage edge deployments |
| POST | `/api/admin/edge/deployments/:id/push` | push the current feed to an edge |
| POST | `/api/admin/edge/deployments/:id/warp` | register free WARP + AmneziaWG into the edge |
| GET | `/api/admin/edge/deployments/:id/warp.conf[?pro=1]` | download the WARP / Amnezia `.conf` |

The Telegram bot (enable with `FORGEPANEL_TELEGRAM_TOKEN` + `FORGEPANEL_TELEGRAM_ADMINS`)
offers the same user management from chat: `/adduser`, `/deluser`, `/enable`,
`/disable`, `/reset`, `/limit <GB>`, `/extend <days>` (admin), and `/sub <token>`
for any user. See [CONFIGURATION.md](CONFIGURATION.md#telegram-bot).

## Node agent (token-auth)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/node/register` | enroll with one-time token |
| POST | `/api/node/heartbeat` | report health → receive engine config |

## Subscription
| Method | Path | Purpose |
|---|---|---|
| GET | `/sub/:token[/format]` | UA-auto-detected; explicit `/v2ray`, `/clash`, `/sing-box`, `/links`, `/json` suffixes |

An explicit suffix always wins over User-Agent sniffing. Aliases: `singbox`/`sb`
for `sing-box`, `clash-meta` for `clash`, `base64`/`v2rayng` for `v2ray`,
`raw`/`uri` for `links`. An explicit request for anything else is a `404` naming
the supported formats, rather than silently returning a different one.

Opening `/sub/:token` in a **web browser** (browser User-Agent + `text/html`
Accept, no proxy-client token) returns a friendly **landing page**: a usage /
expiry summary and, per client (v2rayNG, Hiddify, Streisand, Clash, sing-box), a
scannable **QR** plus a one-tap **Import** deep-link. Proxy clients are never
affected; `?raw=1` forces the raw config body.

Every subscription response carries `Vary: User-Agent` and
`Cache-Control: no-store`: the body varies on a request header while the URL
stays constant, so without them a cache could serve one subscriber's credentials
to another. Failed token lookups are rate limited per source.
