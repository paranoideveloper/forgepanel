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

Every subscription response carries `Vary: User-Agent` and
`Cache-Control: no-store`: the body varies on a request header while the URL
stays constant, so without them a cache could serve one subscriber's credentials
to another. Failed token lookups are rate limited per source.
