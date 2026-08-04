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
| GET/POST | `/api/admin/groups` | group CRUD |
| GET/POST/DELETE | `/api/admin/users[/:id]` | user CRUD (materialises subscription) |
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
| GET | `/sub/:token[/format]` | UA-auto-detected; `/clash`, `/links`, `/json` suffixes |
