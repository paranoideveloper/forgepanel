# Go-side wiring for ForgeEdge

Everything in this document is work on the **Go** side of the repo. The Worker is
complete and tested without it; this is what connects the VPS panel to it so a
subscriber's single URL carries VPS inbounds *and* edge entries.

Nothing here was implemented by the ForgeEdge agent — the brief forbade touching
Go code. Each section states the exact file, signature and payload.

---

## 1. The canonical model contract

`deploy/cloudflare/forgeedge/src/model/node.ts` is a **field-for-field mirror of
`internal/protocol/model/model.go`**, keyed on the Go struct tags. The mapping is
mechanical:

| Go | TypeScript |
|---|---|
| `type Protocol string` + consts | `type Protocol = 'vless' \| 'vmess' \| …` |
| `Node.Tag` → `json:"tag,omitempty"` | `tag?: string` |
| `Node.AlterID` → `json:"alter_id,omitempty"` | `alter_id?: number` |
| `Transport.EarlyData` → `json:"early_data,omitempty"` | `early_data?: number` |
| `Transport.PermitWithout` → `json:"permit_without_stream,omitempty"` | `permit_without_stream?: boolean` |
| `AmneziaWGOptions` embeds `WireGuardOptions` (inlined by `encoding/json`) | `interface AmneziaWGOptions extends WireGuardOptions` |
| `Hysteria2Options.HeartbeatSeconds` → `json:"heartbeat,omitempty"` | `heartbeat?: number` |

So `json.Marshal(*model.Node)` parses directly into the TS `Node` with **no
translation layer**, and a `Node` built at the edge marshals back into a Go
`model.Node` unchanged.

Three Go behaviours are mirrored as well, because the edge renders nodes itself:

| Go | TypeScript |
|---|---|
| `(*Node).Normalize()` | `src/model/normalize.ts` → `normalize()` |
| `(*Node).Validate()` | `src/model/validate.ts` → `validate()` (returns the message, or `null`) |
| `export.URI`, `export.ClashProxy`, `export.ClashYAML`, `render.SingboxOutbound`, `render.XrayOutbound` | `src/export/{uri,clash,singbox,xray}.ts` |

### The drift guard

`testdata/gen/main.go` runs the **real Go exporters** over 20 nodes covering
every protocol/transport/security combination and writes `testdata/golden.json`.
`test/golden.test.ts` asserts byte equality against it — 103 assertions.

Regenerate after **any** change to `internal/protocol/`:

```bash
go run deploy/cloudflare/forgeedge/testdata/gen/main.go
cd deploy/cloudflare/forgeedge && bun test test/golden.test.ts
```

Wire this into CI. A red golden test means the edge and the VPS are about to emit
different links for the same node.

---

## 2. Feeding the canonical model to the edge

### 2.1 Payload

`POST https://<worker>/<SECURE_PATH>/feed`
`Authorization: Bearer <feedPushToken>`

```jsonc
{
  "version": 1,
  "generated_at": "2026-08-07T09:00:00Z",
  "panel": { "name": "ForgePanel", "base_url": "https://panel.example.com" },
  "users": [
    {
      "id": "u_7f3a",
      "sub_token": "the same token as /sub/:token on the VPS",
      "email": "a@b.c",
      "enabled": true,
      "expires_at": "2026-12-31T00:00:00Z",
      "used_traffic": 1234567,
      "data_limit": 0,
      "vless_uuid": "…",          // optional: per-user identity for EDGE entries
      "trojan_password": "…",     // optional: same
      "nodes": [ /* []*model.Node, already redacted */ ]
    }
  ],
  "shared_nodes": [ /* []*model.Node — ForgeDNS tunnels usually live here */ ]
}
```

**`nodes` must already be redacted.** Run the existing
`redactNodesForClient()` from `internal/api/sub.go` — the edge does not re-redact,
and a REALITY/WireGuard server private key that reaches KV is a key you have
published.

`vless_uuid` / `trojan_password` are what make the edge multi-tenant. Omit them
and every subscriber shares one edge identity: fine for a personal deploy, wrong
for a panel with users.

### 2.2 Go handler to add

New file, e.g. `internal/api/edge.go`:

```go
// EdgeFeed builds the canonical feed for ForgeEdge.
func (s *Server) EdgeFeed() (*EdgeFeedDoc, error)

// handleEdgePush POSTs EdgeFeed() to every registered edge deployment.
func (s *Server) handleEdgePush(c *gin.Context)

// handleEdgeFeed serves the same document for the PULL direction
// (the Worker's cron fetches it when feedPullURL is set).
//   GET /api/edge/feed   Authorization: Bearer <feedPullToken>
func (s *Server) handleEdgeFeed(c *gin.Context)
```

`EdgeFeedDoc` mirrors §2.1. `Users[].Nodes` comes from the existing
`s.subscriptionNodes(token, host)`.

### 2.3 Storing edge deployments

The panel needs to remember which Workers it feeds. Suggested table:

```sql
CREATE TABLE edge_deployments (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL,          -- worker/pages project name
  target        TEXT NOT NULL,          -- 'workers' | 'pages'
  origin        TEXT NOT NULL,          -- https://name.acct.workers.dev
  secure_path   TEXT NOT NULL,
  push_token    TEXT NOT NULL,          -- from GET /<path>/api/status
  account_id    TEXT,
  created_at    TEXT NOT NULL,
  last_push_at  TEXT,
  last_status   TEXT
);
```

### 2.4 Push trigger points

Push after anything that changes what a subscriber should receive:

- user created / edited / enabled / disabled / deleted
- inbound created / edited / deleted
- traffic or quota reset
- `forgectl edge push` (manual)

Debounce ~5s: a bulk import shouldn't fire fifty PUTs.

---

## 3. Panel routes to add

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/edge/deployments` | list registered edges + last push status |
| `POST` | `/api/edge/deployments` | register one (origin + secure path + push token) |
| `DELETE` | `/api/edge/deployments/:id` | forget it (does **not** delete the Worker) |
| `POST` | `/api/edge/deployments/:id/push` | push the feed now |
| `GET` | `/api/edge/deployments/:id/status` | proxy `GET <origin>/<path>/api/status` |
| `POST` | `/api/edge/deploy` | start the OAuth deploy flow (see `FORGECTL_EDGE_SPEC.md`) |
| `DELETE` | `/api/edge/deploy/:name` | delete the Worker via the Cloudflare API |
| `GET` | `/api/edge/update-check` | daily "is a newer ForgeEdge released" check |

---

## 4. Backend Mode: the VPS side

Backend Mode is what gives edge users UDP and the full protocol matrix. **A
Cloudflare Worker has outbound TCP via `cloudflare:sockets` and nothing else** —
no UDP socket, no raw IP, no QUIC. So VLESS/Trojan-over-WebSocket and
DNS-over-UDP-relayed-to-DoH are the complete list of what can terminate at the
edge. Everything else needs a real server.

When Backend Mode is on, the Worker forwards the WebSocket upgrade **verbatim**
(same path, same `sec-websocket-protocol` early data, same query) to
`backend.url`, and relays bytes in both directions with no protocol awareness.

### What the VPS must expose

A **plain-HTTP WebSocket inbound** on the ForgePanel node, fronted by whatever
TLS the operator already has:

```jsonc
// Xray inbound
{
  "tag": "forgeedge-ws",
  "port": 8080,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "settings": { "clients": [{ "id": "<same uuid the edge advertises>" }], "decryption": "none" },
  "streamSettings": { "network": "ws", "wsSettings": { "path": "/" } }
}
```

The path must be permissive (`/`) or match what the edge sends, which is
`/vl/<24 hex>` or `/tr/<24 hex>` — see `wsPath()` in `src/edge/nodes.ts`.

Suggested Go work: extend `internal/deploy` with a `--forgeedge-backend` flag on
the node installer that provisions this inbound plus a Caddy/nginx TLS front.

### Optional control endpoint

`POST /forgeedge/warp-scan` with `{"endpoints": ["162.159.192.1:2408", …]}` →

```json
{ "results": [ { "endpoint": "162.159.192.1:2408", "ok": true, "latency_ms": 42, "loss": 0 } ] }
```

Header `X-ForgeEdge-Token: <backend.token>`.

This exists because **the Worker cannot measure WARP latency**: WARP is
WireGuard over UDP, and a Worker has no UDP socket. Without this endpoint the
scanner returns ranked candidates with `measured: false` and **no latency
field** — it does not invent numbers. See `src/warp/scanner.ts`.

---

## 5. Reusing the TS validator from Go

`src/config/validate.ts` is pure and dependency-free. If `forgectl edge` should
pre-flight a config before PUTting it, the cheapest faithful option is to port
that file (≈90 lines, no I/O) rather than shell out to `bun`.

---

## 6. Divergences the lead should know about

| Item | Status |
|---|---|
| `model.Node` mirror | complete, byte-verified against Go for all 14 protocols |
| `Normalize` / `Validate` | complete, byte-verified |
| `export.URI` / `ClashProxy` / `ClashYAML` | complete, byte-verified (incl. Go's `url.Values.Encode` ordering, `PathEscape`/`QueryEscape` rules, and `encoding/json`'s key sorting + HTML escaping) |
| `render.SingboxOutbound` / `XrayOutbound` | complete, byte-verified |
| `render.SingboxInbound` / `XrayInbound` / `SingboxEndpoint` | **not mirrored** — the edge never renders server-side inbounds. Add only if that changes. |
| `export.AmneziaWGConf` / `WireguardConf` | **not mirrored**; the edge has its own WARP-specific generator in `src/warp/config.ts` |
| Xray `finalmask` fragmentation / UDP noise | edge-only. Deliberately **not** in `model.Node` — it describes client emission behaviour, not what the server is. |
