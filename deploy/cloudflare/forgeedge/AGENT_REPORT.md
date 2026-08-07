# §6 ForgeEdge — agent report

Everything is under `deploy/cloudflare/forgeedge/` and `third_party/`. No file
elsewhere in the repo was created or modified; `go.mod`, `go.sum` and all Go
source are untouched; nothing was committed, added or pushed.

---

## 1. Files

### Project scaffolding

| File | Purpose |
|---|---|
| `package.json` | TS/Wrangler project. Scripts: `test` (bun test), `typecheck`, `dev`, `deploy`. Its own dependency tree — the repo-root `frontend/` was never touched. |
| `tsconfig.json` | strict, `@cloudflare/workers-types` + bun types, `noEmit` |
| `wrangler.jsonc` | KV binding (required), D1 (optional, commented), cron `17 */6 * * *`, observability |
| `.gitignore` | `node_modules/`, `.wrangler/`, `bun.lock` |
| `README.md` | architecture, the platform constraint, features, layout |

### Canonical model — mirror of `internal/protocol/model`

| File | Lines | Purpose |
|---|---|---|
| `src/model/node.ts` | 421 | `Node` + every option struct, keyed on the Go JSON tags. `usesTransport`, `isQUICBased`, `sni`, `engineFor`, `keySizeForMethod`. |
| `src/model/normalize.ts` | 313 | mirror of `(*Node).Normalize()` incl. `clearIrrelevant*`, the ShadowTLS PSK derivation and the Go `omitempty` semantics |
| `src/model/validate.ts` | 165 | mirror of `(*Node).Validate()`, returning Go's exact message text |

### Exporters — mirror of `internal/protocol/{export,render}`

| File | Lines | Purpose |
|---|---|---|
| `src/export/uri.ts` | 336 | `export.URI` for all 14 protocols + `plainLinks` |
| `src/export/clash.ts` | 431 | `export.ClashProxy` + the deterministic YAML emitter (same key ranking, quoting and escaping) |
| `src/export/singbox.ts` | 340 | `render.SingboxOutbound` |
| `src/export/xray.ts` | 244 | `render.XrayOutbound` |
| `src/export/gojson.ts` | 84 | `encoding/json` compatibility: sorted keys + HTML escaping. Required for `vmess://`, which is base64 of exactly that JSON. |
| `src/export/subscription.ts` | 330 | assembles the combined list; renders links/v2ray/clash/sing-box/xray/json; failover groups; `canonicalSubFormat` + `detectFormat` |
| `src/export/fragment.ts` | 116 | Xray `finalmask` fragmentation + UDP noise, sing-box `record_fragment`, ECH |

### Protocol data path

| File | Lines | Purpose |
|---|---|---|
| `src/protocols/framing.ts` | 200 | **pure** VLESS and Trojan header parsers, every length bounds-checked |
| `src/protocols/vless.ts` | 152 | VLESS over WS + the DNS-over-UDP → DoH relay |
| `src/protocols/trojan.ts` | 74 | Trojan over WS (CONNECT only) |
| `src/protocols/ws.ts` | 88 | WebSocket ⇄ stream plumbing, early-data decode |
| `src/protocols/retry.ts` | 66 | **pure** retry policy: `proxyip` / `nat64` / off |
| `src/protocols/outbound.ts` | 108 | the socket half: connect, first-write, bidirectional pump |
| `src/protocols/backend.ts` | 172 | **Backend Mode**: verbatim WS upgrade forwarding + the control channel |

### Edge, config, panel, ops

| File | Lines | Purpose |
|---|---|---|
| `src/edge/feed.ts` | 148 | the Go↔edge canonical feed contract, sanitisation, `Subscription-Userinfo` |
| `src/edge/nodes.ts` | 178 | mints edge entries as canonical nodes; stable per-user WS paths; SNI/Host selection |
| `src/edge/chain.ts` | 219 | chain-proxy share-link → canonical node (vless/vmess/trojan/ss/socks/http) |
| `src/routing/rules.ts` | 218 | the one rule catalogue, three core spellings per row |
| `src/routing/emit.ts` | 158 | Xray / sing-box / Clash rule emission |
| `src/config/schema.ts` | 300 | `EdgeConfig`, `EdgeSecrets`, defaults, CF port sets |
| `src/config/store.ts` | 185 | KV load/save, migration, secure-path minting and rotation, optional D1 mirror |
| `src/config/validate.ts` | 97 | **pure** config validation |
| `src/config/runtime.ts` | 27 | per-request runtime state |
| `src/auth.ts` | 128 | secure-path gate, HMAC sessions, password check |
| `src/router.ts` | 165 | data path vs control path, the decoy |
| `src/sub.ts` | 155 | the subscription endpoint |
| `src/panel/handler.ts` | 214 | panel API |
| `src/panel/ui.ts` | 231 | the self-contained panel page |
| `src/warp/account.ts` | 97 | WARP registration, WebCrypto X25519 |
| `src/warp/config.ts` | 137 | wg-quick `.conf` plain + pro, and both as canonical nodes |
| `src/warp/scanner.ts` | 147 | candidate enumeration + ranking; delegates real measurement |
| `src/cleanip/list.ts` | 100 | seeds, validation, parsing, scheduled refresh |
| `src/cleanip/probe.ts` | 57 | the socket-based Cloudflare-edge probe |
| `src/dns/doh.ts` | 33 | DoH relay |
| `src/dns/resolve.ts` | 38 | DoH JSON lookups |
| `src/deploy/cloudflare.ts` | 218 | Workers/Pages deploy, update, delete, status, DNS, update check |
| `src/telegram/bot.ts` | 128 | owner-only status/panel/subs/rotate |
| `src/worker.ts` | 78 | `fetch` + `scheduled` |
| `src/env.ts` | 32 | bindings (KV required; everything else optional) |
| `src/version.ts` | 2 | |

### Tests — 316, all green

| File | Tests | Covers |
|---|---|---|
| `test/golden.test.ts` | 103 | **byte equality with the real Go exporters** |
| `test/framing.test.ts` | 22 | VLESS + Trojan parsers, positive and adversarial |
| `test/encoding.test.ts` | 68 | SHA-224/256 vs `node:crypto`, base64 vs `Buffer`, Go URL escaping, Go JSON, NAT64 |
| `test/routing.test.ts` | 21 | rule catalogue completeness across all three cores |
| `test/securepath.test.ts` | 21 | gate, sessions, password, generated-secret quality |
| `test/subscription.test.ts` | 42 | edge minting, formats, groups, feed, chain proxy |
| `test/edge.test.ts` | 39 | Backend Mode targets, retry policy, WARP, clean IPs, config validation |

### Test data and live probes

| File | Purpose |
|---|---|
| `testdata/gen/main.go` | runs the **real Go exporters** over 20 nodes → `golden.json`. Under `testdata/`, which the go tool excludes from `./...`, so `go build`/`go vet` never see it. |
| `testdata/golden.json` | 60 KB of Go-produced output, the drift guard |
| `testdata/wsprobe.ts` | live VLESS + Trojan probe: starts its own origin, proves real TCP traverses the tunnel |
| `testdata/wsreject.ts` | live negative probe: wrong credentials, non-DNS UDP, garbage |
| `testdata/feed.example.json` | the canonical feed the Go panel will push |

### Docs

| File | Purpose |
|---|---|
| `docs/GO_WIRING.md` | the Go-side work: model mapping table, feed payload, handlers, DB table, panel routes, Backend Mode VPS setup |
| `docs/FORGECTL_EDGE_SPEC.md` | `forgectl edge deploy\|update\|delete\|status\|push\|rotate-path`, OAuth+PKCE, token fallback, Telegram path, exit codes |
| `docs/E2E.md` | the workerd/Miniflare commands for §7 |

### `third_party/` (cloned, read, not modified)

`BPB-Worker-Panel`, `BPB-Wizard`, `Nova-Proxy`, `Nova-Wizard`.

---

## 2. Commands run, with real output

### Install, typecheck, unit tests

```
$ bun install
Checked 43 installs across 98 packages (no changes) [131.00ms]

$ bunx tsc --noEmit
0 errors

$ bun test
bun test v1.3.14 (0d9b296a)
 316 pass
 0 fail
 1321 expect() calls
Ran 316 tests across 7 files. [406.00ms]
```

### Go-parity golden generation and check

```
$ go run deploy/cloudflare/forgeedge/testdata/gen/main.go
wrote /home/ubuntu/forgepanel-clean/deploy/cloudflare/forgeedge/testdata/golden.json (20 cases, 60023 bytes)

$ bun test test/golden.test.ts
 103 pass
 0 fail
 117 expect() calls
Ran 103 tests across 1 file. [75.00ms]
```

20 cases × (normalize, URI, Clash, sing-box, xray) + the full links list + the
whole Clash YAML document, all compared byte-for-byte against Go.

### Bundle

```
$ bunx wrangler deploy --dry-run --outdir=.wrangler/dryrun
Total Upload: 195.85 KiB / gzip: 50.96 KiB
Your Worker has access to the following bindings:
Binding        Resource
env.KV         KV Namespace
--dry-run: exiting now.
```

### Live on workerd (`wrangler dev --local --port 8801`)

**Secure-path gate and decoy**

```
  /                -> 404
  /panel           -> 404
  /admin           -> 404
  /.env            -> 404
  /wp-login.php    -> 404
  /sub/abc         -> 404

  securePath = 4ezhru3f6j62y92ztj93fu2r  (len 24)
  /4ezhru3f6j62y92ztj93fu2r/panel  -> 200   <title>ForgeEdge</title>
  /4ezhru3f6j62y92ztj93fu2rx/panel -> 404
  /<path>/api/status (no session)  -> {"success":false,"status":401,"message":"Unauthorized."}
```

**First-run password, then session**

```
{"success":false,"status":400,"message":"Choose a password of at least 10 characters."}
{"success":true,"status":200,"message":"Password set.","body":{"firstRun":true}}
{"success":false,"status":401,"message":"Wrong password."}
```

**`/api/status`**

```json
{"version":"0.1.0","host":"127.0.0.1",
 "panel":"http://127.0.0.1:8801/4ezhru3f6j62y92ztj93fu2r/panel",
 "dohEndpoint":".../dns-query",
 "subscriptionTemplate":".../sub/<sub_token>",
 "feedPushEndpoint":".../api/feed",
 "feedPushToken":"1P6X5cY6RA-4_YpNCWBOyNhPha6_V1BD",
 "securePathRotatedAt":"2026-08-07T08:11:34.792Z",
 "backendMode":"off","users":0,
 "cleanIPs":{"count":6,"updatedAt":"1970-01-01T00:00:00.000Z"},
 "deployment":null}
```

**Canonical feed push** (1 user with a Hysteria2 + REALITY inbound, 1 shared
ForgeDNS node)

```
bad token : {"success":false,"status":401,"message":"Invalid feed push token."}
real token: {"success":true,"status":200,"message":"Feed accepted.",
             "body":{"users":1,"sharedNodes":1,"warnings":[]}}
```

**Combined subscription — `links`** (17 entries; 14 edge across 7 addresses ×
2 protocols using the **per-user** credentials from the feed, plus both VPS
inbounds and the ForgeDNS tunnel)

```
vless://11111111-2222-4333-8444-555555555555@127.0.0.1:443?alpn=http%2F1.1&fp=chrome&host=127.0.0.1&path=%2Fvl%2Fd8e5a76d8e67…
vless://11111111-2222-4333-8444-555555555555@speed.cloudflare.com:443?…
vless://11111111-2222-4333-8444-555555555555@cf.090227.xyz:443?…
… (7 addresses)
trojan://user-trojan-pw@127.0.0.1:443?alpn=http%2F1.1&fp=chrome&host=127.0.0.1&path=%2Ftr%2F6b01f82c45a7afd6188dbd7c&security…
… (7 addresses)
hysteria2://hy2pass@vps.example.com:8443?down=200&sni=vps.example.com&up=50#VPS%20Hysteria2
vless://11111111-2222-4333-8444-555555555555@203.0.113.10:443?flow=xtls-rprx-vision&fp=chrome&pbk=PUBKEY&security=reality&sid…
forgedns://stormdns@t.example.com?key=k&rr=TXT#ForgeDNS%20tunnel
```

Headers:

```
Vary: User-Agent
Cache-Control: no-store, no-cache, must-revalidate, private
Profile-Title: base64:Rm9yZ2VFZGdl
Profile-Update-Interval: 12
Subscription-Userinfo: upload=0; download=1234567; total=10737418240; expire=1798675200
```

**sing-box**

```
  outbound types: ['direct','hysteria2','selector','trojan','urltest','vless']
  groups: ['Best Ping','Edge','VPS','proxy']
  Edge group size: 14      VPS group size: 2
  tags unique: True        route.final: proxy      rule_set count: 16
  skipped: ['ForgeDNS tunnel: render/singbox: protocol "forgedns" is not a sing-box protocol']
```

**xray**

```
  balancers: ['Best Ping','Edge']     strategy: leastPing
  observatory interval: 30s
  final rule: {'balancerTag':'Best Ping','network':'tcp,udp','type':'field'}
  skipped: ['VPS Hysteria2: render/xray: protocol "hysteria2" is not an Xray protocol; use sing-box',
            'ForgeDNS tunnel: render/xray: protocol "forgedns" is not an Xray protocol; use sing-box']
```

**clash** — 16 proxies + `PROXY` select + 3 `url-test` groups; `type: hysteria2`
present; `up: 50 Mbps` emitted as a string, as mihomo requires.

**User-Agent sniffing**

```
  ClashMetaForAndroid/2.11   -> text/yaml; charset=utf-8
  sing-box/1.12              -> application/json; charset=utf-8
  v2rayNG/1.8                -> text/plain; charset=utf-8
```

**Unknown token / bad format**

```
  /sub/DOES-NOT-EXIST/links  -> status=200 bytes=0   (never a 404 that confirms guesses)
                                Subscription-Userinfo: upload=0; download=0; total=0; expire=0
  /sub/SUBTOKEN123/surprise  -> 404 unsupported subscription format "surprise";
                                supported: v2ray, clash, sing-box, xray, links, json
```

**DoH relay** (real upstream query)

```
{"Status":0,…,"Answer":[{"name":"example.com","type":1,"TTL":62,"data":"104.20.23.154"},…]}
```

**Config validation — every problem at once**

```json
{"success":false,"status":400,
 "message":"port 1234 is not a Cloudflare-reachable port; vlessUUID is not a valid UUID; cleanIPs entry \"<script>\" is not a host or IP; chainProxy: chain proxy is not a URL: junk",
 "body":{"errors":[…4 items…]}}
```

**Fragment + blockQUIC after a valid config PUT**

```
  finalmask.tcp: [{"settings":{"delay":"1","length":"100-200","packets":"tlshello"},"type":"fragment"}]
  finalmask.udp[0].type: noise
  blockQUIC present in xray: yes | sing-box: yes | clash: yes
```

**WARP scan without a backend — no invented numbers**

```
  message: Candidates only: no Backend Mode VPS is configured, and a Worker
           cannot send UDP. No latencies were measured.
  measuredBy: none | candidates: 24
  any latency present: False
  first 3: ['162.159.192.160:2408','162.159.193.236:2408','162.159.195.73:2408']
  distinct /24s: 7
```

**Clean-IP probe — a real TCP socket from workerd to a Cloudflare edge**

```
  target: speed.cloudflare.com | successRate: 3/3 | avgLatencyMs: 54
  detail: cloudflare edge
  target=<script>  ->  {"success":false,"status":400,"message":"target must be a host or IP"}
```

**LIVE DATA PATH** — `bun run testdata/wsprobe.ts`

```
  VLESS  over WS: OK — origin answered through the tunnel
    bytes back: 135, contains marker: true
    first line: [vless hdr]HTTP/1.1 200 OK
  Trojan over WS: OK — origin answered through the tunnel
    bytes back: 133, contains marker: true
    first line: HTTP/1.1 200 OK

DATA PATH: both protocols proxied real TCP.
```

**LIVE AUTH REJECTION** — `bun run testdata/wsreject.ts`

```
  REJECTED — VLESS with a wrong UUID (closed 1000, data forwarded: false)
  REJECTED — Trojan with a wrong password (closed 1000, data forwarded: false)
  REJECTED — VLESS with UDP to a non-DNS port (closed 1000, data forwarded: false)
  REJECTED — garbage bytes (closed 1000, data forwarded: false)

AUTH: every bad credential was refused.
```

**Backend Mode fallback** — backend set to an unreachable host,
`fallbackToEdge: true`

```
  backend = wss://vps.example.com/forgeedge
  VLESS  over WS: OK    Trojan over WS: OK
  worker log 'backend refused the upgrade' occurrences: 2
```

**Secure-path rotation**

```
  old = 4ezhru3f6j62y92ztj93fu2r
  new = vpheywqjknur3kvn42wdvvrh
  old panel -> 404      new panel -> 200
  old sub   -> 404      new sub   -> 200
  old session invalidated -> Unauthorized.
  feed survived the rotation: 17 entries still served
```

---

## 3. Two real defects the tests caught

1. **`randomSecurePath` kept `o` in its alphabet** while its own comment claimed
   `no l/1/0/o`. `test/securepath.test.ts` failed on the assertion. Fixed in
   `src/config/store.ts`: the alphabet is now 32 symbols (`a-z` minus `l` and
   `o`, digits `2-9`), which is also a power of two so `% length` over random
   bytes stays unbiased.
2. **`cloudflare:sockets` in pure modules.** `test/edge.test.ts` could not even
   load, because config validation and the retry policy transitively imported
   the socket module. Fixed architecturally rather than with a mock: pure policy
   moved to `src/protocols/retry.ts` and `src/config/validate.ts`, socket I/O
   isolated in `src/protocols/outbound.ts` and `src/cleanip/probe.ts`.

Two test expectations of mine were wrong, not the code, and were corrected: the
NAT64 zero-padded form (`c000:0221`, which is the correct embedding) and the
Clash YAML quoting of comma-bearing rule strings (which matches Go's
`yamlNeedsQuote`).

---

## 4. Go-side wiring the lead must add

Full detail in `docs/GO_WIRING.md` and `docs/FORGECTL_EDGE_SPEC.md`. Summary:

### 4.1 Canonical-model feed

- `internal/api/edge.go`: `EdgeFeed()`, `handleEdgePush()`, `handleEdgeFeed()`.
- Payload shape: `docs/GO_WIRING.md` §2.1 (working example in
  `testdata/feed.example.json`).
- **Run the existing `redactNodesForClient()` before sending.** The edge does not
  re-redact; a server private key that reaches KV is published.
- Set `vless_uuid` / `trojan_password` per user, or every subscriber shares one
  edge identity.
- `edge_deployments` table: schema in §2.3.
- Push on user/inbound/quota change, debounced ~5s.

### 4.2 CI guard against model drift

```bash
go run deploy/cloudflare/forgeedge/testdata/gen/main.go
cd deploy/cloudflare/forgeedge && bun test test/golden.test.ts
```

A red golden test means the edge and the VPS are about to emit different links
for the same node.

### 4.3 `forgectl edge` subcommands

`deploy | update | delete | status | push | rotate-path`, fully specified in
`docs/FORGECTL_EDGE_SPEC.md` with every Cloudflare API call, the OAuth+PKCE
parameters, the token fallback and its permission list, and exit codes.

Two things worth carrying into the implementation:
- `keep_bindings: ["kv_namespace","d1"]` on every script update, or an update
  detaches KV and every subscriber's config disappears.
- Pass `SECURE_PATH` as a plain-text binding at deploy time rather than scraping
  it from the Worker log afterwards.

### 4.4 Panel routes

`GET/POST /api/edge/deployments`, `DELETE /api/edge/deployments/:id`,
`POST …/:id/push`, `GET …/:id/status`, `POST /api/edge/deploy`,
`DELETE /api/edge/deploy/:name`, `GET /api/edge/update-check`.

### 4.5 Backend Mode on the node installer

A plain-HTTP WebSocket inbound (Xray or sing-box) on the ForgePanel node,
matching path `/` or `/vl/*` + `/tr/*`. Optionally
`POST /forgeedge/warp-scan` so the WARP scanner can report real latencies —
without it the scanner honestly reports `measured: false`.

---

## 5. Miniflare / workerd command for §7

```bash
export PATH=/tmp/forgepanel-bun/bin:$PATH
cd deploy/cloudflare/forgeedge && bun install

# runtime
CI=1 bunx wrangler dev --local --port 8801 --inspector-port 9931

# the secure path is minted on the first request and logged
SECURE=$(grep -oE 'Panel: /[a-z2-9]+/panel' .wrangler/dev.log | head -1 | sed 's|Panel: /||; s|/panel||')

# data-path probes (each starts its own origin server)
bun run testdata/wsprobe.ts  http://127.0.0.1:8801 "$UUID" "$TROJAN_PW"
bun run testdata/wsreject.ts http://127.0.0.1:8801
```

Miniflare-as-a-library (for in-process assertions) is in `docs/E2E.md`. Note it
does **not** implement `cloudflare:sockets` outbound TCP — use the `wrangler dev`
subprocess for anything touching the data path.

---

## 6. Known limits, stated rather than hidden

| Limit | Why, and what covers it |
|---|---|
| Only VLESS/Trojan-over-WS terminate at the edge | A Worker has outbound TCP and nothing else. Backend Mode covers the rest. |
| UDP is DNS-only at the edge | The only UDP that can become an HTTP request. Non-DNS UDP is refused with a clear message rather than silently dropped. |
| WARP latency is not measured at the edge | WARP is WireGuard over UDP. The scanner returns `measured: false`; the Backend Mode `/forgeedge/warp-scan` endpoint supplies real numbers. |
| No self-update at runtime | A Worker that fetches and executes remote code is a supply-chain compromise. The cron reports that a release exists; `forgectl edge update` performs it. |
| Telegram cannot deploy | Deploying needs a Cloudflare credential; gating it on a chat id means one typo hands over the account. The bot does status/panel/subs/rotate, owner-only. |
| `render.SingboxInbound` / `XrayInbound` not mirrored | The edge never renders server-side inbounds. |
| Cloudflare deploy/update/delete untested against a live account | No credentials available. The API calls are implemented in `src/deploy/cloudflare.ts` and specified in `FORGECTL_EDGE_SPEC.md`. |
