# ForgeEdge

A Cloudflare Worker deployment target for ForgePanel. It terminates **VLESS and
Trojan over WebSocket** at Cloudflare's edge, serves DoH, and serves the **same
canonical subscription** the ForgePanel VPS serves — so a subscriber has one URL
carrying their VPS inbounds, the edge entries and their ForgeDNS tunnels
together, with url-test failover between them.

---

## The constraint that shapes everything

A Cloudflare Worker has **outbound TCP via `cloudflare:sockets`, and nothing
else**. No UDP socket. No raw IP. No QUIC. No inbound listener on an arbitrary
port.

That is not a limitation to engineer around; it is the platform contract. It
means the complete list of what can terminate at the edge is:

- VLESS over WebSocket (TCP)
- Trojan over WebSocket (TCP)
- DNS-over-UDP, relayed to DoH — because DNS is the one UDP flow that can be
  turned into an HTTP request

Everything else — Hysteria2, TUIC, WireGuard, AnyTLS, ShadowTLS, SSH, Brook, and
every voice/video call, game and QUIC connection — needs a real server.

**Backend Mode** is the honest answer. The Worker stops being a proxy and
becomes a WebSocket relay in front of the operator's own ForgePanel node. The
VPS runs the real Xray/sing-box, so it has the full protocol matrix and real
UDP. The Worker still contributes what only it can:

- a Cloudflare anycast entry IP that is hard to block wholesale
- TLS on Cloudflare's certificate, across six CDN ports
- the panel, the subscription, the DoH endpoint and the clean-IP rotation

The upgrade is forwarded **verbatim** — same path, same `sec-websocket-protocol`
early data, same query — so the backend sees exactly what the client sent and no
re-framing happens anywhere.

---

## One user, one subscription

`https://<worker>/<SECURE_PATH>/sub/<sub_token>` returns the union of:

| Source | Where it comes from |
|---|---|
| VPS inbounds | the canonical feed the Go panel pushes (or the edge pulls) |
| Edge entries | minted here, per user, across every clean IP × CDN port |
| ForgeDNS tunnels | `shared_nodes` in the same feed |
| Chain proxy | the configured share link, as an explicit entry |
| WARP / WARP Pro | once accounts are registered |

Formats — `links`, `v2ray`, `clash`, `sing-box`, `xray`, `json` — chosen by an
explicit suffix, else `?format=`/`?app=`, else the User-Agent. The same
precedence, aliases and headers as `internal/api/sub.go`.

Failover groups are emitted per core: sing-box `urltest`, Clash `url-test`, Xray
`leastPing` balancers driven by the observatory. Three groups — **Best Ping**
(everything), **Edge**, **VPS** — so a user whose edge is blocked fails over to
the VPS without touching their config.

### Why the output is byte-identical to the VPS panel's

`src/model/node.ts` mirrors `internal/protocol/model/model.go` field for field,
and `src/export/` mirrors `internal/protocol/{export,render}`. Not
approximately — `testdata/gen/main.go` runs the **real Go exporters** over 20
nodes covering every protocol, transport and security layer, and
`test/golden.test.ts` asserts byte equality against the result.

That required reimplementing three Go behaviours JavaScript does not share:

- `url.Values.Encode()` sorts keys; `URLSearchParams` does not, and leaves `/`
  and `:` unescaped where Go escapes them
- `url.PathEscape` and `url.QueryEscape` have different reserved-character sets
- `encoding/json` sorts map keys and HTML-escapes `<`, `>`, `&` — which changes
  the base64 of every `vmess://` link

See `src/common/encoding.ts` and `src/export/gojson.ts`.

---

## Features

**Security.** A compulsory random secure path (24 chars, `a-z2-9` minus the
ambiguous glyphs) gates the panel, the API and every subscription URL.
Unmatched paths get a decoy — a reverse proxy to a real site, or a bare 404.
Constant-time comparison, so the path cannot be searched a character at a time.
Regenerable from the panel, which invalidates every old URL including
subscriptions. Panel administration additionally needs a password (HMAC-signed,
12h sessions).

The `/vl/…` and `/tr/…` data paths are deliberately **not** under the secure
path — those URLs live inside every subscriber's config, so putting the admin
secret in them would hand it to every user. The credential authenticates there.

**Outbound.** Direct, plus two escape hatches for destinations a Worker cannot
reach: a `proxyip` relay, or NAT64 prefix rewriting. The retry fires only when
the first attempt returned zero bytes — the signature of a blackholed connection.

**Evasion.** Xray `finalmask` TLS fragmentation and UDP noise, sing-box
`record_fragment`, ECH (literal config list or DNS-resolved), uTLS fingerprints,
SNI case jitter, WebSocket 0-RTT early data.

**Routing.** One rule catalogue, three cores. Bypass Iran/China/Russia/LAN,
bypass sanctioned services (one toggle, ten geosites), block
QUIC/ads/malware/phishing/cryptominers/porn, plus custom domain and CIDR rules.
A test asserts that every enabled rule reaches **all three** cores — a toggle
that reaches two of three is how "bypass Iran" quietly stops working.

**Clean IPs.** Built-in Cloudflare-fronted seeds, extended from operator source
URLs on a cron, every entry validated before it can reach a subscription. The
on-demand probe speaks HTTP/1.1 to :443 and requires Cloudflare's own 400 plus a
`cf-ray` header — a bare TCP connect proves nothing.

**WARP.** Account registration via WebCrypto X25519, wg-quick `.conf` output,
and a tuned "pro" variant with AmneziaWG junk packets (`Jc`/`Jmin`/`Jmax`; S1/S2
and H1..H4 stay standard because Cloudflare's server is not Amnezia-aware and
would drop the handshake). Both also emit as canonical nodes into the
subscription.

The endpoint **scanner** enumerates and ranks candidates across all seven
published WARP prefixes. It does not measure latency, because a Worker cannot
send UDP — it returns `measured: false` and no latency field unless a Backend
Mode VPS answers `POST /forgeedge/warp-scan`.

---

## Layout

```
src/
  worker.ts             fetch + scheduled entry points
  router.ts             data path vs control path; the decoy
  auth.ts               secure-path gate, sessions, password
  sub.ts                subscription endpoint
  model/                mirror of internal/protocol/model
  export/               mirror of internal/protocol/{export,render} + subscription assembly
  routing/              the rule catalogue and its three emitters
  protocols/            VLESS/Trojan framing, WS plumbing, outbound, Backend Mode
  edge/                 canonical feed, edge node minting, chain proxy parsing
  warp/ cleanip/ dns/   WARP, clean IPs, DoH
  config/ panel/ deploy/ telegram/
test/                   316 tests
testdata/               golden.json (from Go), the generator, live probes
docs/                   GO_WIRING.md, FORGECTL_EDGE_SPEC.md, E2E.md
```

## Commands

```bash
bun install
bunx tsc --noEmit    # typecheck
bun test             # 316 tests
bunx wrangler dev --local --port 8801
bunx wrangler deploy
```

Deploying: see `docs/FORGECTL_EDGE_SPEC.md`. Connecting the Go panel: see
`docs/GO_WIRING.md`. Running it locally: see `docs/E2E.md`.

## Configuration

Everything lives in KV and is editable from the panel. **No dashboard
environment variables are required** — the first request bootstraps the config,
mints the secure path and logs the panel URL. The optional bindings in
`src/env.ts` (`SECURE_PATH`, `ADMIN_PASSWORD`, `FEED_PUSH_TOKEN`,
`CF_API_TOKEN`, `CF_ACCOUNT_ID`) are escape hatches, not requirements. D1 is
optional and never on the read path.

## Prior art

`third_party/BPB-Worker-Panel`, `third_party/BPB-Wizard` (Mozilla Public
License 2.0 / GPL-3.0) and `third_party/Nova-Proxy`, `third_party/Nova-Wizard`
(PolyForm Noncommercial) were read for their architecture. ForgeEdge is an
independent implementation against ForgePanel's canonical model; no code was
copied. The debt worth naming explicitly: Nova's Backend Mode is where the
"a Worker cannot carry UDP, so front your own VPS" framing comes from, and BPB's
panel is the reference for the clean-IP/CDN-port matrix and the WARP-Pro
distinction.
