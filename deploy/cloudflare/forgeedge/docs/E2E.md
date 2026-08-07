# Running ForgeEdge under workerd / Miniflare

Everything below was run for real; the transcript is in `../AGENT_REPORT.md`.

## Prerequisites

```bash
export PATH=/tmp/forgepanel-bun/bin:$PATH     # bun 1.3.14
cd deploy/cloudflare/forgeedge
bun install
```

## Unit tests + typecheck

```bash
bunx tsc --noEmit          # 0 errors
bun test                   # 316 pass, 0 fail
```

Regenerate the Go-parity golden file after any change to `internal/protocol/`:

```bash
cd ../../..
go run deploy/cloudflare/forgeedge/testdata/gen/main.go
cd deploy/cloudflare/forgeedge && bun test test/golden.test.ts
```

## Boot the Worker on real workerd

`wrangler dev --local` runs the actual workerd binary with a Miniflare-simulated
KV, which is the same runtime Cloudflare runs — `cloudflare:sockets`,
`WebSocketPair` and the 101-response path all behave as in production.

```bash
CI=1 bunx wrangler dev --local --port 8801 --inspector-port 9931
```

The first request bootstraps KV and prints the secure path:

```
[forgeedge] bootstrapped. Panel: /<24 chars>/panel
```

Capture it:

```bash
SECURE=$(grep -oE 'Panel: /[a-z2-9]+/panel' .wrangler/dev.log | head -1 | sed 's|Panel: /||; s|/panel||')
B="http://127.0.0.1:8801/$SECURE"
```

### Miniflare as a library (for the §7 harness)

If §7 wants to drive the Worker from inside a Node/Bun test process instead of a
subprocess:

```bash
bun add -d miniflare
```

```ts
import { Miniflare } from 'miniflare';

const mf = new Miniflare({
  scriptPath: '.wrangler/dryrun/worker.js',   // from `wrangler deploy --dry-run --outdir=.wrangler/dryrun`
  modules: true,
  compatibilityDate: '2025-08-01',
  compatibilityFlags: ['nodejs_compat'],
  kvNamespaces: ['KV'],
});
const res = await mf.dispatchFetch('http://edge.local/');
```

Note that Miniflare-as-a-library does **not** implement `cloudflare:sockets`
outbound TCP; only the subprocess `wrangler dev --local` path does. So use the
library form for panel/subscription/routing assertions, and `wrangler dev` for
anything touching the data path.

## The control-plane walk-through

```bash
J=.wrangler/cookies

# decoy: nothing leaks at an unmatched path
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8801/          # 404
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8801/panel     # 404

# first-run password (min 10 chars), then a session cookie
curl -s -c $J -X POST "$B/api/login" -H 'content-type: application/json' \
  -d '{"password":"a-long-enough-password"}'

curl -s -b $J "$B/api/status" | python3 -m json.tool
PUSH=$(curl -s -b $J "$B/api/status" | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"]["feedPushToken"])')

# push the canonical feed exactly as the Go panel will
curl -s -X POST "$B/feed" -H "Authorization: Bearer $PUSH" \
  -H 'content-type: application/json' --data-binary @testdata/feed.example.json

# every subscription format
for f in links v2ray clash sing-box xray json; do
  echo "--- $f"; curl -s "$B/sub/SUBTOKEN123/$f" | head -3
done

# User-Agent sniffing when no format is given
curl -s -o /dev/null -w '%{content_type}\n' -A 'ClashMetaForAndroid/2.11' "$B/sub/SUBTOKEN123"

# DoH relay
curl -s -H 'accept: application/dns-json' "$B/dns-query?name=example.com&type=A"

# clean-IP probe (opens a real TCP socket to a Cloudflare edge)
curl -s -b $J "$B/api/clean-ip/probe?target=speed.cloudflare.com"

# WARP scan — returns candidates with measured:false unless Backend Mode is on
curl -s -b $J -X POST "$B/api/warp/scan"

# rotate: every previous URL dies
curl -s -b $J -X POST "$B/api/rotate-path"
```

## The data plane

Two probes live in `testdata/`. Both start their own origin server, so a pass
means bytes really traversed the tunnel and came back.

```bash
UUID=$(curl -s -b $J "$B/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"]["vlessUUID"])')
TRPW=$(curl -s -b $J "$B/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"]["trojanPassword"])')

# positive: VLESS and Trojan proxy real TCP
bun run testdata/wsprobe.ts http://127.0.0.1:8801 "$UUID" "$TRPW"

# negative: wrong credentials, UDP to a non-DNS port, and garbage are all refused
bun run testdata/wsreject.ts http://127.0.0.1:8801
```

### Backend Mode

Enable it, point it anywhere unreachable, and confirm `fallbackToEdge` keeps
users online:

```bash
curl -s -b $J "$B/api/config" | python3 -c '
import sys,json
c=json.load(sys.stdin)["body"]
c["backend"]={"enabled":True,"url":"wss://unreachable.example/forgeedge","token":"","fallbackToEdge":True}
print(json.dumps(c))' > /tmp/cfg.json
curl -s -b $J -X PUT "$B/api/config" -H 'content-type: application/json' --data-binary @/tmp/cfg.json

bun run testdata/wsprobe.ts http://127.0.0.1:8801 "$UUID" "$TRPW"   # still OK
grep 'backend refused the upgrade' .wrangler/dev.log                # fallback logged
```

To test a **working** backend, run any WS-inbound Xray/sing-box locally and point
`backend.url` at it. The Worker forwards the upgrade verbatim, so the backend
must speak the same protocol the client used, on a path it accepts (`/` is
simplest — the edge sends `/vl/<24 hex>` or `/tr/<24 hex>`).

## What cannot be tested locally

| | Why |
|---|---|
| Real WARP latency | WARP is WireGuard over UDP; a Worker has no UDP socket. Needs the Backend Mode `POST /forgeedge/warp-scan` endpoint on a VPS. |
| Cloudflare deploy/update/delete | Needs a real account. The API calls are in `src/deploy/cloudflare.ts`; the flow is specified in `FORGECTL_EDGE_SPEC.md`. |
| Custom-domain attachment | Needs a zone in the account. |
| Cron triggers | `wrangler dev` does not fire them. Invoke the same functions directly, or use `wrangler dev --test-scheduled` and `curl "http://127.0.0.1:8801/__scheduled"`. |
