# §4 connectivity harness — build report

Everything below was executed. No claim in this file is inferred from reading
code alone; where a conclusion comes from source, the source is cited *and* the
behaviour it predicts was reproduced against a running core.

Scope discipline: every file created is under `test/harness/`. Nothing outside
that directory was edited, `go.mod`/`go.sum` were not touched, `go mod tidy` was
not run, and no `git add`/`commit`/`push` was issued. Every Go file carries
`//go:build harness` and the harness uses the standard library only.

---

## 1. Files created

| Path | Purpose |
|---|---|
| `test/harness/README.md` | how to run it locally and in CI |
| `test/harness/AGENT_REPORT.md` | this file |
| `test/harness/.gitignore` | ignores the generated `.cache/` and `results/` |
| `test/harness/run.sh` | orchestrator (cores → preflight → images → stack → driver → matrix) |
| `test/harness/docker-compose.yml` | three services, two networks, client isolated from the origin |
| `test/harness/Dockerfile.panel` | ForgePanel built from this checkout |
| `test/harness/Dockerfile.tools` | driver + origin, both `-tags harness` |
| `test/harness/matrix.go` | the case table (connectivity, policy, quick sets) |
| `test/harness/runner.go` | one connectivity case end to end, with repair attribution |
| `test/harness/policy.go` | the enforcement cases |
| `test/harness/panelapi.go` | REST client for the panel |
| `test/harness/clientcore.go` | emitted subscription → runnable config → running core |
| `test/harness/probe.go` | HTTP / HTTPS / DNS probes and the isolation control |
| `test/harness/socks.go` | SOCKS5 CONNECT + UDP ASSOCIATE, hand-rolled |
| `test/harness/dnswire.go` | minimal DNS encoder/decoder shared by origin and probe |
| `test/harness/report.go` | `matrix.json`, printed table, derived findings |
| `test/harness/harness_test.go` | opt-in `go test` entry point |
| `test/harness/cmd/harness/main.go` | the driver (runs in the client container) |
| `test/harness/cmd/internetd/main.go` | the isolated origin (HTTP, HTTPS, REALITY dest, UDP DNS) |

Generated at runtime, not committed: `test/harness/.cache/bin/` (verified core
binaries) and `test/harness/results/` (matrix + per-case artefacts).

---

## 2. Gate commands

### The harness compiles under its tag

```
$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go build -tags harness ./test/harness/...
$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go vet   -tags harness ./test/harness/...
```
Both exit 0, no output.

### The harness is invisible to the normal build

```
$ GOFLAGS=-mod=mod /home/ubuntu/sdk/go124/bin/go build ./...
exit=0

$ GOFLAGS=-mod=mod /home/ubuntu/sdk/go124/bin/go vet ./test/...
go: warning: "./test/..." matched no packages
no packages to vet
exit=0

$ GOFLAGS=-mod=mod /home/ubuntu/sdk/go124/bin/go test ./test/...
go: warning: "./test/..." matched no packages
no packages to test
exit=0
```

Without the tag the whole directory matches **no packages at all** — the build
constraints exclude every file, so `go build ./...` and `go test ./...` cannot
be affected by anything here.

### The opt-in test refuses to run outside the fixture

```
$ GOFLAGS=-mod=mod go test -tags harness -run TestConnectivityMatrix -count=1 ./test/harness/
ok  	github.com/forgepanel/forgepanel/test/harness	0.004s
```
(skips without `FORGEPANEL_HARNESS=1`, by design — the matrix mutates panel state)

### The compose file validates

```
$ docker compose -f test/harness/docker-compose.yml config
COMPOSE_CONFIG=OK
```

### The images build

```
$ docker compose -f test/harness/docker-compose.yml build
 Image forgepanel-harness-tools:local Built
 Image forgepanel-harness-panel:local Built
```

### The pinned cores are fetched and verified against the panel's own pins

`run.sh` reads the versions and SHA-256s out of `internal/core/binmgr/binmgr.go`
rather than duplicating them, so a version bump cannot leave the harness testing
a stale core.

```
xray sha:    23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
singbox sha: a3a3ff223b23c3f4731d0a17cb0ef94c97ce257c70721a5b07dc7ca079203c9f
Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)
sing-box version 1.13.15
```
Both digests equal the values in `binmgr.pinnedSHA256`.

---

### The matrix itself

```
$ ./test/harness/run.sh --no-fail
isolation: origin internet:8080 reachable without tunnel = false
           (dial tcp: lookup internet on 127.0.0.11:53: server misbehaving)
running 57 cases against http://panel:2053
...
total=57  pass=20  fail=31  experimental=1  unsupported=5
```

Full table in `results/matrix.txt`, machine-readable rows in `results/matrix.json`.

The isolation control is the first line of every run and is load-bearing: the
client container cannot even *resolve* the origin, so any payload it verifies
crossed the tunnel.

---

## 3. Reproducibility

The matrix was run three times end to end. Comparing the three, **one** case out
of 57 ever changed verdict:

| Case | run 1 | run 2 | run 3 |
|---|---|---|---|
| `vless/xhttp/none` | pass | fail | pass |
| `vless/grpc/tls` | fail | fail | fail | *(same verdict; run 1 attributed it before the pin repair existed)* |
| `trojan/tcp/tls`, `trojan/ws/tls` | fail | fail | fail | *(same verdict, repair attribution differed under load)* |

Everything else — all 20 passes, all 31 failures, the single `experimental` and
all 5 `unsupported` — reproduced identically in every run that reached it.
(Run 1's last 18 cases are excluded from the comparison: the panel's 15-minute
access token expired mid-run and they all failed with HTTP 401. That was a
harness defect, now fixed — `Panel.do` renews the session on a 401 and retries
once.)

The residual instability has a single cause, and it is a property of the panel:
**every inbound or user mutation restarts the proxy core.** Creating an inbound,
creating a user and assigning it each call `startBackground(s.reloadEngines)`,
and `supervisor.Apply` replaces the running process — so an inbound that was
listening a moment ago answers the next connection with a reset, and every live
tunnel on that core drops. The harness now waits for the listener to come back
between probe attempts rather than scoring the restart as a failure; an operator
adding a user to a busy panel has no such luxury.

---

## 4. Findings, with the experiment that established each

Nine findings, derived automatically from the results and printed under the
table. Each names the cases that produced it. The three that need an
experiment beyond the matrix rows are shown with it here.

### BLOCKER — the pinned sing-box cannot run in the shipped image

Production `Dockerfile` runtime stage is `alpine:3.21`; `binmgr` downloads
`sing-box-1.13.15-linux-amd64.tar.gz` at runtime and the supervisor execs it.

```
$ file .cache/bin/sing-box-1.13.15/sing-box
ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped

$ docker run --rm -v "$PWD/.cache/bin:/cores:ro" alpine:3.21 \
    sh -c '/cores/sing-box-1.13.15/sing-box version; echo exit=$?'
sh: /cores/sing-box-1.13.15/sing-box: not found
exit=127

$ docker run --rm -v "$PWD/.cache/bin:/cores:ro" debian:bookworm-slim \
    sh -c '/cores/sing-box-1.13.15/sing-box version | head -1; echo exit=$?'
sing-box version 1.13.15
exit=0

$ docker run --rm -v "$PWD/.cache/bin:/cores:ro" alpine:3.21 \
    sh -c '/cores/xray-v26.3.27/xray version | head -1; echo exit=$?'
Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)
exit=0
```

Hysteria2, TUIC, AnyTLS, ShadowTLS, WireGuard and SSH therefore cannot work in
the official container at all. Xray is unaffected (static). `run.sh` repeats
this check on every run and records it in `results/preflight.json`.

### BLOCKER — Xray TLS client configs cannot accept the panel's own certificate

14 cases, every `*/tls` combination across all five transports. Xray 26 removed
`allowInsecure`:

```
$ xray run -test -c allowinsecure.json
Failed to build TLS config. > common/errors: The feature "allowInsecure" has been
removed and migrated to "pinnedPeerCertSha256". Please update your config(s)...
```

`applyExportDefaults` still sets `Security.AllowInsecure`; `render/xray.go` never
emits it and Xray would reject it; nothing in the create or export path sets
`Security.PinSHA256`. I established the replacement empirically — an xray VLESS
inbound with a self-signed cert, and an xray client pinned to
`hex(sha256(leaf DER))`:

```
$ curl -sS --socks5-hostname 127.0.0.1:19201 http://127.0.0.1:8099/ \
       -o /dev/null -w 'HTTP=%{http_code}\n'
HTTP=200
```

So the pin is the hex SHA-256 of the leaf certificate in DER form, and injecting
it is exactly what turns all 14 red cells green in the harness.

### BLOCKER — Shadowsocks subscriptions are unusable as delivered

All 7 cipher cases. `stampIdentity` writes the user's password onto the node,
but `applyXrayClients` returns early for Shadowsocks so the server keeps the
template PSK. For the 2022-blake3 family it is fatal before it is even wrong:

```
Failed to start: proxy/shadowsocks_2022: create method > decode key:
illegal base64 data at input byte 1
```

`keygen.Password` produces base64url (`K-bQWMKGwURW01grDpO33A`); a SIP022 PSK
must be standard base64 of exactly the key length. Substituting the inbound's
own PSK makes the tunnel carry a verified payload, which places the defect in
the subscription and not the transport.

### The remaining six

`quic-outbound-carries-utls` (blocker), `policy-not-enforced` (blocker),
`singbox-subscription-not-runnable`, `no-online-status`, `traffic-not-accounted`,
`no-inbound-disable`, `accepted-then-skipped` — all derived from the run and
printed in full under the table in `results/matrix.txt`.

Two are worth calling out because they are the negative half of the contract:

* **`policy/user-over-quota` fails.** The tunnel proved it worked, the limit was
  set to 128 KiB, 768 KiB was pushed, the scheduler moved the user to
  `limited` — and the next probe still transferred a full 262144 bytes intact.
  `enabledInboundSpecs` skips only `StatusDisabled` and `StatusExpired`, so a
  limited user stays materialised into the served inbound.
* **`policy/inbound-disabled` fails.** `store.Inbound.Enabled` is honoured by
  both `enabledInboundSpecs` and `subscriptionNodes`, but `CreateInbound` sets it
  true and nothing clears it; `PUT /api/admin/inbounds/:id` binds a `model.Node`,
  which has no such field. Deleting is the only way to take an inbound out of
  service.

The four enforcement rules that **do** hold — `user-disabled`, `user-expired`,
`inbound-removed`, `wrong-credential` — each proved the tunnel worked first, so
the refusal is attributable.

### Per-protocol verdict

| | |
|---|---|
| Proven as delivered | VLESS and VMess over tcp/ws/grpc/httpupgrade/xhttp with `security=none`; VLESS REALITY over tcp (with and without Vision), grpc and xhttp; Trojan tcp without TLS |
| Works, but not as delivered | every `*/tls` combination (needs the cert pin); all 7 Shadowsocks ciphers (needs the server's PSK); Hysteria2 and TUIC (needs the uTLS block removed); ShadowTLS (needs the inner shadowsocks hop) |
| Traffic proven, accounting unprovable | AnyTLS — the only `experimental` row |
| Declared unsupported, correctly | `h2`, `quic`, `kcp` (refused at create with the right message), SSH and AmneziaWG (no engine — but only discoverable from the engine dump) |
| No client leg at all | WireGuard and Brook — the subscription contains no proxy outbound for them |

---

## 4. Notes on precision

* The finding text "nothing populates `Security.PinSHA256`" refers to the
  panel's own generation path. `internal/protocol/parse/uri.go:501` does set it
  — when *importing* a foreign link that already carries a `pinSHA256`
  parameter. No create, default or export path in the panel ever produces one,
  which is what makes a panel-created TLS inbound unusable by its own client
  config.
* Per-user accounting for sing-box protocols is classified `experimental`, not
  `fail`. That is not a courtesy: the limitation is real and verifiable, and
  `internal/core/engine/multi.go` already documents it.
