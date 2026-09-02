# ForgePanel connectivity harness (§4)

This harness answers one question that no unit test in this repository can:
**does a configuration ForgePanel generates actually carry traffic?**

It does that by refusing to accept anything smaller as evidence. For each
protocol × transport × security combination it creates the inbound through the
REST API, creates a user, fetches that user's subscription, launches the real
proxy core from what came back, and pulls a 256 KiB payload from a server the
client container has no route to. The payload is verified byte for byte, the
panel's own traffic counters are read back, and the negative cases (expired,
over quota, disabled, wrong credential) have to be refused.

The output is `results/matrix.json` — machine readable, one row per combination
— and `results/matrix.txt`, the same thing as a printed table.

---

## Why a passing row means something

```
   client ──[ edge, internal ]── panel ──[ transit ]── internet
```

* `edge` is declared `internal: true`. The client container has no default
  route, no DNS entry for the origin, and no path to anything except the panel.
* `internet` is attached only to `transit`, which the client is not on.
* `panel` bridges the two, which is exactly a proxy server's position in
  production.

Before it runs a single case the harness dials the origin directly. If that
succeeds the run aborts: the isolation the results depend on is not there, so
the results would not mean anything. Every request the probes make also uses
SOCKS5 with the hostname unresolved locally, so a passing case additionally
proves the *far* side did the name resolution.

## Running it

```bash
cd test/harness

./run.sh                       # the whole matrix: connectivity + policy
./run.sh --set quick           # the five paths that must never regress
./run.sh --set connectivity    # protocol matrix only
./run.sh --set policy          # enforcement rules only
./run.sh --only vless,trojan   # anything whose case id contains these
./run.sh --keep                # leave the stack up afterwards to poke at it
./run.sh --no-fail             # always exit 0 (report-only)
```

`run.sh` needs Docker with the Compose plugin, `curl`, `unzip` and `tar`. It:

1. reads the pinned core versions **and their SHA-256** straight out of
   `internal/core/binmgr/binmgr.go`, downloads them into `.cache/bin/`, and
   verifies them — so a version bump in the panel cannot leave the harness
   silently testing an older core;
2. execs each pinned core inside the base image the production `Dockerfile`
   ships and records the outcome (see *Preflight* below);
3. builds the two images, starts the panel and the origin;
4. reads the panel's one-time first-run setup token from
   `/var/lib/forgepanel/setup-token.txt` — the same file the installer reads —
   and passes it to the driver;
5. runs the driver in the client container and leaves the matrix in `results/`.

Exit code is non-zero if any case failed, unless `--no-fail` is given.

### Running it from `go test`

```bash
FORGEPANEL_HARNESS=1 go test -tags harness -run TestConnectivityMatrix ./test/harness/
```

This must run **inside the harness client container**, and it deliberately skips
unless `FORGEPANEL_HARNESS=1` is set: the matrix creates, rewrites and deletes
inbounds and users, so pointing it at anything but a disposable fixture would
destroy real state. On a developer machine `go test -tags harness ./...` is a
no-op, and plain `go test ./...` does not even compile these files.

### In CI

```yaml
- name: connectivity harness
  run: ./test/harness/run.sh --set quick
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: connectivity-matrix
    path: test/harness/results/
```

`--set quick` is the PR gate (about two minutes). Run the full matrix nightly:
it takes considerably longer, mostly because proving that traffic was *not*
accounted requires waiting out the panel's 10-second poll and the sweep's
one-minute tick.

Cache `test/harness/.cache/bin` between runs to skip the core downloads. The
only network the harness needs is for that download and the two image builds.

---

## Everything is built with `-tags harness`

Every Go file here starts with `//go:build harness`. That is not decoration: it
keeps the harness out of `go build ./...`, `go vet ./...` and `go test ./...` for
the product, so nothing in this directory can affect a release build. The two
Dockerfiles pass `-tags harness` explicitly.

The harness uses the standard library only. The SOCKS5 client (CONNECT and UDP
ASSOCIATE) and the DNS wire format are implemented here rather than pulled in,
so a malformed reply from a core produces a precise error instead of a generic
dial failure, and so the harness has no dependency that could drift from the
product's.

---

## What each case proves

| Step | Assertion |
|---|---|
| `create-inbound` | the REST API accepts the combination |
| `engine-render` | the engine layer did not silently drop it into `Skipped` |
| `inbound-listening` | the port the panel promised is actually accepting |
| `fetch-subscription` | `/sub/<token>/<format>` returns something |
| `parse-client-config` | what it returned is a runnable client configuration |
| `launch-client` | the real core validates *and starts* that configuration |
| `tcp-payload` | 256 KiB arrives with a matching SHA-256, over a path that does not otherwise exist |
| `https-payload` | the tunnel carries an opaque TLS stream, not just cleartext HTTP |
| `udp-dns` | a name only the origin serves resolves through the tunnel over UDP |
| accounting | the user's `used_traffic` rose by roughly what was pushed |
| online | the panel exposes that the user connected |

UDP is covered explicitly rather than implied. Hysteria2 and TUIC are QUIC, so
every byte of those cases is already UDP; the DNS probe additionally proves UDP
*relay inside* the tunnel, which is a separate capability a proxy can lack while
passing every HTTP test.

### Verdicts

| Status | Meaning |
|---|---|
| `pass` | worked **as delivered**, with traffic, UDP where requested, and accounting |
| `fail` | did not work as delivered, or a policy rule failed to stop traffic |
| `experimental` | traffic is proven but something else cannot be — recorded with the reason |
| `unsupported` | the panel or the engine declares the combination unusable, and says so |

The line the harness holds is that **the deliverable is a subscription that works
as delivered**. When a case only carries traffic after the harness changes the
emitted config, that case is a `fail`, and the change is recorded on the row as
a named `repair:*` mutation with its detail. That is how a red cell becomes
actionable: `repair:xray-tls-pin` making a case pass says the transport is fine
and the emitted TLS config is what is broken.

Two adaptations are *not* repairs and do not fail a row, because they change
nothing about whether the tunnel authenticates or carries bytes:

* `listen-port` — the local SOCKS port is moved so concurrent cases do not
  collide;
* `added-inbound` / `added-route` — the sing-box subscription format emits no
  `inbounds[]`, so nothing can be sent through it as delivered. This is reported
  as its own finding rather than smeared across every sing-box protocol row.

### Findings

Beyond the per-case rows, the report derives **findings**: conclusions that span
cases, each naming the cases that produced it and the code responsible. They are
in `matrix.json` under `findings` and printed under the table. A finding is
never an opinion — it is emitted only when specific evidence in the results
triggers it.

### Preflight

Separately from the matrix, `run.sh` execs each pinned core inside the base
image the production `Dockerfile` ships (`alpine:3.21`) and writes the result to
`results/preflight.json`, which the driver folds into the report. This exists
because the harness runs its own containers on a glibc base — see the header of
`Dockerfile.panel` — and a harness that silently papered over a defect in the
shipped image would be worse than no harness.

---

## Layout

| File | Role |
|---|---|
| `run.sh` | orchestrator: cores, preflight, images, stack, driver, results |
| `docker-compose.yml` | the three services and the two networks |
| `Dockerfile.panel` | ForgePanel, built from this checkout |
| `Dockerfile.tools` | the driver and the origin, both `-tags harness` |
| `matrix.go` | the case table — what is attempted, as data |
| `runner.go` | one connectivity case, end to end, with repair attribution |
| `policy.go` | the enforcement cases (expired, quota, disabled, tampered) |
| `panelapi.go` | REST client for the panel |
| `clientcore.go` | emitted subscription → runnable config → running core |
| `probe.go` | the HTTP / HTTPS / DNS probes and the isolation control |
| `socks.go` | SOCKS5 CONNECT and UDP ASSOCIATE |
| `dnswire.go` | minimal DNS encoder/decoder, shared by origin and probe |
| `report.go` | `matrix.json`, the printed table, and the findings |
| `cmd/harness` | the driver, runs in the client container |
| `cmd/internetd` | the origin, runs in the internet container |
| `harness_test.go` | opt-in `go test` entry point |

`.cache/` (downloaded cores) and `results/` (matrix and per-case logs) are
generated; neither belongs in version control.

## When a case fails

`results/logs/<case>.*` holds everything for that case: the subscription exactly
as the panel returned it, the client configuration the harness derived from it,
and the core's own stderr. Re-run the single case with the stack left up:

```bash
./run.sh --only vless/ws/tls --keep
docker compose -f docker-compose.yml exec panel  cat /var/lib/forgepanel/engines/xray.json
docker compose -f docker-compose.yml logs panel
```
