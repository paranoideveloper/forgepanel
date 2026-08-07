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

## 3. Findings, with the experiment that established each

<!--MATRIX-->

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
