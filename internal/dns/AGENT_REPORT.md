# §5 Domain & DNS Automation Wizard — Agent Report

Branch: `fix/round2-remediation`. Nothing outside the files listed below was
touched: `git diff --name-only` over tracked files returns empty for this work
(the one modified tracked file, `internal/api/server.go`, is the §3 agent's
diag-route addition, not mine).

---

## 1. Wiring the lead must add (two lines)

### `internal/api/server.go`

Add the import:

```go
forgedns "github.com/forgepanel/forgepanel/internal/dns"
```

and **one line** inside the `admin` group in `routes()` (next to the existing
`admin.GET("/domains/check", …)` block, around line 393):

```go
forgedns.RegisterRoutes(admin, forgedns.Deps{Credentials: s.dnsStore, Encryptor: s.dnsEnc, Pools: s.dnsStore, CleanIPs: s.dnsStore})
```

Everything mounts under `/api/admin/dns/*` behind the existing
`s.signer.Middleware()`. `RegisterRoutes` takes a `gin.IRouter`, so the prefix
and auth are entirely the caller's choice.

`s.dnsStore` and `s.dnsEnc` need constructing once wherever the store is opened:

```go
dnsStore, err := forgedns.NewGormStore(db)          // AutoMigrates its own 3 tables
dnsEnc,   err := forgedns.NewAESGCMFromPassphrase(cfg.MasterKey)
```

`NewGormStore` migrates `dns_credentials`, `dns_pool_entries` and
`dns_clean_ip_sets` — tables owned entirely by `internal/dns`, so nothing in
`internal/store` changes. If the lead prefers to defer persistence,
`forgedns.NewMemStore()` satisfies all three interfaces and the routes work
immediately (in-process only). `Pools` and `CleanIPs` are optional: omitting
them makes those routes return **501** with the wiring instruction rather than
panicking. `Credentials` and `Encryptor` are required; omitting the encryptor
makes every credential route return 400 saying credentials are never stored in
plaintext.

Optional `Deps` fields: `Resolver` (defaults to 1.1.1.1/8.8.8.8), `Preflight`
(pin a staging CA or disable the crt.sh lookup), `Audit func(c *gin.Context,
action, target, result string)` — pass `s.audit`-shaped closure to get
`dns.record.created`, `dns.provision`, etc. in the audit log — and `Now`.

### `cmd/forgectl/main.go`

Add **one case** to the dispatch switch in `main()`:

```go
case "provision":
    err = cmdProvision(os.Args[2:])
```

and, optionally, one line to `usage()`:

```
  forgectl provision --domain <domain> --cf-token <token> [--scan] [--json]
```

`cmdProvision` is fully self-contained in `cmd/forgectl/provision.go`; no other
file in `package main` was modified.

---

## 2. Files created

### `internal/dns/` — new package (34 files, ~7 400 lines of source + ~6 000 of tests)

| File | Lines | Contents |
|---|---|---|
| `dns.go` | 319 | Package doc, `Record`/`Zone`/`Identity` types, FQDN + record validation |
| `errors.go` | 155 | `*Error` with `Kind`, `MissingScope`, `Remediation`; sentinels and helpers |
| `provider.go` | 235 | `Provider`, `ProxyController`, `ZoneSettingsController`, `Credentials`, `EnsureRecord`, `DeleteByName` |
| `registry.go` | 193 | Provider registry: 3 implemented + 6 typed-not-implemented entries |
| `resolver.go` | 161 | `Resolver` interface, `NetResolver`, `IsNXDOMAIN` |
| `zone.go` | 232 | `ZoneCandidates`, `ResolveZone` (parent walk), NS-delegation detection + ACME consequence |
| `cloudflare.go` | 421 | CF client: transport, retries, scope-precise error mapping, token verify, zones |
| `cloudflare_records.go` | 350 | CF records CRUD, SRV/MX encoding, `SetProxied`, zone settings |
| `arvancloud.go` | 260 | Arvan client: transport, error mapping, domains |
| `arvancloud_records.go` | 256 | Arvan polymorphic value encoding/decoding, records CRUD, cloud flag |
| `desec.go` | 252 | deSEC client: transport, Retry-After 429 handling, error mapping, domains |
| `desec_records.go` | 298 | deSEC RRset semantics, presentation-format encoding, TTL clamping retry |
| `naming.go` | 328 | `NameTemplate`, `RandomLabel`, `GenerateNames`, `BulkCreate` |
| `preflight.go` | 310 | Preflight types, `Run`, zone/resolution/delegation checks, `FormatReport` |
| `preflight_acme.go` | 260 | Challenge-path (http-01 + dns-01), ACME directory, rate-limit headroom |
| `cleanip.go` | 159 | `ScanConfig`, `IPResult`, `ScanReport`, CF ranges |
| `cleanip_sample.go` | 191 | `SampleIPs`, small-range enumeration, `randomIPIn` |
| `cleanip_scan.go` | 262 | Two-phase scan engine, TLS 1.3 probes, scoring, error tidying |
| `cleanipstore.go` | 184 | `CleanIP`, `CleanIPSet`, `CleanIPRepo`, `ScanJob`, `LoadFreshCleanIPs` |
| `rotation.go` | 141 | `PoolEntry`, `PoolRepo`, `Prober`, `TLSProber` |
| `rotation_pool.go` | 382 | `Pool`, `Check`, `Rotate` (self-healing) |
| `creds.go` | 320 | AES-256-GCM `Encryptor`, `CredentialStore`, key encode/decode |
| `memstore.go` | 155 | In-process implementation of all three repos |
| `gormstore.go` | 246 | GORM implementation + AutoMigrate of the 3 owned tables |
| `wizard.go` | 201 | `ProtocolPlan`, `WizardConfig`, `Step`, `Endpoint`, `WizardReport` |
| `wizard_run.go` | 379 | The 9-step `Run` orchestration |
| `wizard_plan.go` | 183 | Hostname planning, propagation polling, `FormatWizardReport` |
| `routes.go` | 499 | `Deps`, `RegisterRoutes`, status mapping, credential/zone/record handlers |
| `routes_ops.go` | 416 | Zone-settings, preflight, pool, clean-IP and provision handlers |
| **Tests** | | `cfmock_test.go`, `desecmock_test.go`, `testsupport_test.go`, `cloudflare_test.go`, `arvancloud_test.go`, `desec_provider_test.go`, `zone_test.go`, `naming_test.go`, `preflight_test.go`, `preflight_acme_test.go`, `cleanip_test.go`, `rotation_test.go`, `creds_test.go`, `registry_test.go`, `gormstore_test.go`, `routes_test.go`, `routes_ops_test.go`, `wizard_test.go`, `wizard_failures_test.go` |

### Other

- `cmd/forgectl/provision.go` (404) — the `provision` subcommand.
- `cmd/forgectl/provision_test.go` (424) — 15 tests including an offline
  end-to-end run of the whole command.
- `docs/DNS_WIZARD.md` (396) — full documentation.
- `third_party/WhiteDNS-Wizard/` — the reference clone (already gitignored via
  `/third_party/`).

**Not touched:** `internal/api/*`, the frontend, `go.mod`, `go.sum`, or any
other existing file. No new dependency; no `go mod tidy`. The Cloudflare,
ArvanCloud and deSEC clients are hand-rolled `net/http` against the documented
REST endpoints. Only stdlib + `github.com/gin-gonic/gin`, `gorm.io/gorm`,
`golang.org/x/net/publicsuffix` and `github.com/glebarez/sqlite` (test only) —
all already in `go.mod`.

---

## 3. Commands run and their real output

```
$ GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go version
go version go1.25.12 linux/amd64

$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go build ./internal/dns/... ./cmd/forgectl/...
(no output = success)

$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go vet ./internal/dns/... ./cmd/forgectl/...
(no output = success)

$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go test ./internal/dns/... ./cmd/forgectl/...
ok  	github.com/forgepanel/forgepanel/internal/dns	2.404s
ok  	github.com/forgepanel/forgepanel/cmd/forgectl	1.387s

$ GOFLAGS=-mod=mod GOTOOLCHAIN=auto /home/ubuntu/sdk/go124/bin/go test -race -count=3 ./internal/dns/... ./cmd/forgectl/...
ok  	github.com/forgepanel/forgepanel/internal/dns	13.155s
ok  	github.com/forgepanel/forgepanel/cmd/forgectl	23.575s

$ /home/ubuntu/sdk/go124/bin/gofmt -l internal/dns/ cmd/forgectl/provision*.go
(no output = clean)
```

Test counts: **186** passing tests/subtests in `internal/dns`, **15** in
`cmd/forgectl` for `provision`. No test touches the network — the resolver, the
ACME directory, the CT log and all three provider APIs are injectable and
pointed at `httptest` servers or a local TLS listener.

---

## 4. What is proved, and how

### Providers, against their real wire formats

Each mock replays the shapes the real API returns, envelope and all:

- **Cloudflare** — `{success, errors, messages, result, result_info}` with real
  numeric codes (`9109` unauthorized, `10000` auth error, `81053` duplicate
  record, `7003` bad route, `1003` bad zone id). Tested: user- **and**
  account-scoped token verify, wrong account id, disabled token, zone-list
  pagination (3 requests for 5 zones at page size 2), record CRUD, SRV via the
  `data` object, `SetProxied` preserving content, zone settings, 429 and 5xx
  classification, and an unreachable API.
- **ArvanCloud** — `{data, meta}` envelope, sub-names relative to the zone,
  polymorphic `value` (`[{ip}]` / `{host}` / `{text}` / SRV fields). Tested: all
  five value shapes decode, apex stored as `@`, the `Apikey ` prefix is added
  once whether or not the operator pasted it, the cloud flag maps to `Proxied`,
  and all five error statuses map to the right kind.
- **deSEC** — bare JSON RRsets keyed `(subname, type)` in presentation format.
  Tested: TXT round-trips quoted-on-disk/unquoted-in-API, CNAME gains and loses
  its trailing dot, SRV and MX parse from space-separated fields, the synthetic
  `subname/TYPE` record id, a 429 with `Retry-After: 1` is honoured then
  succeeds (asserted: exactly one 1s backoff), exhausted retries report
  `KindRateLimit`, and a proxied record is refused as `KindUnsupported`.

### Permission diagnostics

`TestCloudflarePermissionErrorsNameTheMissingScope` drives a 403/9109 at five
different endpoints and asserts the resulting `MissingScope` is exactly
`Zone → Zone → Read`, `Zone → DNS → Read`, `Zone → DNS → Edit`,
`Zone → Zone Settings → Edit` and `Zone → SSL and Certificates → Edit`
respectively — Cloudflare's own token-editor wording. The SSL case additionally
asserts the remediation names *both* required scopes.

`VerifyCredentials` does not stop at `/tokens/verify` (which only proves the
token is live): it also probes zone enumeration, so an under-scoped token fails
at step one rather than mid-provision.

### Parent-zone resolution and delegation

- `team.example.com` provisions through the `example.com` zone (asserted).
- The candidate chain stops at the public suffix: `example.co.uk` is proposed,
  `co.uk` never is.
- A deeper zone wins over its parent.
- **NS delegation** away from the zone is detected and the ACME consequence is
  spelled out verbatim — asserted to contain `will NOT be served`,
  `NXDOMAIN looking up TXT for _acme-challenge.…`, `remove the NS delegation`
  and the `HTTP-01` alternative.
- A child answering with the zone's *own* nameservers is correctly **not**
  flagged (that would false-alarm on every zone).

### ACME preflight

Six checks, each asserted for both verdict and remediation text. The
distinctions that actually matter are tested:

- NXDOMAIN vs SERVFAIL on `_acme-challenge` (the first is normal before
  issuance; the second names DNSSEC as the usual cause).
- NXDOMAIN vs an unreachable resolver on the hostname.
- A proxied record resolving to edge addresses is a **pass**, not a mismatch.
- NS mismatch remediation says `REGISTRAR` in capitals and names the target
  nameservers — this is the most-misunderstood failure in the whole flow.
- Rate-limit headroom: exhausted (50/week) fails, 5 duplicates fails, 47 warns,
  month-old certificates fall out of the window, and an **unreachable CT log
  only warns** — an outage at crt.sh must never block provisioning.
- A TLS-intercepting captive portal answering 200 with HTML is a warning that
  names "TLS-inspecting proxy", and does not fail the report.

### Clean-IP scanner — against a real TLS 1.3 listener

`TestScanTwoPhaseAgainstRealTLS13Listener` runs both phases against a genuine
listener pinned to TLS 1.3 and asserts 3/3 TCP, 3/3 TLS, `TLS13: true`, 2/2
probes per address, 0% loss, and a real (non-sentinel) score.

Also proved: phase one rejects unreachable addresses and explains a timeout in
censorship terms; **TCP passing while TLS fails** (a plain TCP listener that
never speaks TLS) is caught and explained as an SNI-based block; working
addresses rank ahead of blocked ones; `Keep` trims; and `ScanJob` shortfall
remediation is phase-specific — "no route to the CDN's ranges" vs "not actually
proxied at the provider".

Sampling: round-robins CIDRs (asserted: draws from both ranges), skips network
and broadcast (a `/30` yields exactly 2), and rejects IPv6 CIDRs and malformed
input. All 15 shipped Cloudflare ranges parse.

### Rotation pool

One failure degrades, three retire (asserted step by step); a recovered name
comes back and its failure count resets; ranking puts the fastest healthy entry
first and retired last; `Rotate` creates exactly the shortfall (2 replacements
for `MinHealthy: 3` with 1 alive), each with a provider record id and the
inherited proxy flag; `DeleteRetired` removes the burned record from DNS and
drops the entry; and both "no provider configured" and a provider permission
failure report the shortfall with actionable text instead of silently leaving
the pool short.

### Credentials at rest

AES-256-GCM round-trips; the same plaintext never produces the same ciphertext;
a wrong key and a single flipped byte both fail; the AAD names its purpose; and
the on-disk bytes are asserted **not** to contain the plaintext token — over
both `MemStore` and a real SQLite-backed `GormStore`. `NewCredentialStore`
refuses to exist without an encryptor (there is no plaintext fallback).
Listings and API responses are asserted never to echo secrets.

### Storage

`TestMemStoreMatchesTheGormContract` runs the same sequence against both
implementations so the test double cannot drift from the real store. Re-running
`NewGormStore` over the same database is proved non-destructive.

### HTTP layer

Every error kind is asserted to map onto the right status (400/401/403/404/409/
422/429/501/502), every error body is asserted to carry `remediation`, a
permission failure carries `missing_scope` through to the client, partial bulk
runs return **207** with both results and error, a stale clean-IP set returns
200 with `stale: true` rather than an error, and `RegisterRoutes` is proved to
mount under an arbitrary caller-supplied group (`/api/admin/dns/providers`).
Deps missing an encryptor or pool storage fail cleanly rather than panicking.

### End-to-end

`TestWizardEndToEnd` runs the full 9 steps against the mock provider, the fake
resolver and a real TLS listener, asserting: 2 records created, `ws` proxied,
`reality` **not** proxied, both endpoints proven by a real handshake, and the
edge landing on `ssl=strict`, `websockets=on`, `grpc=on`.

Also proved: re-running is a no-op (`unchanged`, still one record); a UDP
endpoint is not falsely claimed as proven; a bad credential stops after one step
with zero records created; a missing scope surfaces in the step detail; a
delegated subdomain warns but still writes records; propagation is polled until
the name appears and times out into a *warning*, not a failure; nothing
listening is a hard failure naming `forgectl service start` and the firewall;
IPv6 origins produce AAAA; colliding hostnames are rejected up front; and
`--skip-dns` still verifies and proves pre-existing hostnames.

`TestWizardScanSetsTheDialledAddress` proves the headline behaviour: after a
scan, a proxied endpoint's `Address` is a verified `104.16.0.x` edge IP while
its `Host` (sni/host) stays `ws-fra1.example.com`, and the direct endpoint keeps
dialling its hostname.

`TestProvisionEndToEndNonInteractive` drives the actual CLI with
`--api-base` pointed at a mock, asserts a successful run with no prompts, and
parses the `--out` JSON report back into a `WizardReport` to check both
endpoints and the per-protocol proxy decisions.

---

## 5. Bugs this work found and fixed

Three real defects surfaced from tests, not from review:

1. **A proxied record was rewritten on every run.** Cloudflare forces a proxied
   record's TTL to `1` ("automatic") and rejects a custom value, so comparing
   TTL made every re-run an update. `recordEquivalent` now ignores TTL for
   proxied records. (`provider.go`)
2. **A CNAME could point at an IP literal.** `203.0.113.1` satisfies the DNS
   label rules, so `ValidateFQDN` accepted it and the provider rejected it later
   with a far vaguer message. Added `validateHostnameTarget`, applied to CNAME,
   NS, MX and SRV targets. (`dns.go`)
3. **IP sampling gave up after one collision.** A single duplicate draw ended
   the whole sample, so a `/30` returned 1 address instead of 2. Small ranges are
   now enumerated and shuffled; large ones retry. (`cleanip_sample.go`)

A fourth, caught by the help test: a custom `flag.Usage` suppresses
`PrintDefaults`, so `--help` printed the prose and no flag list.

---

## 6. Scope notes

- **Fully implemented:** Cloudflare (records, proxying, zone settings,
  scope-precise diagnostics), ArvanCloud (records + cloud flag), deSEC (records,
  RRset semantics, TTL clamping).
- **Registry entries returning a typed `KindNotImplemented`:** digitalocean,
  gcore, namecheap, godaddy, vultr, hetzner — as permitted for the extra
  providers. Each names its own token URL and points at `--skip-dns` as the
  manual path. `TestUnimplementedProvidersReturnTypedError` asserts all six.
- **Not built (out of scope, worth flagging):** the wizard checks ACME
  *readiness* but does not itself issue certificates — that is
  `internal/cert`/`forgectl cert`, which already exists. The `traffic-proof`
  step proves a TLS endpoint answers; it does not exchange protocol-level
  traffic, which is §4's connectivity harness. UDP endpoints are explicitly
  reported as unprovable by this mechanism rather than silently passed.
