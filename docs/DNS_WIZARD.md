# Domain & DNS Automation Wizard (§5)

The wizard takes a bare domain and a provider credential and leaves behind a
verified, TLS-enabled, traffic-proven inbound set — no dashboard visits, no
prompts. It lives in `internal/dns/` and is reachable three ways: the Go API,
the HTTP API (`dns.RegisterRoutes`), and `forgectl provision`.

The design rule throughout: **every failure names the exact fix**. A provider
returning "Unauthorized to access requested resource" is useless to an operator;
the wizard turns that into "add `Zone → DNS → Edit` at
https://dash.cloudflare.com/profile/api-tokens and include this zone in Zone
Resources".

---

## What a run does

```
verify credential          token is live AND holds the scopes we need
      ↓
resolve owning zone        node.example.com → the example.com zone
      ↓                    + NS-delegation detection with the ACME consequence
plan hostnames             {proto}-{node}-{rand}.example.com, one per inbound
      ↓
create records             A/AAAA, proxied per protocol, idempotent upsert
      ↓
configure the edge         Full (strict) origin pull, TLS 1.2 floor,
      ↓                    WebSockets on, gRPC on
wait for propagation       poll public DNS until the names resolve
      ↓
ACME preflight             resolution, delegation, challenge path,
      ↓                    CA reachability, rate-limit headroom
clean-IP scan              two-phase TCP + TLS 1.3 sweep of the CDN ranges
      ↓
traffic proof              dial every endpoint for real
```

A run returns a `WizardReport` even when steps fail. `report.OK` is the verdict;
each `Step` carries `status`, `detail` and — when it is not `ok` — `remediation`.

---

## Providers

| Provider | Records | Proxy (orange cloud) | Edge settings | Notes |
|---|---|---|---|---|
| **cloudflare** | full | yes | yes | Deepest support. Scope-precise permission errors. |
| **arvancloud** | full | yes (`cloud` flag) | no | Reachable from inside Iran when Cloudflare's API is not. |
| **desec** | full | n/a (no CDN) | no | Free, DNSSEC-signed. Right choice for REALITY / direct-TLS. |
| digitalocean, gcore, namecheap, godaddy, vultr, hetzner | — | — | — | Registry entries only. Their factory returns a typed `KindNotImplemented` error naming where to create the records by hand. |

`GET /dns/providers` returns the whole registry including each provider's
credential field list, so a UI renders the credential form without hard-coding
provider knowledge.

### Adding a provider

Implement `dns.Provider`, optionally `dns.ProxyController` and
`dns.ZoneSettingsController`, then `dns.Register(ProviderInfo{...}, factory)` in
an `init()`. `TestRegistryCapabilityFlagsMatchTheCode` asserts the registry's
capability flags match what the type actually implements, so a mismatch fails
the build rather than misleading the UI.

---

## Cloudflare token scopes

The wizard needs four permissions. The token editor's exact wording is used in
every error message so the operator can find the checkbox:

| Scope | Needed for |
|---|---|
| `Zone → Zone → Read` | enumerating zones — nothing works without it |
| `Zone → DNS → Edit` | creating and updating records (implies read) |
| `Zone → Zone Settings → Edit` | Always Use HTTPS, min TLS, TLS 1.3, gRPC, WebSockets |
| `Zone → SSL and Certificates → Edit` | setting the SSL mode to Full (strict) |

Zone Resources must include the domain (or "All zones from an account").

`VerifyCredentials` does not stop at the `/tokens/verify` endpoint — that only
proves the token is *live*, not that it can do anything. It also probes zone
enumeration, so an under-scoped token fails at step one with a precise message
instead of three steps later.

---

## Parent-zone resolution and delegation

Provisioning `team.example.com` works through the `example.com` zone.
`ResolveZone` walks the parent chain longest-first, stopping at the public
suffix (`example.co.uk` is a candidate, `co.uk` never is), and prefers the
deepest zone that exists.

It also detects **NS delegation** between the zone apex and the target — the
single most common reason a perfectly correct record produces a failing
certificate. When `team.example.com` has its own NS records pointing away from
the zone, the resolution reports:

> `team.example.com` is delegated away from zone `example.com` to
> `ns1.otherdns.net`. Records the panel writes into `example.com` will NOT be
> served for `ws.team.example.com`, so a DNS-01 challenge published in
> `example.com` can never be seen and issuance will fail with "NXDOMAIN looking
> up TXT for `_acme-challenge.ws.team.example.com`". Either remove the NS
> delegation at `team.example.com`, or add `team.example.com` as its own zone at
> the provider and use a credential scoped to it, or switch that host to an
> HTTP-01 challenge on port 80.

A child answering with the zone's *own* nameservers is the zone serving itself,
not a delegation, and is correctly ignored.

---

## Naming templates

`NameTemplate` renders subdomain labels. Default: `{proto}-{node}-{rand}`.

| Placeholder | Value |
|---|---|
| `{proto}` | inbound protocol/transport (`ws`, `reality`, `hy2`) |
| `{node}` | server name; `forgectl` defaults it to the host's short hostname |
| `{region}` | optional geographic tag |
| `{seq}` | 1-based index within a bulk run |
| `{date}` | UTC `YYYYMMDD` |
| `{rand}` / `{rand:N}` | 6 (or N) random characters |

An unknown placeholder is an **error**, not a literal — a typo'd `{nodee}` would
otherwise become a real DNS label containing braces and fail much later at the
provider.

The random alphabet is `bcdfghjkmnpqrstvwxz23456789`: no vowels (a generated
label can never spell a filterable word) and no look-alike characters (`0/O`,
`1/l/I`), because these names get read aloud and typed from QR codes.

Rendered labels are sanitised to legal DNS (lower-case, alphanumerics and
hyphens, no doubled or edge hyphens) and rejected if they exceed 63 characters.

**Bulk creation** (`BulkCreate`, `POST /dns/records/bulk`) generates N unique
names and upserts a record for each. It does not abort on the first failure — a
rate limit partway through a 50-record batch still leaves you the 30 that landed
— except on an auth or permission failure, which would just repeat 50 times.

---

## Idempotence

`EnsureRecord` upserts by `(type, name)` and reports `created` / `updated` /
`unchanged`. Re-running the wizard changes nothing.

Two provider quirks are handled so the upsert does not thrash:

- **Proxied records**: Cloudflare serves them on its own TTL (reports `1`,
  "automatic") and rejects a custom value, so the TTL field carries no
  information and is not compared for a proxied record.
- **deSEC**: clamps TTLs up to the zone minimum (3600 on free accounts), so
  "the provider gave us at least what we asked for" counts as equal. A rejected
  create is automatically retried at the domain minimum.

---

## ACME preflight

`Preflight.Run` returns a `PreflightReport` of six checks. `warn` means issuance
will probably work; `fail` means it cannot.

| Check | What it proves |
|---|---|
| `zone-active` | the provider considers the zone live |
| `public-resolution` | the name resolves publicly, and to the right address |
| `ns-delegation` | public NS matches the provider's assignment; no delegation away |
| `challenge-path` | dns-01: `_acme-challenge.<domain>` is in an answering zone. http-01: the path is reachable |
| `acme-directory` | the CA's directory answers from *this host* and is not intercepted |
| `rate-limit-headroom` | certificates issued for the registrable domain in the last 7 days, against Let's Encrypt's 50/week and 5 duplicates/week |

Distinctions that matter and are made:

- **NXDOMAIN vs SERVFAIL** on the challenge name. NXDOMAIN is the *correct*
  state before issuance. SERVFAIL means a published TXT would never be seen —
  usually a broken DNSSEC chain, and the remediation says so.
- **NXDOMAIN vs unreachable resolver** on the hostname. "Create the record"
  and "your host cannot reach 1.1.1.1" are different problems.
- **Proxied mismatch**. A record behind a CDN deliberately does not resolve to
  the origin; reporting that as a failure would be wrong.
- **Unreachable CT log** is a warning, never a failure. An outage at crt.sh must
  not block provisioning.

Every network dependency (`Resolver`, `HTTP`, `ACMEDirectoryURL`, `CertLogURL`,
`Now`) is injectable. Set `CertLogURL: "-"` to skip the headroom lookup.

---

## Clean-IP scanner

Two phases, because a blocked range fails at connect in milliseconds and the
expensive handshake budget should only be spent on addresses that could work:

1. **TCP connect** across the whole sample.
2. **Repeated TLS 1.3 handshakes** against the survivors — `Probes` per address,
   which is what makes the loss percentage meaningful.

TLS is pinned to 1.3 on *both* bounds deliberately: an edge that only offers 1.2
is not the modern anycast front a client config assumes, and a downgrading
middlebox shows up here rather than as a mystery later.

Results rank by `avgRTT × (1 + 4 × loss/100)` — loss is weighted heavily because
a lossy edge address produces exactly the intermittent-disconnect complaint that
is hardest to diagnose.

**The output is the `address` field of a client config while `sni` and `host`
stay on the domain.** That is the entire point.

Failure modes get phase-specific advice:

- *nothing connected* → no route to the CDN ranges from this host, or the whole
  range is blocked from this vantage point.
- *TCP passed, TLS did not* → the hostname is not actually proxied yet, the edge
  has no certificate for it, or something is resetting on the SNI.

Sampling round-robins the CIDRs so one enormous `/13` does not swamp the sample,
skips network/broadcast addresses, and enumerates-and-shuffles ranges small
enough to exhaust rather than colliding on random draws.

A stored set carries the SNI it was verified against and its timestamp;
`LoadFreshCleanIPs` refuses to hand back a set older than the caller's freshness
window, because addresses clean last month are routinely blocked today.

---

## Rotation pool

A health-checked, self-healing set of domains. Clients are handed `active`
entries; the pool retires names that stop working and mints fresh subdomains to
replace them.

- `Check` probes every entry (default: a real TLS handshake — a name that
  resolves but whose edge refuses the SNI is exactly what a pool routes around).
- One failure **degrades**; `FailureThreshold` consecutive failures (default 3)
  **retires**. A single blip must not burn a name.
- A passing check resets the failure count, so a transient outage does not
  permanently shrink the pool.
- `Rotate` health-checks, optionally deletes retired records from DNS, then
  creates fresh subdomains until `MinHealthy` usable entries exist again.
- With no provider configured, the shortfall is reported plainly rather than
  silently left short.

---

## Credentials at rest

AES-256-GCM, with the nonce prepended and an AAD binding the blob to this
package. There is deliberately **no plaintext fallback**: `NewCredentialStore`
refuses to exist without an `Encryptor`.

The panel supplies the key, so this package never decides where a master key
lives. `NewAESGCM(key)` for raw key bytes, `NewAESGCMFromPassphrase(secret)` to
derive one from the panel master key string.

`CredentialRecord` keeps provider/label/timestamps as plaintext metadata so the
UI lists credentials without decrypting anything; `List()` always nils the
secret. A wrong key produces "the panel master key changed" rather than a raw
cipher error.

`LastVerifiedAt` / `LastVerifyError` are stamped by `RecordVerification`, so a
token that expired last week is visible in the list instead of discovered
mid-provision.

---

## Storage

Three tables, owned entirely by this package and migrated by
`dns.NewGormStore(db)` — nothing in `internal/store` has to change:

- `dns_credentials`
- `dns_pool_entries`
- `dns_clean_ip_sets`

`dns.NewMemStore()` implements the same three interfaces for tests and for
`forgectl provision`, which has no panel database to talk to.

---

## HTTP API

`dns.RegisterRoutes(rg gin.IRouter, deps dns.Deps)` mounts under whatever group
the caller passes, so the panel decides the prefix and the auth middleware.

```
GET    /dns/providers
GET    /dns/credentials
POST   /dns/credentials              {provider,label,data{},verify}
DELETE /dns/credentials/:id
POST   /dns/credentials/:id/verify
GET    /dns/zones?credential=
POST   /dns/zones/resolve            {credential,domain}
GET    /dns/records?credential=&zone=&type=&name=
POST   /dns/records                  {credential,zone,record}
DELETE /dns/records?credential=&zone=&id=  (or &name=&type=)
POST   /dns/records/bulk             {credential,zone,domain,template,count,…}
POST   /dns/records/proxy            {credential,zone,record_id,proxied}
GET    /dns/zone-settings?credential=&zone=
POST   /dns/zone-settings            {credential,zone,recommended|settings}
POST   /dns/preflight                {domain,expect_ip,challenge,credential?}
GET    /dns/pool/:name
POST   /dns/pool/:name/entries
DELETE /dns/pool/:name/entries?domain=
POST   /dns/pool/:name/check
POST   /dns/pool/:name/rotate
GET    /dns/cleanip
GET    /dns/cleanip/:name?max_age=
POST   /dns/cleanip/scan             {name,sni,port,cidrs,samples,probes,keep}
POST   /dns/provision                the whole wizard
```

### Error contract

Every error body is `{error, kind, provider, op, remediation, missing_scope?}`.
`kind` maps onto the status so a frontend reacts without string-matching:

| kind | status |
|---|---|
| `validation` | 400 |
| `auth` | 401 |
| `permission` | 403 (with `missing_scope`) |
| `not_found` | 404 |
| `conflict` | 409 |
| `preflight` | 422 |
| `rate_limit` | 429 |
| `unsupported`, `not_implemented` | 501 |
| `network` | 502 |

Partial successes return **207 Multi-Status** with both the results that landed
and the error — a bulk run that hits a rate limit at record 30 must not discard
the first 29.

---

## `forgectl provision`

```
forgectl provision --domain example.com --cf-token $CF_API_TOKEN --node fra1 --scan --json
forgectl provision --domain example.com --provider desec --desec-token $DESEC_TOKEN
forgectl provision --list-zones --cf-token $CF_API_TOKEN
```

Zero interactive prompts anywhere in this path — it is meant to run from an
installer, a CI job or a cron entry as readily as from a shell. Credentials come
from flags first, then `CF_API_TOKEN` / `CF_ACCOUNT_ID` / `ARVAN_API_KEY` /
`DESEC_TOKEN`.

Key flags:

| Flag | Effect |
|---|---|
| `--ip auto` (default) | detects this host's public address |
| `--protocols` | `proto[:port][:proxied\|direct][:udp]`, comma-separated |
| `--template` | naming template (default `{proto}-{node}-{rand}`) |
| `--skip-dns` | verify and prove hostnames that already exist — the path for a provider with no backend |
| `--scan` | run the clean-IP scan and use the winner as the dialled address |
| `--challenge` | `dns-01` (default) or `http-01` |
| `--propagation-wait` | `0` disables the wait |
| `--api-base` | redirect the provider's API root (proxy, private endpoint, testing) |
| `--json` / `--out` | full report as JSON, to stdout and/or a file |

A run with failed steps exits non-zero after printing the report.

---

## Default protocol plan

The proxy decision is per-protocol because it is not a preference:

| Protocol | Port | Proxied | Why |
|---|---|---|---|
| `ws`, `xhttp`, `grpc` | 443 | **yes** | a CDN in front is the point of that transport |
| `reality`, `vision` | 443 / 8443 | **no** | the edge terminates TLS and destroys the handshake |
| `hy2` | 8443 | **no** | UDP; also not provable by a TCP handshake, and the report says so rather than reporting a false failure |

---

## Testing

```bash
GOFLAGS=-mod=mod GOTOOLCHAIN=auto go test ./internal/dns/... ./cmd/forgectl/...
```

Every provider is exercised against an httptest server replaying its real wire
format — Cloudflare's `{success, errors, messages, result, result_info}`
envelope with its actual numeric error codes, ArvanCloud's `{data, meta}` with
sub-names and polymorphic value objects, deSEC's bare JSON RRsets in
presentation format with a `Retry-After` 429.

The scanner, the prober and the wizard's traffic proof run against a **real
TLS 1.3 listener**, not a stub — the handshake genuinely completes.

No test touches the network: the resolver, the ACME directory, the CT log and
every provider API are injectable and pointed at local servers.
