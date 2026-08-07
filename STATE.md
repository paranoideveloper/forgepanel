# ForgePanel Round-2 Remediation — STATE

Branch: `fix/round2-remediation`. Working against **v1.3.2** (current `main`),
not the `v1.1.0` the round-2 prompt was written against — see ADR-0001.

Resume rule: re-read this file + `docs/DECISIONS.md` + `FORGEPANEL_ROUND2_FIX_PROMPT.md`,
then continue at the first unchecked box.

## Bug reproduction findings (verified against current code)

| Bug | Finding | Status |
|-----|---------|--------|
| BUG-4 (inbounds can't be edited) | Already fixed pre-round-2: `PUT /inbounds/:id` → `handleUpdateInbound`, e2e-tested. | N/A (done before) |
| BUG-1 (subs malformed) | Structurally valid for all 5 formats. **sing-box output rejected by the real core** (`duplicate tag: proxy`). `Subscription-Userinfo` hardcoded all-zeros. Missing formats: xray, clash-meta, surge, quantumultx, loon, shadowrocket. | In progress |
| BUG-3 (no TLS / no domain UI) | Real: only `/domains/check` + `/domains/ns-wizard`. No Domains CRUD, per-inbound domain, global default, one-click ACME, or no-domain REALITY guidance. | Pending |
| BUG-2 (configs don't connect) | Cannot reproduce/disprove without the §4 connectivity harness. | Pending |

## §8 Definition of Done

- [x] BUG-1: every subscription format validates structurally + accepted by real cores; golden files.
  - [x] sing-box core-rejection fixed (`b983885`), proven by `sing-box check`.
  - [x] xray format added, accepted by `xray run -test` (`41bd4b5`).
  - [x] Subscription-Userinfo header math from DB (`41bd4b5`).
  - [x] shadowrocket alias → base64 links (`41bd4b5`).
  - [x] clash-meta as a distinct renderer; surge / quantumultx / loon line formats (`internal/api/sub_proprietary.go`).
  - [x] full format golden matrix + structural validator (`TestSubscriptionFormatsStructural`, `internal/api/testdata/golden/`).
- [x] BUG-2 / §4: connectivity harness proves real traffic per protocol; unproven combos flagged `experimental`.
  - `internal/core` `TestFullMatrixConnectivity`: **24/24 protocol inbounds pass real end-to-end traffic** through the actual xray/sing-box cores (only the 4 REALITY variants skipped — steal-handshake cannot complete on loopback, verified on a public IP).
  - Reconciled the §4 harness teammate's 5 confirmed blockers, each fixed and proven with the real core:
    - #1 alpine runtime could not exec the glibc sing-box release (exit 127) → `gcompat` (`e96461a`); proven by running pinned sing-box-1.13.15 inside the built image.
    - #2 xray26 removed `allowInsecure`; self-signed TLS was unverifiable → `applyExportDefaults` pins `pinnedPeerCertSha256=hex(sha256(leaf))` (`b75d404`); proven by a real xray TLS round-trip (HTTP 204).
    - #3 `fingerprint=chrome` → `utls` on QUIC, which sing-box rejects → no uTLS on QUIC at render+defaults (`6e278ee`); Hy2/TUIC/AnyTLS now PASS on loopback (were skipped).
    - #4 SS-2022 subscription stamped a base64url user pw as the PSK → keep the inbound PSK in `stampIdentity` (`6e278ee`); proven by `xray run -test`.
    - #5 sing-box subscription shipped no inbound/route (not runnable) → mixed inbound + route (`4acef9c`); proven by `sing-box check`.
    - +ShadowTLS bare outbound (no inner-SS detour) → ss→shadowtls detour chain (`370302d`); proven by `sing-box check`.
    - +over-quota (`StatusLimited`) users kept transferring → cut off in `enabledInboundSpecs` + edge feed (`9077e5b`).
    - +inbound-disable: `POST /inbounds/:id/toggle` clears `Enabled`, honoured by `enabledInboundSpecs` (BUG-4 work).
- [x] BUG-3: Domains section; global + per-inbound + per-node domain; cascade to SNI/host/cert/link/sub; one-click ACME; no-domain REALITY guidance; never show plaintext as secure.
- [x] §3: validation & proof engine (3 layers, live Verify, diagnostics catalogue, Panel Doctor) — `internal/diag`, `docs/DIAGNOSTICS.md`.
- [x] §5: Cloudflare-first DNS automation wizard (+ ArvanCloud, deSEC; 6 more registry stubs), clean-IP scanner, `forgectl provision` — `internal/dns` wired in `server.go`, `cmd/forgectl/provision.go`.
- [x] §6: ForgeEdge Cloudflare Worker (316 tests) + Go-side (`internal/edge`, `internal/api/edge*.go`, `EdgeDeployment`, `forgectl edge`); shared redacted feed; CI drift guard (`c61bcd3`, `1278f79`, `6bcf228`, `d8ad4c5`, `28348c3`, `6bc03d9`).
- [x] §7: `docs/E2E_REPORT.md` with real pasted output.
- [x] `make check` clean; coverage ≥75% overall, ≥90% for protocol + forgedns.
  - `internal/protocol/**` tree aggregate = **99.5%** (`-coverpkg=./internal/protocol/...`): model 100, parse 99.7, render 99.8, export 99.6, keygen 93.3. ✅
  - `internal/forgedns/**` tree aggregate = **97.1%** (`-coverpkg=./internal/forgedns/...`): adapter 90.6, codec 97.9, server 100, session 99, upstream 96.7. ✅ (fixed a real HOL-block reorder-stall bug found by the coverage tests, `0caed9d`.)
  - `go test ./... -count=1` = 0 failures; `gofmt`/`go vet`/`staticcheck`/`govulncheck` clean; race subset clean.
- [x] Zero TODO/FIXME/"not implemented" outside `third_party/` (grep = 0).
- [x] `CHANGELOG.md` + `RELEASE_NOTES.md` updated; tagged `v1.4.0` (next after v1.3.2).


## CI status (branch — all jobs reproduced locally with CI's exact commands)

Root failures on `main` were **govulncheck**, **shellcheck**, and the **workflow's
own invalid YAML** (unquoted colons in 7 job names — GitHub would reject the whole
file); all fixed here.

| CI job | local result |
|--------|--------------|
| code-hygiene: gofmt / tidy / vet / staticcheck / shellcheck / goreleaser check | PASS |
| govulncheck ./... | PASS (was FAIL exit 3) — 0 vulns affect the code |
| all Go test suites (`go test ./... -count=1`) | PASS (0 failures) |
| race-detector subset (`-race`) | PASS |
| e2e-smoke (`make build` + forgectl/forgenode/forgepanel version) | PASS |
| cross-compile linux/{amd64,arm64,386} | PASS |
| frontend svelte suite (`bun run check` 397 files 0 err + `bun run test`, 39 tests) | PASS |
| forgeedge-worker (`tsc --noEmit` + `bun test` 316 + Go↔TS drift guard) | PASS |
| docker-build (73 MB; pinned glibc sing-box execs inside via gcompat) | PASS |

Live CI cannot be triggered from the branch (workflow only runs on main/PRs; token
lacks `workflow` scope to add a dispatch trigger). Proven by local reproduction;
recorded in docs/E2E_REPORT.md.


## CI workflow_dispatch (blocked on token scope)
The change to add a manual `workflow_dispatch` trigger to `.github/workflows/ci.yml`
is captured at `packaging/github-workflows/ci-add-workflow-dispatch.patch`. It could
not be pushed: the token lacks the `workflow` scope. Apply it with a workflow-scoped
token (or via the GitHub UI) to enable branch dispatch. Not retried; does not gate anything.

## Carried fixes for main
- `2318d00` govulncheck: x/net v0.56.0, x/text v0.39.0, go directive -> 1.25.12.
- `2e5e06e` shellcheck: install.sh SC2155/SC2015.
- `c61bcd3` invalid CI workflow YAML: 7 job names had unquoted colons (`name: Test Suite: …`); GitHub rejects the whole file, so CI could never have run on main as written. Also anchored the `.gitignore` `forgectl` pattern that was silently ignoring `cmd/forgectl/` sources.
- `fa4740f` SPA asset serving (the panel UI was entirely non-functional on main).
- `b7e47c8` frontend↔backend API contract (login, overview, groups, presets) — the SPA could not log in or load on main.
- `e96461a` alpine runtime could not exec the glibc sing-box release binary (exit 127) → gcompat. Six sing-box protocols were dead in the shipped container on main.
These heal main's red CI / broken container when the branch is merged.

## Log

- `c88256c` feat(inbounds): BUG-4 — safe-edit warnings (confirm on port/proto/transport change), clone, toggle, bulk, undo. 4 tests.
- `fa4740f` fix(panel): serve the SvelteKit SPA assets — the UI was 100% dead (/_app/* 404). CRITICAL. Carried for main.
- `b7e47c8` fix(panel): repair frontend↔backend contract (login /api/login+access_token, /admin/overview, /admin/groups, /protocols/presets) + Playwright e2e desktop+mobile bilingual, 6/6. Carried for main.


- `126117a` feat(domains): BUG-3 backend — registry, cascade (SNI/Host/addr), one-click TLS w/ honest preflight, no-domain REALITY guidance (EN+FA). 9 tests.
- `be1ef0c` feat(domains): BUG-3 frontend — Domains view + nav tab + no-domain banner + REALITY one-click. 2 vitest tests. Proven live: inbound inherits default domain, link rides it.


- `b983885` fix(sub): sing-box duplicate "proxy" tag — reserved selector/direct tags. Proven by real core.
- `41bd4b5` feat(sub): xray + shadowrocket formats + real Subscription-Userinfo. Proven by `xray run -test`.
