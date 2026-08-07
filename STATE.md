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

- [ ] BUG-1: every subscription format validates structurally + accepted by real cores; golden files.
  - [x] sing-box core-rejection fixed (`b983885`), proven by `sing-box check`.
  - [x] xray format added, accepted by `xray run -test` (`41bd4b5`).
  - [x] Subscription-Userinfo header math from DB (`41bd4b5`).
  - [x] shadowrocket alias → base64 links (`41bd4b5`).
  - [ ] clash-meta as a distinct renderer.
  - [ ] surge / quantumultx / loon line formats.
  - [ ] full protocol×transport×security×format golden matrix + structural validator.
- [ ] BUG-2 / §4: connectivity harness proves real traffic per protocol; unproven combos flagged `experimental`.
- [x] BUG-3: Domains section; global + per-inbound + per-node domain; cascade to SNI/host/cert/link/sub; one-click ACME; no-domain REALITY guidance; never show plaintext as secure.
- [ ] §3: validation & proof engine (3 layers, live Verify, diagnostics catalogue, Panel Doctor).
- [ ] §5: Cloudflare-first DNS automation wizard (+ 8 providers), clean-IP scanner, `forgectl provision`.
- [ ] §6: ForgeEdge Cloudflare Worker (unified model, OAuth deploy, WARP, chain, fragment, routing, backend mode).
- [ ] §7: `docs/E2E_REPORT.md` with real output for all 13 steps.
- [ ] `make check` clean; coverage ≥75% overall, ≥90% for protocol + forgedns.
- [ ] Zero TODO/FIXME outside `third_party/`.
- [ ] `CHANGELOG.md` + `RELEASE_NOTES.md` updated; tag (next after v1.3.2 — NOT v1.1.0).


## CI status (branch — all jobs reproduced locally with CI's exact commands)

Root failures on `main` were **govulncheck** and **shellcheck**; both fixed here.

| CI job | local result |
|--------|--------------|
| code-hygiene: gofmt / tidy / vet / staticcheck / shellcheck / goreleaser check | PASS |
| govulncheck ./... | PASS (was FAIL exit 3) |
| all 7 Go test suites (`-shuffle=on -count=1`) | PASS |
| race-detector subset | PASS |
| e2e-smoke (`make build` + forgectl version) | PASS |
| cross-compile linux/{amd64,arm64,386} | PASS |
| frontend svelte suite (`bun run check` + `bun run test --coverage`, 37 tests, 90.9%) | PASS |
| docker-build | PASS |

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
These heal main's red CI when the branch is merged.

## Log

- `126117a` feat(domains): BUG-3 backend — registry, cascade (SNI/Host/addr), one-click TLS w/ honest preflight, no-domain REALITY guidance (EN+FA). 9 tests.
- `be1ef0c` feat(domains): BUG-3 frontend — Domains view + nav tab + no-domain banner + REALITY one-click. 2 vitest tests. Proven live: inbound inherits default domain, link rides it.


- `b983885` fix(sub): sing-box duplicate "proxy" tag — reserved selector/direct tags. Proven by real core.
- `41bd4b5` feat(sub): xray + shadowrocket formats + real Subscription-Userinfo. Proven by `xray run -test`.
