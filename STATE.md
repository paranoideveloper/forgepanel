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
- [ ] BUG-3: Domains section; global + per-inbound + per-node domain; cascade to SNI/host/cert/link/sub; one-click ACME; no-domain REALITY guidance; never show plaintext as secure.
- [ ] §3: validation & proof engine (3 layers, live Verify, diagnostics catalogue, Panel Doctor).
- [ ] §5: Cloudflare-first DNS automation wizard (+ 8 providers), clean-IP scanner, `forgectl provision`.
- [ ] §6: ForgeEdge Cloudflare Worker (unified model, OAuth deploy, WARP, chain, fragment, routing, backend mode).
- [ ] §7: `docs/E2E_REPORT.md` with real output for all 13 steps.
- [ ] `make check` clean; coverage ≥75% overall, ≥90% for protocol + forgedns.
- [ ] Zero TODO/FIXME outside `third_party/`.
- [ ] `CHANGELOG.md` + `RELEASE_NOTES.md` updated; tag (next after v1.3.2 — NOT v1.1.0).

## Log

- `b983885` fix(sub): sing-box duplicate "proxy" tag — reserved selector/direct tags. Proven by real core.
- `41bd4b5` feat(sub): xray + shadowrocket formats + real Subscription-Userinfo. Proven by `xray run -test`.
