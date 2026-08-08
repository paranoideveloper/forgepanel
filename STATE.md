# ForgePanel Round-2 Remediation — STATE

Branch: `fix/round2-remediation`. Working against **v1.3.2** (current `main`),
not the `v1.1.0` the round-2 prompt was written against — see ADR-0001.

## v1.7.2 — Honest status + ForgeDNS multi-domain (parity batch 5)

- **Verify honesty**: diag.Result.Unprovable; loopbackUnprovable() = REALITY +
  UDP protos (tuic/hy2/wireguard/amneziawg/brook) → Unprovable (not Pass:false).
  Frontend renders neutral "— n/a" not red ✗. Tests updated.
- **Firewall honesty**: firewall.ufwBlocksByDefault() parses `ufw status verbose`
  Default incoming; Reachability/IsReachableLocally return true when default=allow,
  so working ports aren't falsely flagged 🔥.
- **ForgeDNS multi-domain**: create form has extra-domains input → domains[] in the
  create body (backend already stored Zone + Domains → DOMAIN array). Research
  confirmed CottenDNS/MasterDNS/StormDNS all take a DOMAIN array + server generates
  encrypt_key.txt (v1.5.7 read-back is the right model).
- **Transport labels**: WG/AWG→udp, hy2/tuic→udp/quic (were showing tcp).
STILL OPEN (big/queued): DNS key for cotten/storm needs LIVE diagnosis if still
wrong on a FRESH zone (read-back deployed); **CF Worker free-config generator**
(BPB/Nova/patterniha-style — huge new subsystem); **Amnezia config generator**
(darknessshade style). v1.7.1 shipped GHCR prebuilt image (docker pull works on
the user's censored build network; confirmed pull + boot).

## v1.7.0 — Setup Wizard + UX fixes (parity batch 4)

- **SetupWizardView** (sidebar ✨): 4-step guided onboarding (domain/TLS →
  reality-quickstart inbound → create user + auto-assign all inbounds → share
  QR/link). Registered in +page.svelte viewLoaders. e2e wizard.spec.ts (desktop+
  mobile) verified end-to-end incl. the emitted sub carrying vless://+reality.
- **Node 404 fix**: added `/api/node/install.sh` alias (UI hands that path out;
  script was only at `/node-install.sh`).
- **Health matrix fix**: SystemHealthView read name/healthy/detail; API returns
  label/state/summary — fixed rendering + HealthDetail type + test mock.
- **Mobile**: InboundsView table in `.table-scroll` (min-width 720, overflow-x);
  SystemHealthView media query stacks grids/rows; firewall badge tooltip clarified.
- **Package hardening**: nfpms `dependencies: [ca-certificates]` + per-format
  recommends; postinstall.sh opens ufw/firewalld for panel/80/443/53.
Gotchas: e2e default port 24700 is taken on the France box — run FP_E2E_PORT=34700;
`pkill -f forgepanel-test` kills the running shell, use `pkill -x forgepanel-test`.
Also v1.6.3 shipped the resilient Docker build (apk mirror fallback) — but the
user's server can't reach ANY Alpine mirror, so the .deb is their path.

## v1.6.2 — Subscription landing page (parity batch 3)

Browser-facing `/sub/:token` landing page (`internal/api/subpage.go`): usage/expiry
summary + per-client Import deep-links (clash://, sing-box://, hiddify://) + Copy
buttons for Clash/sing-box/Hiddify/v2rayNG/Xray/Base64. Gated by
`isBrowserSubRequest` (browser UA + text/html Accept + no client token); `?raw=1`
opts out. Verified: Go tests (browser gets HTML, clients don't, raw opts out) +
screenshot. Remaining parity: node-naming templates, WARP, Farsi i18n, chain
proxy, clean-IP surfacing, Telegram control.

## v1.6.1 — Xray fragment + subscription-settings UI (parity batch 2)

- **Xray TLS Fragment** (routing.Fragment): dialerProxy→freedom fragment outbound
  splits the TLS hello; `?fragment=1` + tuning params or operator default. VERIFIED
  by real `xray run -test`.
- **Subscription defaults UI**: card in UsersView (routing preset dropdown +
  fragment toggle) → GET/POST /admin/settings/subscription (settings
  sub_routing_preset + sub_fragment_default). /sub applies the fragment default
  when the query omits it. e2e subscription.spec.ts verifies persist + /sub honours
  (desktop+mobile, against the built binary).
- **install.sh shipped as a release asset** (goreleaser extra_files + before hook
  for the .sha256) — the documented `curl install.sh` flow 404'd before.
Remaining parity: node-naming templates, WARP configs, Farsi i18n, chain proxy,
subscription landing page, clean-IP surfacing, Telegram control.

## v1.6.0 — Self-provisioning + routing presets (BPB/Nova parity, batch 1)

Rasoul wants ForgePanel to have every option BPB-Worker-Panel / Nova-Proxy have
(see memory reference_forgepanel_feature_parity) and the install to "do all the
work". Batch 1:
- **Installer opens the firewall** (`open_firewall` in install.sh): panel port +
  80/443/53 across ufw/firewalld/iptables, best-effort, after health check.
- **Dynamic `:80` ACME helper** (`Server.StartACMEHelper`/`StopACMEHelper`): TLS
  comes up on domain-save with no restart; main.go + handlePanelAddressUpdate wire
  it. Fixes the "port 80 helper only starts at boot" limitation.
- **Routing presets** — new `internal/protocol/routing` package: bypass-Iran /
  direct-LAN / block ads·malware·porn·QUIC for sing-box (rule-sets via
  download_detour=proxy), Xray (built-in geoip/geosite), Clash (rule-providers,
  spliced into the exporter YAML via clashWithRouting). Query `?routing=` +
  per-flag override; default from setting `sub_routing_preset` (="iran"). VERIFIED
  by real `sing-box check` + `xray run -test`. Remaining parity batches: node
  naming templates, subscription page + format links, WARP configs, Farsi i18n,
  chain proxy, clean-IP surfacing.

## v1.5.8 — Certificates page: truthful trust banner (cert-honesty)

On a server exposing only :2053 (80/443 closed), ACME failed with
`acme/autocert: missing certificate` — HTTP-01 can't reach a closed :80. The
panel made it worse: the green "viewing over the domain — browser-trusted"
banner keyed off hostname match only, so it claimed trust while the browser said
"Not Secure". Fixed the banner to key off `cert.available` (green only when a
trusted cert is live; otherwise explains the port-80 requirement + the
save-domain-needs-restart caveat). Domain hint now states the port-80 need too.

## v1.5.7 — ForgeDNS encryption-key mismatch (forgedns-key)

A real MasterDNS zone exposed that the client config's `ENCRYPTION_KEY` (the
panel's 64-hex key `4540…`) did not match the server's `encrypt_key.txt`
(`065b…`, 32 hex). Empirically confirmed: MasterDNS rejects a wrong-length key,
generates its own 16-byte key, and overwrites the file on every start (a fresh
random key each time a wrong-length one is supplied); a correctly-sized key is
kept. So client ≠ server → the tunnel can never decrypt. Fix: read the effective
key back from the server and adopt it — `Manager.EffectiveKey()`, plus
`adoptUpstreamKeys()` (post-sync poll, since the rewrite is async) and
`adoptEffectiveKey()` at bundle-render time. Converges after one sync (the adopted
key is a length the upstream keeps → stable). `looksLikeKey` hex-validates to
avoid adopting a partial write; unit-tested.

## v1.5.6 — ForgeDNS delegation IP + port note (forgedns-net)

Running a real zone (`s13.eshkaftak.vip`, masterdns) on the Docker host surfaced
two issues: (1) the delegation A-record showed the Docker bridge IP `172.18.0.2`
because `detectServerIP()` sees only the container interface — added
`publicServerIP()` which, when the detected IP is private, resolves the panel's
configured domain to the real public IP; used for the bundle, panel-address
`server_ipv4`, and DNS-check points-here. (2) The container wasn't publishing
`53/udp`, so the running MasterDNS listener got no queries — fixed on the box
(compose override now maps `53:53/udp`+`53/tcp`) and the setup panel now warns
that 53/udp must be open/published. Verified the live tunnel: Cloudflare delegates
s13→ns.eshkaftak.vip→172.104.159.120, and `:53` now answers tunnel-style queries.
`isPrivateIP` unit-tested.

## v1.5.5 — ForgeDNS page "shows nothing" (forgedns-ux)

The DNS Tunnels page had a blank adapter dropdown and zone creation silently
failed — all Go↔TS contract drift: `/forgedns/adapters` returned `[]string` (UI
wanted `{id,name}`), the dropdown listed native codecs that can't build a bundle,
and the view POSTed `domain`/read `domain`/`active` while the API uses
`zone`/`enabled` + a separate `/bundle` endpoint. Fixed the adapters endpoint to
return the upstream (bundle-capable) family as objects; rewired the view to the
real contract and to fetch the delegation bundle (A/NS records, Cloudflare
warning, SOCKS5, client_config.toml, steps); deduped the standalone `/forgedns`
page into a wrapper over the shared component; bundle A-record defaults to the
server IP. Verified end-to-end against the built binary (create a real
cottendns zone → delegation records + client config), screenshot in
`e2e/test-results/forgedns.png`; new `e2e/tests/forgedns.spec.ts` + rewritten
component test.

## v1.5.4 — Certificates & Panel Domain page (cert-ux)

A user configured `c.xonyon.dpdns.org` and the page reported "DNS failed to
resolve" + "Self-Signed / Indefinite", and Force-Renew said "enable HTTPS first".
Diagnosis on the live host: **the ACME machinery already worked** — a real Let's
Encrypt cert (issuer YE1) is issued over the domain via HTTP-01 on `:80`, and
`https://c.xonyon.dpdns.org:2053/` verifies with `ssl_verify=0`. The bug was the
page: it read the wrong JSON keys (`resolved`/`ip` and the imported-cert list)
instead of the live `panel-address.cert` + `resolves`/`points_here`, so it always
showed failure. Root user-confusion: they were opening the panel **by IP**, where
SNI can't match the domain, so the self-signed fallback (→ "Not Secure") is served.

Fixed & verified in a browser against the BUILT embedded binary (screenshot in
`e2e/test-results/certificates.png`) and end-to-end on the live v1.5.4 container:

- Cert view now reads the real backend fields (true issuer/expiry/days + a
  DNS-points-here verdict); new IP-vs-domain banner links the domain URL to use.
- Saving a panel domain enables HTTPS/ACME; Force-Renew needs only a domain;
  cert priming at boot; domain change ⇒ `restart_required`.
- e2e `certificates.spec.ts` (desktop+mobile) + rewritten `CertificatesView.test.ts`.

## v1.5.0 UI round (BUG-5..BUG-9) — v1.4.0 was WITHDRAWN

A real-server deploy of v1.4.0 exposed that the primary flow did not work in the
browser: Config Studio was a shell, there was no Inbounds section, the panel was
plain HTTP, and the tests validated renderers/handlers in isolation so they were
green while the UI could create nothing. **v1.4.0 tag deleted.** Fixed this round,
each proven in a real browser against the BUILT `go:embed`'d binary:

- **BUG-6 Inbounds section** — new `InboundsView` + shared schema-driven
  `InboundForm` (13 protocols, transport/security pickers, per-field forms from
  `/protocols/schema`, Generate keys, live four-format preview, Save). List with
  Config/Verify/Clone/Toggle/Delete + config card (`vless://` + QR). `7d97ddf`.
- **BUG-5 Config Studio** — rebuilt from a placeholder into the real builder.
- **First-run setup UI** — a fresh install had no way to create the admin in the
  browser; added a setup form. SS2022 PSK keygen fixed. `1c…` (setup commit).
- **BUG-7 HTTPS by default** — cert store self-signed fallback; panel always
  ServeTLS (self-signed w/o domain, ACME with). `(https commit)`.
- **BUG-8** — Panel Doctor panel + Paste-Anything importer + live Verify badges;
  bulk/ForgeEdge-deploy/Live-Explorer/command-palette honestly graded MISSING in
  `docs/UI_AUDIT.md`.
- **BUG-9 verification method** — `e2e/` Playwright runs against the built binary
  with positive assertions + screenshots; harness fixed for HTTPS. 5/5 desktop.

Proof (real browser, deployed server): setup via UI, **13/13 protocols created
through the UI**, Shadowsocks **Verify ✓ 3ms** (real traffic), importer creates
an inbound, Doctor renders, **0 console errors**. See `docs/E2E_REPORT.md` and
`docs/UI_AUDIT.md`. Gates: `go test ./...` 0 fail, gofmt/vet/staticcheck/
govulncheck clean, frontend 38 pass, e2e 5 pass. Tag: **v1.5.0**.

---


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
  - **Overall = 76.0%** (`go test ./... -coverprofile`, total statements) ≥ 75%. ✅
  - `go test ./... -count=1` = 0 failures; `gofmt`/`go vet`/`staticcheck` (v0.7.0)/`govulncheck` clean; race subset clean.
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
