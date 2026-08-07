# Changelog

## v1.4.0 — Round-2 remediation & expansion

### Fixed (the broken fundamentals)
- **Panel UI was completely dead**: the SvelteKit build's `/_app/*` assets were
  never served (404), so the app could not boot. Now served with correct MIME
  types + SPA fallback.
- **Login was broken**: the SPA called `/api/auth/login` returning `{token}`; the
  backend serves `/api/login` returning `{access_token}`. Reconciled, plus the
  `/health`→`/admin/overview`, `/usergroups`→`/groups`, `/presets`→
  `/protocols/presets` mismatches. A path-audit script now keeps them in sync.
- **Subscriptions**: the sing-box output was rejected by the real core (duplicate
  `proxy` tag); the `Subscription-Userinfo` header reported all-zeros regardless
  of the user's real quota/expiry. Both fixed and proven against `sing-box check`.
- **BUG-3 — Domains**: a first-class Domains registry, a domain that cascades to
  SNI / Host / cert / client-link address / subscription, one-click ACME with an
  honest preflight, and the no-domain path that steers to REALITY (EN+FA) instead
  of silently emitting plaintext.
- **BUG-4 — inbound editing**: safe-edit warnings on breaking changes, clone,
  enable/disable, bulk actions, and one-level undo. Covered by Playwright.
- **BUG-2 — emitted configs now carry real traffic** (the §4 connectivity harness
  drives the real cores over every emitted config; 24/24 protocol inbounds pass,
  only the 4 REALITY variants skipped on loopback):
  - The shipped **alpine image could not exec the glibc sing-box** release binary
    (exit 127) — Hysteria2/TUIC/AnyTLS/ShadowTLS/WireGuard/SSH were all dead in
    the container. Added `gcompat`; proven by running the pinned sing-box inside
    the built image.
  - **QUIC no longer carries a `utls` block** sing-box rejects: `fingerprint=chrome`
    was stamped on every TLS node and turned into `utls`, which Hysteria2/TUIC
    refuse. Now suppressed for QUIC at both the render and defaults layers.
  - **Self-signed TLS is auto-pinned** for xray-core 26 (which removed
    `allowInsecure`): the subscription now carries `pinnedPeerCertSha256` of the
    exact cert the engine serves. Proven by a real xray TLS round-trip.
  - **Shadowsocks keeps its inbound PSK** in the subscription: stamping the user's
    base64url password broke SS-2022 (needs exact-length standard base64) and
    handed clients a key the single-key server never held.
  - The **sing-box subscription is runnable as delivered**: it now ships a local
    mixed inbound + route instead of an outbounds-only document that carried
    nothing.
  - **ShadowTLS carries traffic**: the subscription emits the required
    Shadowsocks→ShadowTLS `detour` chain instead of a bare shadowtls outbound
    that camouflages TLS but proxies nothing. Proven by `sing-box check`.
- **Over-quota users are cut off**: `enabledInboundSpecs` and the ForgeEdge feed
  skipped only Disabled/Expired, so a user past their data limit (`StatusLimited`)
  kept transferring until the next engine reload. Both planes now agree.
- **Inbounds can be disabled without deletion**: `POST /inbounds/:id/toggle`
  clears `Enabled`, which `enabledInboundSpecs` honours, so a disabled inbound
  stops serving immediately (previously only deletion removed it).
- **ForgeDNS reassembly no longer deadlocks**: a full reorder buffer used to
  reject the in-order head frame that would have drained it, stalling the session
  permanently on its own missing head. The head is now always accepted.
- **CI workflow was invalid YAML**: all seven `Test Suite: …` job names carried an
  unquoted colon, which GitHub rejects for the whole file. Quoted; a real carried
  fix for main (the workflow could never have run as written).

### Added
- Subscription formats: `xray` (validated by `xray run -test`), `surge`, `loon`,
  `quantumultx`, `shadowrocket`; `clash-meta`; a golden-file matrix over all.
- **Validation & Proof engine** (`internal/diag`): static checks with a coded,
  bilingual diagnostics catalogue (`docs/DIAGNOSTICS.md`), a live Verify that
  carries real traffic through one canonical node, and a Panel Doctor.
- **§4 connectivity harness** (`test/harness/`, build-tagged): docker-compose
  proof of real traffic per protocol, with an experimental-flagging matrix.
- **§5 DNS automation wizard** (`internal/dns`): Cloudflare-first (+ ArvanCloud,
  deSEC) token verification with precise scope diagnostics, zone/subdomain CRUD,
  parent-zone/delegation handling, ACME preflight, rotation pool, clean-IP
  scanner, and `forgectl provision`.
- **§6 ForgeEdge** (`deploy/cloudflare/forgeedge/`): a Cloudflare Worker sharing
  the canonical model — VLESS/Trojan over WS, DoH, WARP, chain proxy, fragment,
  routing rules, and Backend Mode to a VPS node.
- **§6 ForgeEdge Go-side** (`internal/edge`, `internal/api/edge*.go`,
  `internal/store` `EdgeDeployment`, `forgectl edge`): the panel now feeds the
  canonical model to registered Workers — a redacted push/pull feed so one
  subscription URL carries VPS inbounds *and* edge entries, Cloudflare
  OAuth+PKCE (and `--api-token`) deploy/update/delete/status/push/rotate-path, and
  a CI drift guard that regenerates the golden fixtures from the real Go exporters
  and asserts the TypeScript mirror is byte-identical.

### CI / build
- Fixed the red CI: govulncheck (x/net, x/text, go 1.25.12) and shellcheck; the
  invalid workflow YAML (unquoted colons in job names); and a `.gitignore` pattern
  (`forgectl`) that was silently ignoring the whole `cmd/forgectl/` source dir.
- All fixes on one branch; `make check`, `staticcheck ./...` and `govulncheck
  ./...` clean; the full non-`-short` Go matrix, race detector, frontend (39),
  ForgeEdge worker (316) + drift guard, e2e, cross-compile and docker all green.
