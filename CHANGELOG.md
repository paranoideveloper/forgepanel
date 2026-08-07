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

### CI / build
- Fixed the red CI: govulncheck (x/net, x/text, go 1.25.12) and shellcheck.
- All fixes on one branch; `make check`, `staticcheck ./...` and `govulncheck
  ./...` clean; the full non-`-short` Go matrix, frontend, e2e and docker green.
