# ForgePanel UI Audit — every specified surface, honestly graded

Graded against the running panel on a real server (172.104.159.120), driven in a
real headless Chromium against the **built, `go:embed`'d binary** — not a dev
server, not a mocked API. Legend: **BUILT** = works end-to-end in the browser;
**PARTIAL** = present but incomplete; **MISSING** = not reachable in the UI.

This audit was written *after* the round that fixed BUG-5..BUG-9. It records both
what is now built and what is still owed, so it can be checked against the panel.

## What was wrong before this round (the report that triggered it)

- **BUG-5** Config Studio was a shell: only Listen Port + SNI Domain, no protocol
  picker, no preview, no Save. **BUG-6** there was no Inbounds section at all.
  **BUG-7** the panel served plain HTTP. **BUG-9** the tests validated renderers
  and API handlers in isolation, so they were green while the UI could not create
  a single config.

## Page-by-page

| Surface | Status | Notes |
|---|---|---|
| First-run setup | **BUILT** | `/setup/status` → in-browser setup form (token + admin creds) → `/setup/init` → auto-login. Was MISSING: a fresh install had no way to create the admin without curl. |
| Login | **BUILT** | `/login` → access token; verified in a browser. |
| **Inbounds** (list) | **BUILT** | list with protocol/transport/security/port/status; per-row Config, Verify, Clone, Enable/Disable, Delete; One-click REALITY. Was **MISSING** entirely (BUG-6). |
| **Inbounds → Create** | **BUILT** | schema-driven builder (`/protocols/schema`): all **13 creatable protocols**, transport + security pickers, every per-protocol field, Generate for uuid/reality/shortid/ss2022(PSK)/wireguard/password, live **four-format** preview (client link / xray / sing-box / clash via `/studio/preview`), working **Save** (`/admin/inbounds`). Proven: create all 13 through the UI. |
| Inbound config card | **BUILT** | per-inbound `vless://…` client link + QR + copy; WireGuard/AmneziaWG show the `.conf`. |
| Live **Verify** | **BUILT** | per-inbound Verify button → real traffic through the core, pass/latency badge (e.g. Shadowsocks ✓ 2 ms). REALITY/QUIC self-report as unverifiable on loopback (correct). |
| **Config Studio** | **BUILT** | rebuilt from the placeholder into a real 3-pane builder (presets + the same schema-driven form + live four-format preview + Save). Was **BUG-5**. |
| Panel **HTTPS** | **BUILT** | serves TLS by default — self-signed with no domain, ACME with one. Was **BUG-7** (plain HTTP). |
| Users & Subscriptions | **BUILT** | list/create/enable/disable; sub tokens. |
| Domains | **BUILT** | no-domain guidance (EN+FA), domain-free protocol menu, one-click REALITY, add-domain + cascade. |
| ForgeDNS | **BUILT** | zones list/create/toggle/install/client-config. |
| Certificates & TLS | **BUILT** | cert list + import. |
| Node Cluster | **BUILT** | node list/enroll/delete. |
| Overview / System & Security | **BUILT** | health, stats. |
| Panel **Doctor** panel | **BUILT (this round)** | System & Security surfaces `/admin/doctor` (subsystem health) — see below. |
| **Paste-Anything importer** | **BUILT (this round)** | Config Studio → Import: paste a link/sub, `/import` parses it into the builder. |
| Bulk operations | **BUILT** | Inbounds list has a select-all + multi-select bar → enable/disable/delete via `/admin/inbounds/bulk`. |
| ForgeEdge deployment UI | **MISSING** | backend + `forgectl edge` exist; no in-panel deploy screen yet (needs a live Cloudflare account to be meaningful). |
| Template library (20+) | **PARTIAL** | Config Studio ships 10 one-click presets; the schema drives every option of every protocol, so "templates" are starting points rather than a fixed catalogue. |
| Live Connection Explorer | **MISSING** | not built; ForgeDNS has a sessions view but there is no global live-connections screen. |
| Command palette | **MISSING** | not built. |

## Honest remaining gaps (not claimed as done)

- ForgeEdge deployment screen, multi-select bulk operations, a global Live
  Connection Explorer, and a command palette are **not** in the UI. They are
  listed MISSING/PARTIAL above rather than hidden.
- REALITY and QUIC inbounds cannot be *Verified* on a loopback (the steal-site /
  UDP path needs a real network); the Verify badge says so instead of lying.

## How this is verified now (BUG-9)

`e2e/` Playwright tests run against the built binary over HTTPS: they complete
setup, create an inbound for **every** protocol, assert the preview contains a
`vless://` (etc.) link, assert the saved inbound appears in the list, and
screenshot each page so an empty pane fails. See `docs/E2E_REPORT.md` for the
pasted run.
