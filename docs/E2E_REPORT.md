# ForgePanel v1.5.0 — End-to-End Verification Report

Real, pasted command output. Branch `fix/round2-remediation`. The v1.4.0 tag was
**withdrawn** because the primary flow (create a config in the browser) did not
work; this round rebuilt the UI and fixes the verification method so a test can
no longer pass on an empty pane.

Toolchain: go1.25.12, bun 1.3.14, Chromium (Playwright). Every UI assertion below
was made by a real headless browser against the **built, `go:embed`'d binary** —
not a dev server, not a mocked API.

## §7 — The acceptance test, entirely through the UI, zero terminal

Run by the in-repo Playwright suite (`e2e/`), which `go build`s `cmd/forgepanel`,
starts it, completes first-run setup, and drives the browser. Positive, specific
assertions (protocol dropdown by name; preview contains `vless://`; saved inbound
appears in the list AND its config card yields a link):

```
$ go build -o e2e/forgepanel-test ./cmd/forgepanel
$ cd e2e && bunx playwright test --project=desktop

Running 5 tests using 1 worker
  ✓ tests/acceptance.spec.ts › Config Studio can create a VLESS+REALITY inbound end to end (2.1s)
  ✓ tests/acceptance.spec.ts › every protocol can be created through the UI (19.7s)
  ✓ tests/bug4.spec.ts › panel UI boots — login works and the shell renders (655ms)
  ✓ tests/bug4.spec.ts › Domains: no-domain banner is bilingual and a domain can be added (1.0s)
  ✓ tests/bug4.spec.ts › BUG-4: inbound edit lifecycle persists and undo restores (741ms)
  5 passed (25.9s)
```

## Against the real deployed server (172.104.159.120), fresh install

A separate headless-Chromium run against the binary deployed on the live server,
over HTTPS, starting from a wiped data directory:

```
SETUP via UI ok                       # created the admin account in the browser, no curl
CREATE 13: 13/13 appear in the list   # vless vmess trojan shadowsocks socks http
                                      # hysteria2 tuic anytls shadowtls wireguard amneziawg brook
VERIFY shadowsocks (traffic): '✓ 3ms' # real bytes through the core, via the UI Verify button
IMPORT paste-anything: created=True rows 13->14   # pasted a vless:// link → new inbound
DOCTOR panel: Overall + per-subsystem health rendered
PAGE ERRORS: []
```

Protocol dropdown, verbatim, as read from the running `<select>`:

```
['VLESS','VMess','Trojan','Shadowsocks','SOCKS5','HTTP','Hysteria2','TUIC',
 'AnyTLS','ShadowTLS','WireGuard','AmneziaWG','Brook']   # 13
```

A created VLESS+REALITY inbound's live preview (Client Link tab), verbatim:

```
vless://98fd3d1e-2f7e-4509-a8f3-7c5750cfa5a2@172.104.159.120:31001?flow=xtls-rprx-vision
  &fp=chrome&pbk=YFhB8WkVhxk_0vQZdAxyNikAssAyV0Kv8AIUgFFPvFA&security=reality
  &sid=a713d57271c787b1&sni=www.cloudflare.com&type=tcp#acc-vless
```

Screenshots (attached to the chat): the populated Inbounds list, the three-pane
Config Studio with the live `vless://`/xray/sing-box/clash preview, and the Panel
Doctor. An empty pane fails these tests.

## BUG-by-BUG

- **BUG-5** Config Studio: rebuilt from a shell into a real builder — protocol/
  transport/security pickers, every per-protocol field (schema-driven from
  `/protocols/schema`), Generate for uuid/reality/shortid/ss2022-PSK/wireguard/
  password, live four-format preview, working Save. **Fixed.**
- **BUG-6** Inbounds section: added — list + create + Config/Verify/Clone/Toggle/
  Delete + config card. **Fixed.**
- **BUG-7** HTTPS: the panel serves TLS by default (self-signed with no domain,
  ACME with one); plain HTTP now returns 400. **Fixed.**
- **BUG-8** surfaces: Panel Doctor and the Paste-Anything importer are reachable
  and working; live Verify badges are in the Inbounds list. Multi-select bulk,
  a ForgeEdge deploy screen, a global Live Connection Explorer and a command
  palette are **not** built and are listed as PARTIAL/MISSING in
  `docs/UI_AUDIT.md` (not hidden).
- **BUG-9** verification: the Playwright suite runs against the built embedded
  binary with positive, specific assertions and screenshots; a first-run setup
  form was added so a fresh install is usable from the browser.

## CI parity (unchanged subsystems)

```
gofmt -l .                 clean        go vet ./...        clean
staticcheck ./...          clean        govulncheck ./...   0 affecting vulns
go test ./... -count=1     0 failures
frontend: bun run check    0 errors     bun run test        38 pass
e2e (desktop)              5 pass
```

## Known limitations

REALITY and QUIC inbounds cannot be *Verified* on a loopback (steal-site / UDP
needs a real network); the Verify badge reports that rather than faking a pass.
Live Cloudflare edge deploy is implemented + unit-tested against mocks, not
exercised against a real account.
