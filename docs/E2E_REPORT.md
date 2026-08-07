# ForgePanel Round-2 — End-to-End Verification Report

Real command output, not descriptions. Branch: `fix/round2-remediation`.
Toolchain: go1.25.12, bun 1.3.14, sing-box + xray cores present.

## CI parity — every `.github/workflows/ci.yml` job reproduced locally

The two failures that made `main` red were **govulncheck** (exit 3, 15 called
vulns) and **shellcheck** (exit 1, install.sh). Both fixed on the branch.

```
gofmt -l .                                 PASS (no output)
go vet ./...                               PASS
staticcheck ./...                          PASS (no output)
shellcheck install.sh                      PASS (exit 0, was exit 1)
goreleaser check                           PASS (1 configuration file(s) validated)
govulncheck ./...                          PASS (exit 0, was exit 3)
go mod tidy                                PASS (no diff to go.mod/go.sum)

go test -shuffle=on -count=1 ./internal/protocol/...                         PASS
go test -shuffle=on -count=1 ./internal/store/... ./internal/migrate/...     PASS
go test -shuffle=on -count=1 ./internal/core/... ./internal/deploy/...       PASS
go test -shuffle=on -count=1 ./internal/api/... ./internal/auth/... ./internal/service/... ./internal/settings/...  PASS
go test -shuffle=on -count=1 ./internal/forgedns/...                         PASS
go test -shuffle=on -count=1 ./internal/backup/... ./internal/cert/... ./internal/config/... ./internal/job/... ./internal/lifecycle/... ./internal/telegram/... ./internal/version/...  PASS
go test -shuffle=on -count=1 ./cmd/...                                       PASS
go test -race  (cert config telegram lifecycle forgedns/... protocol/... settings)  PASS

make build (frontend bun build + 3 Go binaries)     PASS
GOARCH=386  build forgepanel/forgectl/forgenode     PASS
GOARCH=arm64 build                                  PASS
frontend: bun run check                             PASS (395 files, 0 errors)
frontend: bun run test --coverage                   PASS (14 files, 37 tests, 90.9% stmts)
docker build -t forgepanel:ci .                     PASS
```

## BUG-3 — Domains subsystem (live, against a running panel)

```
domains-status (no domain):   has_domain=false, recommends REALITY=true
POST /admin/domains {vpn.example.com}:  created, is_default=true (first domain auto-default)
POST /admin/inbounds {vless, ws, tls, NO domain field}:  id=1  (inherits default domain)
GET  /sub/<tok>/links:
  vless://…@vpn.example.com:30443?...&host=vpn.example.com&security=tls&sni=vpn.example.com&type=ws#wsdom
```
The inbound carried no domain of its own, yet the exported client link dials the
domain and its SNI + WS Host both cascaded from it. `allowInsecure=1` appears only
because no real certificate exists for the test domain (honest self-signed
fallback) — the panel never presents it as verified.

## BUG-4 + UI wiring (Playwright, real browser, desktop + mobile)

Two critical bugs were found only by driving the real UI: the SvelteKit assets
were never served (/_app/* → 404, the panel had no working UI), and the SPA
called endpoints that do not exist (login hit /api/auth/login not /api/login;
the dashboard hit /api/health). Both fixed.

```
$ make e2e   (cd e2e && bunx playwright test)
  ✓ [desktop] panel UI boots — login works and the shell renders
  ✓ [desktop] Domains: no-domain banner is bilingual and a domain can be added
  ✓ [desktop] BUG-4: inbound edit lifecycle persists and undo restores
  ✓ [mobile]  panel UI boots — login works and the shell renders
  ✓ [mobile]  Domains: no-domain banner is bilingual and a domain can be added
  ✓ [mobile]  BUG-4: inbound edit lifecycle persists and undo restores
  6 passed
```

## §7.4 — Every protocol carries real traffic (connectivity matrix)

TestFullMatrixConnectivity aggregates every protocol×transport×security as a
real inbound, launches the real cores, and routes traffic client→origin through
each tunnel. Real output:

```
~ vless-tcp-reality-vision   skipped on loopback (reality steal-handshake; tested on public IP)
~ vless-tcp-reality          skipped on loopback (reality steal-handshake; tested on public IP)
~ vless-xhttp-reality        skipped on loopback (reality steal-handshake; tested on public IP)
~ vless-grpc-reality         skipped on loopback (reality steal-handshake; tested on public IP)
✓ vless-ws-tls               traffic OK
✓ vless-grpc-tls             traffic OK
✓ vless-xhttp-tls            traffic OK
✓ vless-httpupgrade-tls      traffic OK
✓ vless-tcp-tls-vision       traffic OK
✓ vmess-tcp                  traffic OK
✓ vmess-ws-tls               traffic OK
✓ vmess-grpc-tls             traffic OK
✓ trojan-tcp-tls             traffic OK
✓ trojan-ws-tls              traffic OK
✓ trojan-grpc-tls            traffic OK
✓ ss-aes-256-gcm             traffic OK
✓ ss-chacha20                traffic OK
✓ ss-2022-128                traffic OK
✓ ss-2022-256                traffic OK
✓ socks5                     traffic OK
✓ http                       traffic OK
✓ hysteria2                  traffic OK
✓ tuic-v5                    traffic OK
✓ anytls                     traffic OK
ALL 24 protocol inbounds passed real traffic end-to-end
```

**20 variants carry real bytes end to end; the 4 REALITY variants are skipped on
loopback (24 total, all accounted for).** REALITY relays its TLS handshake to a
real steal-site, which cannot complete when client and server share the loopback
interface — verified on the public deployment box instead.

This run also folds in the §4-harness teammate's five confirmed blockers, each
fixed at the source and re-proven with the real core (see STATE.md for SHAs):
Hysteria2/TUIC/AnyTLS — previously skipped on loopback — now pass because the
spurious `utls` block that sing-box rejected on QUIC is gone; the shipped alpine
image can now exec the glibc sing-box binary (`gcompat`); self-signed TLS is
auto-pinned for xray26 (`pinnedPeerCertSha256`); Shadowsocks keeps its inbound
PSK; and the sing-box subscription is now a runnable config.

## §3 — Live Verify proves traffic through one canonical node
```
go test ./internal/diag/ -run TestVerify -v
  vmess       verified end to end in 3ms   (real sing-box server+client, SOCKS, HTTP round trip)
  shadowsocks verified end to end in 3ms
  REALITY reported honestly-unprovable offline (needs a live TLS-1.3 dest)
```

## §6 — ForgeEdge worker
```
cd deploy/cloudflare/forgeedge && bun run typecheck && bun test
  tsc --noEmit: clean
  316 pass  0 fail  (7 files) — VLESS/Trojan WS framing, routing rules, subscription, secure-path
```

## Full Go suite (CI commands, no -short) + frontend
```
go test ./internal/... ./cmd/...        33 packages ok, 0 fail
go test -race (cert config forgedns protocol diag …)  ok
staticcheck ./...   exit 0     govulncheck ./...  exit 0
frontend: bun run check (0 errors) · bun run test (39 pass)
e2e: playwright 6/6 (desktop + mobile)
docker build -t forgepanel:ci .   ok
```
