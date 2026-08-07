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
