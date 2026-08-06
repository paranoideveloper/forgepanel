## Summary of Changes
<!-- Provide a clear, concise summary of the changes made, the root cause addressed, and why this change is necessary. -->

## AI Agent / Contributor Checklist (CI Matrix Compliant)
- [ ] **Root Cause Fixed**: Addressed root cause cleanly without superficial workarounds.
- [ ] **Minimal Diff**: No unrequested abstractions, unnecessary files, or unneeded boilerplate.
- [ ] **Code Formatting & Clean Dependencies**: `gofmt -l .` reports zero unformatted files, and `go mod tidy` produces no `git diff`.
- [ ] **Decoupled & Randomized Test Pass**: `go test -shuffle=on -count=1 ./...` passes 100% across all sub-suites in `.github/workflows/ci.yml`.
- [ ] **Data Race Clean**: `go test -race ./...` runs with zero data race detections.
- [ ] **Static Analysis Clean**: Executed `go vet ./...` (and `staticcheck` if available) with zero issues.
- [ ] **Build Verification**: Verified `make build` compiles static binaries (`forgepanel`, `forgectl`, `forgenode`).
- [ ] **AGENTS.md Compliance**: Followed all architectural and precision guidelines in `AGENTS.md`.

## Verification Evidence
```bash
# Paste exact verification command output here
# gofmt check, go test -shuffle=on -count=1 -v ./..., go test -race ./..., go vet ./..., make build
```

## Affected Components
- [ ] `cmd/forgepanel` (Control panel server & Web REST API)
- [ ] `cmd/forgectl` (CLI administration tool)
- [ ] `cmd/forgenode` (Node daemon worker)
- [ ] `internal/*` (Core services, SQLite store, API, Auth, Jobs)
- [ ] Documentation / CI / Configuration
