# AGENTS.md - ForgePanel AI Agent Operating Instructions

This document provides architectural context, development principles, testing requirements, and PR guidelines for AI coding agents working on **ForgePanel**.

## 1. System Architecture & Structure

ForgePanel is a Go-based server management panel and node orchestration platform designed for high performance, zero external dependencies, and single-binary deployment.

### Binaries (`./cmd/`)
- **`cmd/forgepanel`**: Core management panel, HTTP/REST API server, web UI host, and system orchestrator.
- **`cmd/forgectl`**: CLI administration utility for panel management, system health, backups, and user credentials.
- **`cmd/forgenode`**: Lightweight node daemon running on remote managed servers.

### Key Packages (`./internal/`)
- **`internal/api`**: REST API routes, HTTP handlers, middleware, request binding/validation.
- **`internal/auth`**: Authentication routines, JWT/session management, authorization checks.
- **`internal/config`**: System configuration structure (`config.yaml`), default settings, environment loading.
- **`internal/core`**: Core domain types, shared interfaces, system constants.
- **`internal/domain`**: Business domain rules and entity behavior.
- **`internal/store`**: SQLite database layer (via `modernc.org/sqlite` pure-Go driver), repository implementations, query executions.
- **`internal/service`**: Application service layers coordinating business tasks.
- **`internal/job`**: Asynchronous task runner, job queue, background workers.
- **`internal/lifecycle`**: Service initialization, background task orchestration, graceful shutdown handlers.
- **`internal/migrate`**: Schema versioning and SQL migrations.
- **`internal/forgedns`, `internal/backup`, `internal/cert`, `internal/telegram`**: Subsystem integrations.

---

## 2. Core Operating Rules for AI Agents

1. **Precision & Root Cause Solutions**:
   - Fix problems at the root cause. Avoid superficial patches, hacks, or ignoring edge cases.
   - Respect existing architectural abstractions and package boundaries.

2. **Surgical Diffs & Minimal Changes**:
   - Do not add unrequested abstractions, unnecessary files, or dead code.
   - Maintain concise, clean diffs focused directly on the prompt requirement.

3. **Mandatory Test Verification & CI Matrix Standards**:
   - All tests across all decoupled suites (`.github/workflows/ci.yml`) must pass cleanly.
   - Run tests with `-shuffle=on -count=1` to guarantee test independence and prevent state leakages between tests.
   - Ensure code passes race detector (`go test -race ./...`) and `gofmt -l .` formatting checks.

4. **Zero CGO Requirement**:
   - SQLite is driven via pure Go (`modernc.org/sqlite`).
   - Binaries must build cleanly with `CGO_ENABLED=0`.
3. **Mandatory Testing & Quality Verification**:
   - All tests must pass prior to opening or updating a PR.
   - Run `go test ./...` and `go vet ./...` locally before submitting changes.

4. **Zero CGO Requirement**:
   - SQLite is driven via pure Go (`modernc.org/sqlite`).
   - Binaries must build with `CGO_ENABLED=0`.

5. **RTK Command Wrapper**:
   - When running CLI/shell commands in environments with RTK installed, prefix commands with `rtk` (e.g., `rtk go test ./...`, `rtk make build`).

---

## 3. Mandatory Pre-Commit Checklist & Test Suite Verification

Before submitting or updating any Pull Request, agents **MUST** execute and pass all verification steps:

```bash
# 1. Code Formatting, Frontend & Dependency Hygiene
UNFORMATTED=$(gofmt -l .) && test -z "$UNFORMATTED"
(cd frontend && bun run check && bun run test --coverage)
go mod tidy && git diff --exit-code go.mod go.sum

# 2. Decoupled Matrix & Randomized Test Execution
rtk go test -shuffle=on -count=1 -v ./internal/core/... ./internal/protocol/...
rtk go test -shuffle=on -count=1 -v ./internal/api/... ./internal/store/... ./internal/auth/...
rtk go test -shuffle=on -count=1 -v ./internal/forgedns/...
rtk go test -shuffle=on -count=1 -v ./cmd/...
rtk go test -shuffle=on -count=1 -v ./internal/deploy/... ./internal/domain/... ./internal/backup/... ./internal/cert/... ./internal/config/... ./internal/job/... ./internal/lifecycle/... ./internal/migrate/... ./internal/telegram/... ./internal/version/...

# 3. Concurrency & Data Race Detector
rtk go test -race -v ./...

# 4. Go Vet & Static Analysis
rtk go vet ./...

# 5. Build Compilation Check
## 3. Mandatory Pre-Commit Checklist & Test Execution

Before submitting a Pull Request, agents **MUST** execute and pass the following steps:

```bash
# 1. Run full unit and integration test suite
rtk go test ./...

# 2. Run Go static analyzer / linter
rtk go vet ./...

# 3. Verify static multi-binary build compilation
rtk make build
```

---

## 4. Pull Request Requirements

Every pull request created or modified by an agent must follow `.github/PULL_REQUEST_TEMPLATE.md`, providing:
- Clear summary of changes and root-cause rationale.
- Verification evidence covering formatting, matrix testing, race detection, static analysis, and builds.
- Checklist confirming full compliance with `AGENTS.md` instructions and PR #3 CI matrix standards.
Every pull request created by an agent must follow `.github/PULL_REQUEST_TEMPLATE.md`, providing:
- Clear summary of changes and root-cause rationale.
- Verification evidence (pasted output of test runs).
- Checklist confirming `AGENTS.md` rules were followed.
