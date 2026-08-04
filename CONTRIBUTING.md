# Contributing to ForgePanel

## Build & test
- Go 1.24. `make build` → `bin/forgepanel`, `bin/forgectl`, `bin/forgenode`.
- `make check` → `go vet ./...` + `go test ./...`.
- Network/process integration tests are behind `-short` (they download the pinned
  cores). Run the full suite with `go test ./...`.

## The one architectural rule
There is exactly one canonical representation of a node: `model.Node`. Everything
else (render/export/parse) is a pure function of it. If you add a protocol or a
field, extend `model` + `Normalize` + `Validate`, then export **and** parse
together, and keep the round-trip property test green. See `CLAUDE.md`.

## Conventions
- Doc comments explain **why**, citing the spec section (`§N`).
- No secrets in exported links; validate input at the edge; parameterised queries.
- Conventional Commits; never leave the tree broken between commits.

## Adding a DNS-tunnel wire format
Implement `adapter.Adapter` in `internal/forgedns/adapter`, register it in
`named.go`, add test vectors. No changes to the session/server/API layers.
