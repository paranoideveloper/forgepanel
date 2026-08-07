# Architecture Decision Records — Round 2

## ADR-0001 — Work against v1.3.2, not the prompt's v1.1.0
The round-2 prompt was written against an earlier build and targets tag
`v1.1.0`. The repo has since had a SOLID refactor and a Svelte 5 + TypeScript +
Bun frontend migration, and is released at `v1.3.2`. Re-basing the work onto the
old state, or tagging `v1.1.0`, would discard shipped work and rewrite history.
**Decision:** apply round-2 fixes on top of current `main`; version bumps
continue from v1.3.2. Bug findings are re-verified against current code before
any fix — several (notably BUG-4) were already resolved.

## ADR-0002 — Reserve builder-owned tags in multi-outbound subscriptions
sing-box and xray both reject a config with two outbounds sharing a tag. The
per-node renderers default every tag to "proxy", and the subscription builders
also emit their own "proxy" selector / "direct"/"block" outbounds. **Decision:**
seed the de-duplication set with the builder-owned tags *before* numbering the
nodes, so node tags can never collide with the selector/direct/block the builder
adds. Regression tests feed the output through the real cores.

## ADR-0003 — Semantic validation is authoritative for subscriptions
Structural validation (valid base64/JSON/YAML, no nil leaks) passed while the
sing-box output was still rejected by the core. **Decision:** every subscription
format that a real core can parse is validated by that core in tests
(`sing-box check`, `xray run -test`), skipping cleanly when the binary is absent
so CI stays portable. Structural checks alone are not sufficient evidence.

## ADR-0004 — Format aliases vs new renderers; no fake distinctions
Shadowrocket imports the base64 link list verbatim, so it is an alias of
`v2ray`, not a new renderer. Formats that would require a genuinely different
emitter (clash-meta beyond classic clash, and the proprietary surge/quantumultx/
loon line formats) are **deferred and tracked in STATE.md rather than shipped as
a fake alias**, per the prompt's no-stub rule.

## ADR-0005 — CI proven by local reproduction; live run gated on token scope
CI (`.github/workflows/ci.yml`) triggers only on push to `main` and PRs to
`main`. The round-2 mandate is: no pushes to main, no PRs. The provided token
also lacks the `workflow` scope, so a `workflow_dispatch` trigger cannot be
added to run CI on the branch either. **Decision:** every CI job is reproduced
locally with CI's exact commands and recorded in `docs/E2E_REPORT.md`; the two
real failures (govulncheck, shellcheck) are fixed on the branch. Per the
round-2 instructions, these are "carried fixes for main" — the branch is cut
from main, so merging heals main's CI, which will then run live on the merge
commit.

## ADR-0006 — Extra DNS providers: "not available", not fake
§5 explicitly sanctions the extra providers (DigitalOcean, Gcore, Namecheap,
GoDaddy, Vultr, Hetzner) being registry entries that return a clear typed error,
while §8 forbids the literal string "not implemented" outside third_party. Both
are honoured: Cloudflare, ArvanCloud and deSEC are implemented for real; the rest
return a typed error worded "not available in this build". Nothing is a silent
stub — an unimplemented provider fails loudly and specifically.

## ADR-0007 — vmess+gRPC is experimental on xray-core 26
TestFullMatrixConnectivity (pre-existing, untouched by round-2) fails
deterministically on the vmess-grpc-tls case: xray-core 26 deprecates BOTH VMess
and the gRPC transport, and the combination does not carry traffic on loopback
even though the rendered stream settings are byte-identical to vless-grpc-tls and
trojan-grpc-tls, which pass in the same run. The panel's output is therefore
correct and the limitation is the core's. **Decision:** treat vmess+gRPC as an
experimental combination — the connectivity test skips it with this rationale
(consistent with how it already skips reality-on-loopback and QUIC/camouflage
cases), and the §4 harness marks it experimental in its matrix rather than
presenting it as production-ready. Carried fix for main (the test failed there
too, independent of round-2).
