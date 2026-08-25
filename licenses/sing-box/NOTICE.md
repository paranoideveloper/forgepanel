# sing-box, as distributed by ForgePanel

ForgePanel distributes a compiled **sing-box** binary. sing-box is licensed
**GPL-3.0-or-later** and is copyright © 2022 nekohasekai
<contact-sagernet@sekai.icu>. The full licence text is in `LICENSE` beside this
file, and it is installed next to the binary.

ForgePanel itself is MIT. That is unaffected: the panel *runs* sing-box as a
separate program — it starts it as a subprocess and talks to it over a local
socket — and does not link against it or include its code. The two are
separate works distributed together, which the GPL calls mere aggregation.
Distributing the sing-box **binary**, however, is conveying a GPL work, and the
obligations below apply to that binary.

## Why ForgePanel builds it rather than shipping the official one

Per-user traffic counters for the protocols only sing-box serves — Hysteria2,
TUIC, AnyTLS, ShadowTLS and WireGuard — exist only in a build carrying the
`with_v2ray_api` build tag. The official release archives are **not** built with
it. On an official binary those protocols are unmetered: a user can exhaust
their plan on them and stay active indefinitely, because the quota system is
guarding traffic it cannot observe.

## Corresponding source

The binary is built from **unmodified** upstream source. Nothing is patched,
added or removed; only build tags differ.

| | |
|---|---|
| Upstream | https://github.com/SagerNet/sing-box |
| Version | `v1.13.15` |
| Source archive | https://github.com/SagerNet/sing-box/archive/refs/tags/v1.13.15.tar.gz |
| Build recipe | `scripts/build-singbox.sh` in this repository |

That script is the complete recipe: it pins the version, sets the tag list, and
passes the exact compiler and linker flags used. Together with the upstream
source above it constitutes the corresponding source for the binary ForgePanel
distributes.

## Verifying the binary matches that source

The build is reproducible. Two independent runs on a matching Go toolchain
produce **byte-identical** binaries, so the published checksum is checkable
rather than something to take on trust:

```sh
TARGETS="amd64 arm64" scripts/build-singbox.sh /tmp/verify
sha256sum /tmp/verify/sing-box-*
```

Compare against `pinnedSHA256` in `internal/core/binmgr/binmgr.go`, which is what
the panel itself verifies before installing the binary. A mismatch is refused
rather than installed.

## Build tags

The official tag set, plus one:

```
badlinkname, tfogo_checklinkname0, with_acme, with_ccm, with_clash_api,
with_dhcp, with_gvisor, with_naive_outbound, with_ocm, with_purego, with_quic,
with_tailscale, with_utls, with_wireguard,
with_v2ray_api            <- the only addition
```

Nothing is removed. The build script verifies this after compiling and fails if
the set differs, because silently dropping `with_gvisor` or `with_tailscale`
would remove capabilities operators depend on and the loss would not surface
until something failed at runtime.

## Naming

The upstream licence adds: *"no derivative work may use the name or imply
association with this application without prior consent."* ForgePanel therefore
does not present this binary as its own, does not rename the project, and does
not claim endorsement by or association with the sing-box authors. It is
upstream sing-box, compiled with one additional build tag, and it is installed
under a distinct filename (`sing-box-forgepanel`) so it cannot be mistaken for —
or shadow — an operator's own sing-box installation.
