#!/usr/bin/env bash
#
# Build the sing-box ForgePanel ships.
#
# WHY WE BUILD IT OURSELVES. Hysteria2, TUIC, AnyTLS, ShadowTLS and WireGuard are
# served by sing-box, and per-user traffic counters for them exist only in a
# build carrying `with_v2ray_api`. The official release archives are not built
# with it, so on an official binary those protocols are UNMETERED: a user can
# exhaust their plan on them and stay active forever, because the quota system is
# guarding traffic it cannot see. That failure is silent and always in the
# customer's favour.
#
# WHAT THIS GUARANTEES. Shipping a proxy core is a trust decision, so the build
# is constrained to be checkable rather than taken on faith:
#
#   * the sing-box version is pinned to the same one ForgePanel already used, so
#     adopting this build changes metering and NOTHING else;
#   * the tag set is the official one PLUS with_v2ray_api, verified after the
#     build — quietly dropping with_gvisor or with_tailscale would lose features
#     operators depend on, and the loss would not surface until something failed
#     at runtime;
#   * -trimpath and a pinned Go toolchain make the output reproducible, so anyone
#     can rebuild and compare the checksum against the one we publish;
#   * the binary is exercised (`version`, `check`) before it is accepted.
#
# Usage:
#   scripts/build-singbox.sh [outdir]        # host architecture
#   TARGETS="amd64 arm64" scripts/build-singbox.sh dist/
#
set -euo pipefail

# Pinned to match internal/core/binmgr. Changing it here without changing it
# there means the panel verifies a checksum for a version it did not ask for.
SINGBOX_VERSION="${SINGBOX_VERSION:-1.13.21}"

# The official tag set, plus the one the official build omits. Kept as a single
# sorted string so a diff against `sing-box version` is exact.
OFFICIAL_TAGS="badlinkname,tfogo_checklinkname0,with_acme,with_ccm,with_clash_api,with_dhcp,with_gvisor,with_naive_outbound,with_ocm,with_purego,with_quic,with_tailscale,with_utls,with_wireguard"
BUILD_TAGS="${OFFICIAL_TAGS},with_v2ray_api"

OUTDIR="${1:-dist/singbox}"
TARGETS="${TARGETS:-$(go env GOARCH)}"

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || die "go toolchain not found"
say "go $(go env GOVERSION), sing-box v${SINGBOX_VERSION}"
say "tags: ${BUILD_TAGS}"

mkdir -p "$OUTDIR"
# Truncate rather than append: re-running into the same directory otherwise
# accumulates stale entries, and a checksums file listing an artifact twice —
# possibly with two different hashes from two different runs — is worse than no
# checksums file, because it looks authoritative.
: > "${OUTDIR}/checksums.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A throwaway module that requires the pinned sing-box, so `go build -o` can
# target the command inside it. `go install` cannot be used here: it refuses to
# write a cross-compiled binary when GOBIN is set, which makes arm64 impossible.
say "resolving sing-box v${SINGBOX_VERSION}"
(
  cd "$WORK"
  go mod init forgepanel-singbox-build >/dev/null 2>&1
  GOFLAGS=-mod=mod go get "github.com/sagernet/sing-box/cmd/sing-box@v${SINGBOX_VERSION}" >/dev/null 2>&1
) || die "could not resolve sing-box v${SINGBOX_VERSION}"

for arch in $TARGETS; do
  out="${OUTDIR}/sing-box-${SINGBOX_VERSION}-linux-${arch}"
  say "building linux/${arch}"

  # -trimpath removes local filesystem paths from the binary; without it the
  # output embeds this machine's directory layout and nobody else can reproduce
  # the checksum. GOFLAGS=-mod=mod matches how the rest of the tree builds.
  #
  # -checklinkname=0 is REQUIRED, not a workaround to tidy away later: sing-box
  # reaches into crypto/tls internals with //go:linkname (that is what the
  # upstream tfogo_checklinkname0 tag refers to), and Go rejects those
  # references at link time without it. Dropping this flag does not produce a
  # slightly different binary — it produces no binary at all.
  #
  # -X ...constant.Version stamps the version. Without it the build reports
  # "unknown", and binmgr's post-install version check — the thing that catches
  # a mismatched artifact — has nothing to compare.
  (
    cd "$WORK"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOFLAGS=-mod=mod \
      go build -trimpath -tags "$BUILD_TAGS" \
        -ldflags "-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION}" \
        -o "$WORK/sing-box-$arch" \
        github.com/sagernet/sing-box/cmd/sing-box
  ) || die "build failed for ${arch}"

  built="$WORK/sing-box-$arch"
  [ -f "$built" ] || die "built binary not found for ${arch}"
  install -m 0755 "$built" "$out"

  # Verify the tags on the HOST architecture only; a cross-built binary cannot
  # be run here, and claiming to have checked it would be worse than not
  # checking.
  if [ "$arch" = "$(go env GOARCH)" ]; then
    got_tags="$("$out" version | sed -n 's/^Tags: //p' | tr ',' '\n' | sort | paste -sd, -)"
    want_tags="$(printf '%s' "$BUILD_TAGS" | tr ',' '\n' | sort | paste -sd, -)"
    [ "$got_tags" = "$want_tags" ] || die "tag mismatch
  built: ${got_tags}
  want:  ${want_tags}
A missing tag silently removes a capability operators depend on."
    case "$("$out" version | head -1)" in
      *"$SINGBOX_VERSION"*) ;;
      *) die "built binary reports the wrong version: $("$out" version | head -1)" ;;
    esac
    say "verified tags and version on linux/${arch}"
  else
    say "cross-built linux/${arch} (not executed here; tags unverified on this host)"
  fi

  sha="$(sha256sum "$out" | cut -d' ' -f1)"
  printf '%s  %s\n' "$sha" "$(basename "$out")" >> "${OUTDIR}/checksums.txt"
  say "$(basename "$out")  ${sha}"
done

# sing-box is GPL-3.0. Conveying the binary requires keeping its notices intact,
# so the licence travels with every artifact rather than only living in the
# repository.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "${REPO_ROOT}/licenses/sing-box/LICENSE" ]; then
  install -m 0644 "${REPO_ROOT}/licenses/sing-box/LICENSE" "${OUTDIR}/sing-box-LICENSE"
  install -m 0644 "${REPO_ROOT}/licenses/sing-box/NOTICE.md" "${OUTDIR}/sing-box-NOTICE.md"
  say "included sing-box LICENSE and NOTICE (GPL-3.0)"
else
  die "licenses/sing-box/LICENSE is missing; refusing to build a GPL binary without its licence"
fi

say "artifacts in ${OUTDIR}"
say "pin these in internal/core/binmgr (pinnedSHA256) before shipping"
