#!/usr/bin/env bash
# ForgePanel §4 connectivity harness — orchestrator.
#
#   ./run.sh                 # full matrix (connectivity + policy)
#   ./run.sh --set quick     # the five paths that must never regress
#   ./run.sh --only vless    # every case whose id contains "vless"
#   ./run.sh --keep          # leave the stack up for inspection afterwards
#
# What it does, in order:
#   1. fetches the proxy cores the panel pins, verifying the SHA-256 the panel
#      itself would verify (read out of internal/core/binmgr, so a version bump
#      there cannot silently leave this script testing an older core);
#   2. builds the two images and starts the panel + the isolated origin;
#   3. reads the one-time first-run setup token out of the panel's data dir,
#      exactly as the installer does, and hands it to the driver;
#   4. runs the driver in the client container and copies the matrix out.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CACHE="$HERE/.cache/bin"
RESULTS="$HERE/results"
BINMGR="$ROOT/internal/core/binmgr/binmgr.go"
COMPOSE=(docker compose -f "$HERE/docker-compose.yml")

KEEP=0
DRIVER_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)  KEEP=1; shift ;;
    --set)   DRIVER_ARGS+=(-set "$2"); shift 2 ;;
    --only)  DRIVER_ARGS+=(-only "$2"); shift 2 ;;
    --no-fail) DRIVER_ARGS+=(-fail-on-fail=false); shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) DRIVER_ARGS+=("$1"); shift ;;
  esac
done

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# 1. pinned cores
# ---------------------------------------------------------------------------
pin_value() { # pin_value <const-name>
  grep -oE "^\s*$1\s*=\s*\"[^\"]+\"" "$BINMGR" | grep -oE '"[^"]+"' | tr -d '"'
}
pin_sha() {  # pin_sha <asset-filename>
  grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[0-9a-f]{64}\"" "$BINMGR" | grep -oE '[0-9a-f]{64}'
}

XRAY_VERSION="$(pin_value XrayVersion)"
SINGBOX_VERSION="$(pin_value SingboxVersion)"
[[ -n "$XRAY_VERSION" && -n "$SINGBOX_VERSION" ]] || { err "could not read pinned core versions from $BINMGR"; exit 1; }

case "$(uname -m)" in
  x86_64)  XRAY_ASSET="Xray-linux-64.zip";        SB_ARCH="amd64" ;;
  aarch64) XRAY_ASSET="Xray-linux-arm64-v8a.zip"; SB_ARCH="arm64" ;;
  *) err "unsupported architecture $(uname -m)"; exit 1 ;;
esac
SB_ASSET="sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"
XRAY_SHA="$(pin_sha "$XRAY_ASSET")"
SB_SHA="$(pin_sha "$SB_ASSET")"

verify() { # verify <file> <sha256>
  local got; got="$(sha256sum "$1" | cut -d' ' -f1)"
  [[ "$got" == "$2" ]] || { err "checksum mismatch for $1: got $got, want $2"; return 1; }
}

fetch_cores() {
  mkdir -p "$CACHE/xray-$XRAY_VERSION" "$CACHE/sing-box-$SINGBOX_VERSION"
  local xbin="$CACHE/xray-$XRAY_VERSION/xray"
  local sbin="$CACHE/sing-box-$SINGBOX_VERSION/sing-box"

  if [[ ! -x "$xbin" ]]; then
    log "fetching $XRAY_ASSET ($XRAY_VERSION)"
    local tmp; tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/x.zip" \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ASSET}"
    [[ -n "$XRAY_SHA" ]] && verify "$tmp/x.zip" "$XRAY_SHA"
    (cd "$tmp" && unzip -qo x.zip xray)
    install -m 0755 "$tmp/xray" "$xbin"
    rm -rf "$tmp"
  fi
  if [[ ! -x "$sbin" ]]; then
    log "fetching $SB_ASSET"
    local tmp; tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/sb.tgz" \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SB_ASSET}"
    [[ -n "$SB_SHA" ]] && verify "$tmp/sb.tgz" "$SB_SHA"
    tar -xzf "$tmp/sb.tgz" -C "$tmp" --strip-components=1 --wildcards '*/sing-box'
    install -m 0755 "$tmp/sing-box" "$sbin"
    rm -rf "$tmp"
  fi
  # The panel container runs as uid 65532 and must be able to execute these.
  chmod -R a+rX "$CACHE"
  log "cores ready: $("$xbin" version | head -1) / $("$sbin" version | head -1)"
}

fetch_cores

# ---------------------------------------------------------------------------
# 1b. can the SHIPPED image actually execute these cores?
#
# The harness runs its panel on a glibc base so every protocol is testable, but
# production ships alpine. That is exactly the kind of difference a harness must
# not paper over, so each pinned core is exec'd inside the production base image
# and the outcome is written next to the matrix for the driver to report.
# ---------------------------------------------------------------------------
PROD_BASE="$(grep -oE '^FROM alpine:[0-9.]+' "$ROOT/Dockerfile" | tail -1 | sed 's/^FROM //')"
PROD_BASE="${PROD_BASE:-alpine:3.21}"

preflight() {
  mkdir -p "$RESULTS"
  local out="$RESULTS/preflight.json"
  local entries=()
  for pair in "xray:xray-$XRAY_VERSION/xray" "sing-box:sing-box-$SINGBOX_VERSION/sing-box"; do
    local engine="${pair%%:*}" rel="${pair#*:}"
    local text rc
    text="$(docker run --rm -v "$CACHE:/cores:ro" "$PROD_BASE" \
              /cores/"$rel" version 2>&1 | head -2 || true)"
    rc="$(docker run --rm -v "$CACHE:/cores:ro" "$PROD_BASE" \
              sh -c "/cores/$rel version >/dev/null 2>&1; echo \$?" 2>/dev/null | tail -1)"
    rc="${rc:-1}"
    local ok=false; [[ "$rc" == "0" ]] && ok=true
    entries+=("$(printf '{"engine":"%s","binary":"/cores/%s","ok":%s,"exit":%s,"output":%s}' \
      "$engine" "$rel" "$ok" "$rc" "$(printf '%s' "$text" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')")")
    if [[ "$ok" == "true" ]]; then
      log "preflight: $engine runs in $PROD_BASE"
    else
      err "preflight: $engine CANNOT run in $PROD_BASE (exit $rc): $text"
    fi
  done
  printf '{"production_runtime_base":"%s","checks":[%s]}\n' \
    "$PROD_BASE" "$(IFS=,; echo "${entries[*]}")" > "$out"
}

mkdir -p "$RESULTS"
preflight

# ---------------------------------------------------------------------------
# 2. bring the stack up
# ---------------------------------------------------------------------------
export HARNESS_XRAY_VERSION="$XRAY_VERSION"
export HARNESS_SINGBOX_VERSION="$SINGBOX_VERSION"
export HARNESS_ADMIN_USER="${HARNESS_ADMIN_USER:-harness}"
export HARNESS_ADMIN_PASS="${HARNESS_ADMIN_PASS:-Harness-Probe-9143}"

rm -f "$RESULTS"/matrix.json "$RESULTS"/matrix.txt
rm -rf "$RESULTS/logs"; mkdir -p "$RESULTS/logs"

cleanup() {
  if [[ "$KEEP" == "1" ]]; then
    log "stack left running (--keep). Tear down with:"
    printf '    docker compose -f %s down -v\n' "$HERE/docker-compose.yml"
    return
  fi
  log "tearing the stack down"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "building images"
"${COMPOSE[@]}" build

log "starting panel + origin on isolated networks"
"${COMPOSE[@]}" up -d internet panel

log "waiting for the panel to answer /healthz"
for i in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T panel curl -fsS http://127.0.0.1:2053/healthz >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" == "60" ]]; then
    err "panel never became healthy"
    "${COMPOSE[@]}" logs --no-color panel | tail -40
    exit 1
  fi
  sleep 1
done

# ---------------------------------------------------------------------------
# 3. the one-time setup token, read the way the installer reads it
# ---------------------------------------------------------------------------
TOKEN="$("${COMPOSE[@]}" exec -T panel sh -c 'cat /var/lib/forgepanel/setup-token.txt 2>/dev/null || true' | tr -d '\r\n')"
if [[ -z "$TOKEN" ]]; then
  log "no setup token on disk — assuming this panel already has an administrator"
fi
export HARNESS_SETUP_TOKEN="$TOKEN"

# ---------------------------------------------------------------------------
# 4. run the driver
# ---------------------------------------------------------------------------
log "running the matrix"
set +e
"${COMPOSE[@]}" run --rm \
  -e HARNESS_SETUP_TOKEN="$TOKEN" \
  client /usr/local/bin/harness "${DRIVER_ARGS[@]}"
RC=$?
set -e

if [[ -f "$RESULTS/matrix.txt" ]]; then
  log "results: $RESULTS/matrix.json  $RESULTS/matrix.txt"
else
  err "no matrix was produced"
fi

if [[ "$RC" != "0" ]]; then
  err "harness exited $RC — see the matrix above and $RESULTS/logs/"
fi
exit "$RC"
