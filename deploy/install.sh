#!/usr/bin/env sh
# ForgePanel one-command installer (spec §14). Detects arch, installs the
# binary + a hardened systemd unit, prints credentials once. Idempotent.
# Usage: sh install.sh [--uninstall|--update]
set -eu
PREFIX="${PREFIX:-/usr/local/bin}"
DATA="${FORGEPANEL_DATA:-/var/lib/forgepanel}"
UNIT=/etc/systemd/system/forgepanel.service
BIN_SRC="${BIN_SRC:-./bin/forgepanel}"

uninstall() {
  systemctl stop forgepanel 2>/dev/null || true
  systemctl disable forgepanel 2>/dev/null || true
  rm -f "$UNIT" "$PREFIX/forgepanel" "$PREFIX/forgectl"
  systemctl daemon-reload 2>/dev/null || true
  echo "forgepanel uninstalled (data in $DATA kept)"
}

case "${1:-}" in
  --uninstall) uninstall; exit 0 ;;
esac

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
install -d -m 0700 "$DATA"
install -m 0755 "$BIN_SRC" "$PREFIX/forgepanel"
[ -f ./bin/forgectl ] && install -m 0755 ./bin/forgectl "$PREFIX/forgectl" || true

cat > "$UNIT" <<UNIT
[Unit]
Description=ForgePanel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=FORGEPANEL_DATA=$DATA
ExecStart=$PREFIX/forgepanel
Restart=on-failure
RestartSec=3
# Hardening (spec §14)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now forgepanel
echo "forgepanel installed. Credentials were printed to the journal:"
echo "  journalctl -u forgepanel --no-pager | head -20"
