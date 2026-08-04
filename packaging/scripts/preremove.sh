#!/bin/sh
# Stop and disable the unit before the files disappear. Skipped on upgrades so
# the service is not needlessly interrupted.
set -e

# deb passes "upgrade"/"remove"; rpm passes 1 (upgrade) or 0 (uninstall).
case "${1:-}" in
  upgrade|1) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop forgepanel >/dev/null 2>&1 || true
  systemctl disable forgepanel >/dev/null 2>&1 || true
fi

exit 0
