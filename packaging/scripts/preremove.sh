#!/bin/sh
# Stop and disable the unit before the files disappear. Skipped on upgrades so
# the service is not needlessly interrupted.
set -e

# deb passes "upgrade"/"remove"; rpm passes 1 (upgrade) or 0 (uninstall).
case "${1:-}" in
  upgrade|1) exit 0 ;;
esac

if [ -x /usr/local/bin/forgectl ]; then
  /usr/local/bin/forgectl uninstall --keep-data --yes
elif command -v systemctl >/dev/null 2>&1; then
  # Legacy fallback: never infer file ownership or delete paths without the
  # lifecycle command; only stop the known service.
  systemctl stop forgepanel >/dev/null 2>&1 || true
  systemctl disable forgepanel >/dev/null 2>&1 || true
fi

exit 0
