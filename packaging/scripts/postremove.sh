#!/bin/sh
# Reload systemd once the unit file is gone. /var/lib/forgepanel is left in
# place on purpose — removing the package must not destroy user data.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
