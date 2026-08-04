#!/bin/sh
# Runs after the .deb/.rpm unpacks. Enables the unit on first install and
# restarts it on upgrade; never fails the package transaction.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true

  if systemctl is-active --quiet forgepanel 2>/dev/null; then
    systemctl restart forgepanel >/dev/null 2>&1 || true
  else
    systemctl enable --now forgepanel >/dev/null 2>&1 || true
  fi
fi

cat <<'EOF'

ForgePanel installed.

  Status:   systemctl status forgepanel
  Logs:     journalctl -u forgepanel -f
  Data dir: /var/lib/forgepanel
  Config:   /etc/forgepanel/forgepanel.env   (optional overrides)

The first-boot admin URL and credentials are printed once in the service log.

EOF

exit 0
