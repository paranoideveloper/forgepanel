#!/bin/sh
# Runs after the .deb/.rpm unpacks. Record package-owned host resources before
# starting the service so the same manifest-backed uninstall works for packages
# and the verified installer.
set -e

if [ -x /usr/local/bin/forgectl ]; then
  /usr/local/bin/forgectl lifecycle record-install \
    --method package --version "${2:-package}" --data /var/lib/forgepanel \
    --resource binary:/usr/local/bin/forgepanel:true \
    --resource cli:/usr/local/bin/forgectl:true \
    --resource node:/usr/local/bin/forgenode:true \
    --resource unit:/etc/systemd/system/forgepanel.service:true \
    --resource env:/etc/forgepanel/forgepanel.env:true \
    --resource data_dir:/var/lib/forgepanel:false
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true

  if systemctl is-active --quiet forgepanel 2>/dev/null; then
    systemctl restart forgepanel >/dev/null 2>&1 || true
  else
    systemctl enable --now forgepanel >/dev/null 2>&1 || true
  fi
fi

# Open the ports the panel binds (panel UI, 80/443 for automatic TLS, 53 for
# ForgeDNS) on a managed host firewall, so the panel and Let's Encrypt work
# without a manual step. Best-effort; a missing/inactive firewall is a no-op and
# never fails the install.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "status: active"; then
  for p in 2053 80 443 53; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  ufw allow 53/udp >/dev/null 2>&1 || true
  ufw allow 443/udp >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for p in 2053 80 443 53; do firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true; done
  firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

cat <<'EOF'

ForgePanel installed.

  Status:   systemctl status forgepanel
  Logs:     journalctl -u forgepanel -f
  Data dir: /var/lib/forgepanel
  Settings: sudo forgectl settings show

The first-boot admin URL and credentials are printed once in the service log.

EOF

exit 0
