#!/usr/bin/env bash
# ForgePanel installer — downloads the latest release binary, installs a systemd
# service, starts it, and prints the admin URL + credentials.
#
#   curl -fsSL https://raw.githubusercontent.com/paranoideveloper/forgepanel/main/install.sh | sudo bash
#
set -euo pipefail

REPO="paranoideveloper/forgepanel"
BIN=/usr/local/bin/forgepanel
DATA=/var/lib/forgepanel
UNIT=/etc/systemd/system/forgepanel.service

if [ "$(id -u)" != "0" ]; then echo "Please run as root (sudo)." >&2; exit 1; fi

# --- detect arch ---
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
OS=linux

echo ">> Resolving latest ForgePanel release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4 || true)
if [ -z "${TAG:-}" ]; then echo "Could not find a release. Is one published yet?" >&2; exit 1; fi
ASSET="forgepanel-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

echo ">> Downloading ${ASSET} (${TAG})..."
curl -fsSL -o "$BIN" "$URL" || { echo "Download failed: $URL" >&2; exit 1; }
chmod +x "$BIN"
mkdir -p "$DATA"

echo ">> Installing systemd service..."
cat > "$UNIT" <<UNITEOF
[Unit]
Description=ForgePanel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN}
WorkingDirectory=${DATA}
Environment=FORGEPANEL_DATA=${DATA}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now forgepanel

echo ">> Waiting for first boot..."
sleep 3
echo
echo "========================================================================"
echo " ForgePanel is installed and running (systemd service: forgepanel)."
echo
echo " First-boot admin URL + password are in the service log:"
echo "     journalctl -u forgepanel --no-pager | grep -A3 -i 'admin'"
echo
journalctl -u forgepanel --no-pager 2>/dev/null | grep -iE 'panel|admin|password|http://' | tail -n 6 || true
echo "========================================================================"
echo " Manage it with:  systemctl {status|restart|stop} forgepanel"
echo " Data dir:        ${DATA}"
echo " Tip: put it behind Caddy/Nginx with TLS before real use."
