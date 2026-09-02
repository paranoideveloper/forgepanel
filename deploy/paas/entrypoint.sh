#!/bin/sh
# ForgePanel PaaS entrypoint.
#
# One job: put the baked cores where binmgr will find them, then exec the panel.
# Everything else — which port to bind, which hostname to publish, whether to
# serve TLS — the panel works out from the platform's own environment.
set -eu

DATA="${FORGEPANEL_DATA:-/var/lib/forgepanel}"
STAGE=/opt/forgepanel-cores

mkdir -p "$DATA/bin"

# Copy, do not symlink: the data directory is often a platform volume, and a
# symlink into the image layer survives a redeploy pointing at a core version
# the new image no longer ships.
if [ -d "$STAGE" ]; then
  for core in "$STAGE"/*; do
    [ -d "$core" ] || continue
    name=$(basename "$core")
    if [ ! -d "$DATA/bin/$name" ]; then
      cp -a "$core" "$DATA/bin/$name"
      chmod -R +x "$DATA/bin/$name" 2>/dev/null || true
      echo "forgepanel: staged core $name"
    fi
  done
fi

# A volume is what makes this deployment durable. Without one the platform gives
# the container a fresh filesystem on every deploy and restart, which throws
# away the admin account, every inbound, every user and all traffic accounting —
# and it does so silently, looking exactly like a first install. Say so once, at
# the only moment anyone is reading the logs.
#
# The check reads /proc/self/mountinfo rather than df. BusyBox df reports the
# first mount it finds for the underlying DEVICE, which inside a container is
# whatever bind-mount came first — /etc/resolv.conf, in practice — so a
# correctly mounted volume is reported as unmounted. A warning that fires when
# the operator did the right thing is worse than none: it is the reason the
# real one gets ignored. Field 5 of mountinfo is the mount point itself.
if [ ! -f "$DATA/panel.json" ] && ! awk -v d="$DATA" '$5 == d { found = 1 } END { exit !found }' /proc/self/mountinfo; then
  echo "forgepanel: WARNING — $DATA is not a mounted volume."
  echo "forgepanel: every deploy and restart will start from an empty panel — no admin account,"
  echo "forgepanel: no inbounds, no users, no traffic history. Attach a volume mounted at $DATA."
fi

exec /usr/local/bin/forgepanel "$@"
