#!/usr/bin/env bash
# Compatibility entry point. Keep all host installation, repair, upgrade and
# uninstall behaviour in the repository-root installer.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec "$root/install.sh" "$@"
