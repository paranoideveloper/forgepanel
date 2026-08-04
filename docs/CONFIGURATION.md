# Configuration

All configuration is via environment variables (sane defaults applied at boot).

| Variable | Default | Purpose |
|---|---|---|
| `FORGEPANEL_DATA` | `~/.forgepanel` | data + secrets dir (mode 0700) |
| `FORGEPANEL_PANEL_PORT` | `2053` | HTTPS panel port |
| `FORGEPANEL_SUB_PORT` | `2096` | subscription port |
| `FORGEPANEL_API_PORT` | `2054` | REST API port |
| `FORGEPANEL_DNS_PORT` | `53` | ForgeDNS authoritative listener (udp) |
| `FORGEPANEL_ADMIN_USER` | `admin` | initial admin username |

Secrets (admin path, master key) are generated on first boot into
`<data>/secrets.json` and never leave the machine. The master key derives the JWT
signing secret and the backup-encryption key.

Engine binaries are downloaded and pinned into `<data>/bin/` on first use; the
SQLite database is `<data>/forgepanel.db`.
