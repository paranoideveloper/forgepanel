# Troubleshooting

**Panel prints credentials only once.** They are in `<data>/secrets.json`
(admin path) and were shown at first boot. Lost the password? Delete the admin
row and restart to re-seed, or reset via `forgectl` (roadmap).

**An engine shows `invalid_config`.** The panel never applies a config the core
rejects. Open `GET /api/admin/engines/config` to see the generated config and the
core's rejection reason. Common causes: a REALITY inbound on a non-443 port
(warning only), a port already in use, or a missing SNI.

**ForgeDNS listener won't bind :53.** Port 53 needs `CAP_NET_BIND_SERVICE` (the
systemd unit and Docker grant it) or root. Set `FORGEPANEL_DNS_PORT` to a high
port for testing.

**ForgeDNS tunnel resolves NXDOMAIN.** The zone must be delegated to this server:
use the Setup panel to get the glue/NS records, add them at your registrar, and
wait for propagation. The panel is authoritative only for zones you created.

**Subscription is empty.** The user's group must bind at least one enabled
inbound, and the user must be `active` (not limited/expired/disabled).

**Build fails with "requires go >= 1.25".** Dependencies are pinned to
go1.24-compatible versions; run `go mod tidy` with go1.24 and keep the `go 1.24`
directive.
