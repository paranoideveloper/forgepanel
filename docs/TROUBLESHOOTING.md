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

Check the delegation with a direct apex query, which must answer `NOERROR` with
records — not `NXDOMAIN`:

```
dig @<server-ip> t.example.com SOA +norecurse
dig @<server-ip> t.example.com NS  +norecurse
```

The `NS` name the server returns must match the record you created at the
registrar. Both are derived from the **registrable** domain, so zone
`t.example.com` uses `ns1.example.com`.

A name *under* the zone that is not decodable tunnel traffic answers `NXDOMAIN`
by design; a zone we do not serve answers `REFUSED`. If an apex query returns
`REFUSED`, the zone is not registered on this server at all — check that it is
enabled in the panel.

**ForgeDNS zone won't restart: "address already in use".** The panel now waits
for a zone's process to fully exit before starting its replacement, so a
persistent bind failure means something *else* owns the port. The error names the
holder when it can identify it. ForgePanel deliberately never signals a process
it did not start — killing an unknown PID could take down `systemd-resolved`,
another resolver, or a second panel instance. Stop the holder yourself, or bind
the zone to a different address or port:

```
sudo ss -ulpn 'sport = :53'
```

On a systemd host the usual answer is `systemd-resolved`: set
`DNSStubListener=no` in `/etc/systemd/resolved.conf`, or bind the zone to the
public IP instead of `0.0.0.0`.

**A ForgeDNS zone edit rolled itself back.** If a new config fails to start
within its settle window, the panel restores the previous working config and
restarts that instead, rather than leaving the zone down in a crash-loop. The
zone's `last_error` and recent logs say what the new config did wrong.

**Subscription is empty.** The user's group must bind at least one enabled
inbound, and the user must be `active` (not limited/expired/disabled).

**Build fails with "requires go >= 1.25".** Dependencies are pinned to
go1.24-compatible versions; run `go mod tidy` with go1.24 and keep the `go 1.24`
directive.
