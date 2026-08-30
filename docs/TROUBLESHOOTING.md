# Troubleshooting

**Panel path or credentials are lost.** The admin path is in
`<data>/panel.json`. Reset a password or 2FA locally without exposing a secret
on the command line:

```
sudo forgectl admin reset-password --user admin
sudo forgectl admin reset-2fa --user admin
sudo forgectl admin regenerate-path
```

**A port or address change made the panel unavailable.** The web UI and
`forgectl settings set` save a rollback copy before restarting the service. A
failed restart restores the previous settings. Inspect the service with
`sudo forgectl status` and `journalctl -u forgepanel -e`; use
`sudo forgectl repair` for a recorded installation.

**A package or installer uninstall retained files.** This is intentional when
a file changed after ForgePanel installed it or an older install has no manifest.
Run `sudo forgectl uninstall --dry-run` to see the ownership evidence. Do not
delete the listed files blindly; preserve the data directory unless an explicit
`--purge --yes` is appropriate.

**An engine shows `invalid_config`.** The panel never applies a config the core
rejects. Open `GET /api/admin/engines/config` to see the generated config and the
core's rejection reason. Common causes: a REALITY inbound on a non-443 port
(warning only), a port already in use, or a missing SNI.

**An engine shows `unresponsive`.** The process is alive but stopped answering
its own local API, which the panel probes every 30s and acts on after three
consecutive failures — a core that wedges never exits, so before this it was
reported as `running` while it served nobody. `last_probe_error` in
`GET /api/admin/engines/status` carries the reason: `connection refused` means
the core never bound its API port (it accepted the config and then failed to
finish starting), while a timeout means it is up and stuck, usually on a box
under memory pressure. sing-box is only probed when the installed binary was
built with `with_v2ray_api`; a stock build has no stats API to answer and is
never marked unresponsive for the lack of one.

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
go1.25-compatible versions; run `go mod tidy` with go1.25 and keep the `go 1.25`
directive.
