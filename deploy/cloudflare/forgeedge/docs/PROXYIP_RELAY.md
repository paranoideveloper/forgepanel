# Reaching Cloudflare-hosted destinations (proxyIP relay)

A Cloudflare Worker's `connect()` to a **Cloudflare-owned IP is refused**. Since a
large slice of the web sits behind Cloudflare, those destinations are unreachable
*through the edge* unless the Worker relays them via a host that is **not** on
Cloudflare's network.

ForgeEdge has two escape hatches (both in `src/protocols/retry.ts`, and only used
when a direct connection returns zero bytes — so non-CF traffic is untouched):

- **`nat64`** — dial an IPv6 literal a public NAT64 gateway translates back. Zero
  infrastructure, but the *public* gateways are unreliable (measured ~25% success,
  ~19 s hangs otherwise), so it is **off by default**. Only worth it with a
  gateway you trust.
- **`proxyip`** — relay through a host you run. This is the reliable option.

## The reliable option: an SNI-routing relay

Run a tiny SNI proxy on any non-Cloudflare box with a public IP and an open port.
It peeks the TLS ClientHello's SNI and forwards the raw stream to `<SNI>:443` —
it terminates nothing, so it needs no certificate.

With [gost](https://github.com/go-gost/gost) v3:

```ini
# /etc/systemd/system/gost-sni-relay.service
[Unit]
Description=gost SNI relay for ForgeEdge proxyIP
After=network.target
[Service]
ExecStart=/usr/local/bin/gost -L sni://:15443
Restart=always
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now gost-sni-relay
# verify it routes by SNI (should return the destination's real cert):
echo | openssl s_client -connect <relay-ip>:15443 -servername www.cloudflare.com 2>/dev/null | grep 'CN ='
```

Then point the Worker at it — in the panel config, or directly in KV
`forgeedge:config`:

```json
{ "proxyIPMode": "proxyip", "proxyIPs": ["<relay-ip>:15443"] }
```

The Worker connects to `<relay-ip>:15443`, sends the client's ClientHello, and the
relay forwards it to the real destination. `Worker → relay` and `relay → CF` are
both ordinary connections; only `Worker → CF-IP` is the refused one.

Verified: with the relay configured, `https://www.cloudflare.com/` returns 200 in
~0.5 s through the edge (vs. a hang/failure without it), while non-CF traffic
still egresses directly.

> The default ships `proxyIPs: []` / `proxyIPMode: 'off'` deliberately — a relay
> is operator infrastructure, not something to hardcode for everyone.
