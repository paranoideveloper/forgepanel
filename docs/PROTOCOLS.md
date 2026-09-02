# Protocols

Every protocol ForgePanel supports is a first-class member of the canonical
model in `internal/protocol/model`. This document walks through all fourteen:
what each one is, which fields of `model.Node` it uses, what `Validate()`
enforces, what `Normalize()` does to it, and which engine runs it.

Two model-wide behaviours apply throughout and are worth stating once.

**Field relevance is enforced, not assumed.** `Normalize()` clears every field
that is not meaningful for the selected protocol. A Trojan node cannot retain a
`UUID` left over from an earlier edit; a VMess node cannot retain a `Password`.
The tables below list the fields each protocol *keeps* — everything else is
zeroed.

**Transport applies to six protocols only.** `Protocol.UsesTransport()` is true
for VLESS, VMess, Trojan, Shadowsocks, SOCKS and HTTP. Those six layer over the
orthogonal transport (`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `h2`, `mkcp`,
`quic`) and security (`none`, `tls`, `reality`) stack. The other eight carry
their own wire format, and `Normalize()` forces their `Transport` to the
canonical zero value (`{Network: tcp}`) so that equality stays well defined.

---

## Transport and security layers

Before the protocols themselves, the two layers they share.

### Transports

`tcp` is the base case and the only transport under which VLESS's XTLS Vision
flow is meaningful. It optionally carries HTTP header obfuscation
(`HeaderObfs.Type = "http"`) with a spoofed Host and path, which makes the stream
resemble plain HTTP to a shallow inspector.

`ws` (WebSocket) is the CDN workhorse: it takes a `Path`, a `Host` header,
arbitrary extra `Headers`, and WebSocket early data via `EarlyData` (the `ed=`
parameter) with a configurable `EDHeader` name. `httpupgrade` is the lighter
sibling — the same HTTP Upgrade handshake without the WebSocket framing
overhead — and takes the same path/host fields.

`grpc` uses `ServiceName` as its path equivalent, `MultiMode` to select gun
versus multi mode, plus `IdleTimeout`, `HealthCheck`, `InitialWindows` and
`PermitWithout` for connection tuning.

`xhttp` (formerly `splithttp`; `Normalize()` rewrites the legacy name) splits
upload and download across separate HTTP requests, which survives CDNs and
middleboxes that break long-lived connections. `XHTTPMode` selects `auto`,
`packet-up`, `stream-up` or `stream-one`; `XPaddingB` sets the padding byte
range; `XMux` carries multiplexing parameters (max concurrency, max connections,
connection reuse and lifetime limits, request-time limits, keepalive period).

`h2` is HTTP/2 with a path and a host list. `mkcp` is a UDP-based reliable
transport with a `Seed`, MTU/TTI tuning, uplink and downlink capacity hints,
congestion control and buffer sizes, plus the full header-obfuscation set
(`none`, `srtp`, `utp`, `wechat-video`, `dtls`, `wireguard`). `quic` takes a
`QUICSecurity` cipher (`none`, `aes-128-gcm`, `chacha20-poly1305`), a `QUICKey`
and a header type.

`Transport.clearIrrelevant()` keeps only the fields belonging to the selected
network, which is why a node switched from `grpc` to `ws` cannot smuggle a stale
`ServiceName` into its exported link.

### Security

`none` means no TLS layer. `Normalize()` collapses the whole `Security` struct to
`{Type: none}` so that leftover SNI or ALPN values cannot affect equality.

`tls` is standard TLS, with `ServerName` (SNI), `ALPN` (sorted during
normalization for deterministic export), `Fingerprint` (a uTLS profile from the
validated set `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`,
`qq`, `random`, `randomized` — anything else is a validation error),
`AllowInsecure`, min/max version, cipher suites, certificate and key file paths,
and `PinSHA256` for certificate pinning. Optional ECH (Encrypted Client Hello)
carries a base64 `ConfigList` or an `AutoFetch` flag that resolves it from the
DNS HTTPS resource record.

`reality` is REALITY, which borrows a real third-party TLS server's certificate
chain for the visible portion of the handshake. `Dest` is the borrowed target,
`ServerNames` the SNIs accepted for it, `PrivateKey` the server secret,
`PublicKey` the client-side value, `ShortIDs` the set of valid short
identifiers with `ShortID` the one selected for a given client link, `SpiderX`
the crawler path (defaulting to `/`), and `Xver` the PROXY-protocol version.
`MLDSA65Seed` and `MLDSA65Verify` carry post-quantum authentication and are
empty — meaning disabled — by default; see
[DECISIONS.md ADR-007](DECISIONS.md#adr-007-ml-dsa-65-post-quantum-reality-keys-are-generated-but-default-off).

Validation is strict here because REALITY misconfiguration is a common and
confusing failure: a REALITY node must have a public or private key, must have a
`Dest` or at least one server name, and every shortId must be even-length
lowercase-or-uppercase hex of at most 16 characters (8 bytes). Normalization
sorts `ServerNames` and `ShortIDs`, defaults `SpiderX` to `/`, adopts the single
server name as the SNI when no explicit SNI is set, clears `ECH` (REALITY
performs its own handshake), and forces `AllowInsecure` to false — there is no
coherent meaning for "skip verification" when the entire point is borrowing a
verifiable chain.

---

## Per-user traffic accounting: which protocols are covered

Every protocol below is rendered with a stable, opaque per-user identifier
(`u<ID>`, resolved back through the panel database — never a contact address, and
never the client's UUID or password, both of which would then appear in engine
logs). That identifier is what makes traffic attributable to one user rather than
to the inbound as a whole.

**Xray-served protocols** — VLESS, VMess, Trojan, Shadowsocks, SOCKS and HTTP —
are read via `xray api statsquery`. Quota enforcement and traffic resets work
for those.

**sing-box-served protocols** — Hysteria2, TUIC, AnyTLS and ShadowTLS — are
metered too, but only on a build that carries `with_v2ray_api`. Per-user totals
come from `experimental.v2ray_api`, and the **official sing-box release archives
are not built with it**: starting one fails with `v2ray api is not included in
this build`. `clash_api`, which official builds do include, reports live
connections rather than cumulative totals, so polling it would miss every
connection that closed between polls — quotas would appear enforced while
silently leaking traffic, which is worse than reporting nothing because the
failure is invisible.

So ForgePanel builds its own sing-box (`scripts/build-singbox.sh`): the same
pinned upstream version, the official tag set plus that one tag, built with
`-trimpath` and a pinned toolchain so two independent builds are byte-identical.
The release ships it beside the panel binary and `binmgr` adopts it after
verifying it against a pinned checksum.

**When that build is absent the panel still runs**, on the upstream archive,
and those protocols are simply unmetered — a deliberate fallback rather than a
failure, since refusing to start would be a worse trade for an operator who
does not sell metered plans. The "Traffic metering" health subsystem says which
of the two is in use, so the state is never silent.

Practical consequence: **check the Traffic metering health row before relying on
quotas for users whose only inbound is Hysteria2, TUIC, AnyTLS or ShadowTLS.**
Expiry and enable/disable apply to them regardless, since those do not depend on
counters.

WireGuard and AmneziaWG are not in either list: both are served by a kernel
interface rather than a supervised core, and their accounting comes from the
interface counters.

---

## VLESS

**Canonical ID** `vless` · **Engine** Xray · **Uses transport** yes

VLESS is a stateless, encryption-free transport protocol: it carries only
identity and routing, and delegates confidentiality entirely to the TLS or
REALITY layer beneath it. That minimalism is the point — there is no protocol
overhead to fingerprint, and no redundant encryption on top of TLS. It is the
default choice for most modern deployments and the only protocol that supports
XTLS Vision.

**Required:** `UUID`. **Optional:** `Flow`, which must be either empty or
`xtls-rprx-vision` — any other value is a validation error. `Encryption`
defaults to `none` during normalization and is the field through which
post-quantum ML-KEM-768 key exchange is configured on Xray builds that support
it.

Vision is the flow-control mechanism that avoids TLS-in-TLS by splicing the
inner stream directly once the handshake is complete, which both improves
throughput and removes the distinctive nested-TLS record pattern. It only works
over raw TCP. `Normalize()` therefore clears `Flow` whenever the network is not
`tcp`, rather than exporting a link that clients will fail on for reasons the
user cannot see.

`Password`, `Username` and `AlterID` are cleared. Exported as
`vless://uuid@host:port?<transport+security params>#remark`.

---

## VMess

**Canonical ID** `vmess` · **Engine** Xray · **Uses transport** yes

VMess is the original V2Ray protocol. It provides its own authenticated
encryption, which means it can run without TLS, but that also gives it a
distinguishable handshake — the reason newer deployments prefer VLESS behind
REALITY. It remains important for client compatibility and for legacy
subscriptions being imported.

**Required:** `UUID`. `AlterID` is forced to `0` by normalization: alterId > 0
selects the legacy pre-AEAD MD5 authentication scheme, which is deprecated,
removed from current cores, and actively detectable. ForgePanel only speaks
VMessAEAD. `Encryption` (the `security` field in VMess terminology) defaults to
`auto` and may be `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`.

`Password` and `Username` are cleared. Exported in the interoperable "v2rayN"
format: `vmess://` followed by base64 of a JSON object with the widely
implemented v2 schema (`v`, `ps`, `add`, `port`, `id`, `aid`, `scy`, `net`,
`type`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, and `pbk`/`sid` for REALITY).
Note the field overloading that format imposes: for gRPC, `path` carries the
service name and `type` carries the mode; for mKCP, `path` carries the seed and
`type` the header obfuscation. The parser inverts this exactly, which is what
keeps the round-trip property intact.

---

## Trojan

**Canonical ID** `trojan` · **Engine** Xray · **Uses transport** yes

Trojan hides in plain sight by imitating an ordinary HTTPS server. A client
authenticates with a password inside a normal TLS session; a probe that connects
without the correct password is served whatever the fallback web server serves.
To an active prober, the endpoint is indistinguishable from a website. It is
simple, mature and widely supported.

**Required:** `Password`. **Optional:** `Flow` for XTLS variants where the core
supports it, and fallback targets configured at the inbound level.

`UUID`, `Username`, `Encryption` and `AlterID` are cleared. Trojan defaults to
TLS; the exporter still writes the explicit `security` parameter so that the
round-trip is exact rather than dependent on a default. It also supports
CDN-plain deployments (`security=none` behind a CDN that terminates TLS itself)
over `tcp`, `ws`, `grpc`, `xhttp` and `httpupgrade`. Exported as
`trojan://password@host:port?<params>#remark` with the password URL-escaped, so
passwords containing spaces or punctuation survive.

---

## Shadowsocks

**Canonical ID** `shadowsocks` · **Engine** Xray · **Uses transport** yes

Shadowsocks is the oldest protocol here and still one of the most useful: a thin
AEAD-encrypted SOCKS-like tunnel with no handshake to fingerprint. Modern
deployments should use the SIP022 "2022-blake3" family, which fixes the replay
and active-probing weaknesses of the original AEAD ciphers.

**Required:** `Method` and, unless the method is `none`, `Password`. Eight
methods are supported:

| Method | Key size | Family |
|---|---|---|
| `2022-blake3-aes-128-gcm` | 16 bytes | SIP022 |
| `2022-blake3-aes-256-gcm` | 32 bytes | SIP022 |
| `2022-blake3-chacha20-poly1305` | 32 bytes | SIP022 |
| `aes-256-gcm` | 32 bytes | AEAD (legacy) |
| `aes-128-gcm` | 16 bytes | AEAD (legacy) |
| `chacha20-ietf-poly1305` | 32 bytes | AEAD (legacy) |
| `xchacha20-ietf-poly1305` | 32 bytes | AEAD (legacy) |
| `none` | — | plaintext, for use behind another encrypted layer |

For the SIP022 methods the password is not a passphrase — it is a **base64 PSK
whose decoded length must equal the cipher key size exactly**. This is the single
most common real-world Shadowsocks misconfiguration, so `Validate()` treats it as
a hard error rather than a warning. Multi-user SS2022 uses Extensible Identity
Headers with a `serverPSK:userPSK` composite; validation splits on `:` and checks
every segment's decoded length independently. `keygen.SS2022PSK(method)` produces
a correctly sized PSK and refuses to generate one for a non-SIP022 method.

Base64 is accepted in all four variants — standard and URL-safe, padded and
unpadded — because client apps emit all four.

**Optional:** a SIP003 plugin via `SSPlugin`, with `Name` (`v2ray-plugin`,
`obfs-local`, `shadow-tls`) and an opaque `Opts` string.

`UUID`, `Username`, `Flow`, `Encryption` and `AlterID` are cleared. Exported in
SIP002 form: `ss://base64url(method:password)@host:port?plugin=...#remark`.

---

## SOCKS

**Canonical ID** `socks` · **Engine** Xray · **Uses transport** yes

SOCKS5 with no encryption of its own. It is not a censorship-circumvention
protocol; it is the local interface between an application and a tunnel, the
egress of a chain, or a link between servers over an already-secure path.

**Optional:** `Username` and `Password`. Credentials are genuinely optional —
an open SOCKS proxy is a valid configuration and sometimes the correct one on a
loopback or private interface — so `Validate()` permits it. Config Doctor raises
a finding when an unauthenticated SOCKS inbound is bound to a public address,
because in that position it is an open relay that will be found and abused.

UDP-over-TCP is available where the engine supports it. `UUID`, `Flow`,
`Encryption` and `AlterID` are cleared. Exported as
`socks://base64url(user:pass)@host:port#remark`, with the userinfo section
omitted entirely when there are no credentials.

---

## HTTP

**Canonical ID** `http` · **Engine** Xray · **Uses transport** yes

An HTTP CONNECT proxy, optionally wrapped in TLS. Same role as SOCKS: a local
interface or a chain link, not a circumvention protocol on its own. It exists
here because some clients and corporate environments speak only HTTP proxy, and
because an HTTPS proxy is occasionally the least conspicuous option on a network
where that is exactly what is expected.

**Optional:** `Username` and `Password`, same reasoning as SOCKS. `UUID`, `Flow`,
`Encryption` and `AlterID` are cleared. Exported with the scheme reflecting the
security layer — `https://` when TLS is enabled, `http://` otherwise — as
`scheme://user:pass@host:port#remark`.

---

## Hysteria2

**Canonical ID** `hysteria2` · **Engine** sing-box · **Uses transport** no

Hysteria2 runs over QUIC with an aggressive Brutal-style congestion controller,
which makes it dramatically faster than TCP-based protocols on lossy,
long-latency or actively-degraded paths. It is the protocol of choice where the
network is not blocking you outright but is making TCP unusable through packet
loss and throttling.

**Required:** `Password`. Because it is QUIC-based, `Protocol.IsQUICBased()` is
true, so normalization forces TLS (a QUIC connection without TLS is not a thing)
and defaults `ALPN` to `["h3"]`.

**Optional, via `Hysteria2Options`:**

`ObfsType` — currently only `salamander` — with `ObfsPassword` applies a
lightweight obfuscation layer over the QUIC packets so the connection does not
present a recognizable QUIC handshake. `UpMbps` and `DownMbps` declare the
client's bandwidth to the congestion controller, and `IgnoreClientBandwidth`
tells the server to disregard those declarations and use its own values.

`PortHopping` is Hysteria2's signature anti-blocking feature: a range such as
`20000-50000` across which the client rotates its destination port every
`PortHopInterval` seconds. Blocking a single port accomplishes nothing, and the
traffic pattern does not present a stable flow to per-port rate limiting. The
server must have the whole range forwarded to its listener, which is exactly the
kind of thing Config Doctor checks for collisions with other services.

`MasqueradeType` (`proxy`, `file` or `string`) with `MasqueradeURL` controls what
an unauthenticated HTTP/3 request to the endpoint receives — a reverse proxy to a
real site, a static file tree, or a fixed string. This is the active-probing
defence: a prober sees a plausible web server, not a refused connection.
`BrutalCC` selects the Brutal congestion controller explicitly.

Certificate pinning through `Security.PinSHA256` is common with Hysteria2, since
many deployments use a self-signed certificate plus a pin rather than a
CA-issued one. Exported as
`hysteria2://password@host:port?obfs=&obfs-password=&mport=&hop_interval=&up=&down=&sni=&insecure=&pinSHA256=#remark`.

---

## TUIC

**Canonical ID** `tuic` · **Engine** sing-box · **Uses transport** no

TUIC v5 is the other QUIC-based protocol here, with a different emphasis from
Hysteria2: rather than maximizing throughput on degraded links, it minimizes
handshake latency and provides genuinely good UDP relaying, which matters for
gaming, voice and video traffic that Shadowsocks-style UDP-over-TCP handles
badly.

**Required:** both `UUID` **and** `Password`. TUIC uses a two-part credential and
`Validate()` rejects a node with only one of them — a distinct failure from
every other protocol here, and one users hit when copying a link by hand.

**Optional, via `TUICOptions`:** `CongestionControl` (`bbr`, `cubic` or
`new_reno`; normalization defaults to `bbr`), `UDPRelayMode` (`native` sends UDP
as QUIC datagrams for lowest latency, `quic` sends it over reliable streams for
correctness on paths that drop datagrams; defaults to `native`),
`ZeroRTTHandshake` to allow 0-RTT resumption at the cost of replay protection,
`HeartbeatSeconds` for keepalive, and `DisableSNI`.

As with Hysteria2, TLS is forced and `ALPN` defaults to `["h3"]`. `Username`,
`Flow`, `Encryption` and `AlterID` are cleared. Exported as
`tuic://uuid:password@host:port?congestion_control=&udp_relay_mode=&sni=&alpn=&allow_insecure=#remark`.

---

## AnyTLS

**Canonical ID** `anytls` · **Engine** sing-box · **Uses transport** no

AnyTLS is a recent protocol built specifically to defeat traffic-analysis
classifiers. Rather than hiding *what* the protocol is, it attacks the packet
size and timing distribution that machine-learning classifiers rely on, using a
configurable padding scheme and long-lived session reuse to keep the observable
pattern away from the signature of a proxy.

**Required:** `Password`. **Optional, via `AnyTLSOptions`:** `PaddingScheme`, a
list of rules describing how much padding to apply to which packets in a session
(the default scheme is tuned for TLS-like distributions; custom schemes let an
operator adapt to a specific classifier); `IdleSessionCheckInterval` and
`IdleSessionTimeout` controlling how long unused sessions are held open; and
`MinIdleSessions`, the number of warm sessions kept ready so a new connection
does not pay handshake latency and does not create the burst of new-connection
events that classifiers notice.

`UUID`, `Username`, `Flow`, `Encryption` and `AlterID` are cleared. Exported as
`anytls://password@host:port?<transport+security params>&padding_scheme=#remark`,
with the padding scheme newline-joined.

---

## WireGuard

**Canonical ID** `wireguard` · **Engine** kernel-wg, falling back to sing-box ·
**Uses transport** no

WireGuard is a full VPN rather than an application proxy: a modern, small, fast
kernel-or-userspace tunnel with excellent cryptography and no obfuscation
whatsoever. Its handshake is trivially identifiable and it is blocked wherever
blocking is systematic. It serves as an inbound, as a chained outbound, and as
the transport for Cloudflare WARP.

**Which datapath serves it.** sing-box's `wireguard` endpoint is an *outbound*
construct. As a server it completes a handshake and answers traffic addressed to
its own tunnel address — so it looks alive, and a client can even ping the
gateway — but it forwards nothing onward. So an inbound is served by `wg-quick`
and the in-tree `wireguard` module wherever the host can run them, which is also
about three times faster: 2.2–2.5 Gbit/s against 0.75–0.85 for the userspace
path, measured on one box with the same client and destination. A host with
neither the module nor `wireguard-tools` still gets the sing-box endpoint, and
the Engines page reports which is serving. `Node.Engine` overrides the choice
per inbound.

**Egress.** The generated server config installs its own NAT (`PostUp`
MASQUERADE on the tunnel's own source prefix, the two FORWARD accepts, and
`ip_forward`), removing exactly that on `PostDown`. Without it the tunnel
handshakes, answers a ping to the gateway, and reaches nothing: every forwarded
packet leaves the box with a private source address.

**Addressing.** Each inbound is allocated the next free `/24` from `10.66.`,
skipping anything another inbound holds — WireGuard and AmneziaWG are checked
together, since two inbounds on one prefix collide whatever their protocol. The
first WireGuard inbound keeps `10.66.66.0/24`, so an upgrade never moves a
tunnel whose config has already been handed out. Per-user peer addresses come
from the pool in `internal/wgpeer`.

The exported client config offers only the address families the tunnel actually
has an address for: advertising `::/0` on an IPv4-only tunnel makes a dual-stack
client route IPv6 into an interface with no IPv6 address and blackhole every
AAAA destination — invisible on an IPv4-only test host, severe on a phone.

**Required:** `WireGuardOptions.PrivateKey` (local) and `PublicKey` (peer).
`Validate()` rejects a node missing either.

**Optional:** `PreSharedKey` for the additional symmetric layer; `LocalAddress`,
the tunnel-internal addresses assigned to this peer; `AllowedIPs`, defaulting to
`0.0.0.0/0` and `::/0` when unset; `Keepalive` for NAT traversal; `Workers` for
userspace parallelism.

`MTU` defaults to 1420 during normalization and is validated to 576–1500.
Getting MTU wrong is the classic WireGuard failure: the tunnel establishes,
small packets flow, and anything large — a TLS handshake, a file download —
hangs, because fragmentation is being dropped somewhere on the path. Config
Doctor probes for this rather than trusting the configured value.

`Reserved` is three bytes and exists for **Cloudflare WARP**: WARP's WireGuard
implementation uses those reserved header bytes for client identification, and a
WARP endpoint will not respond correctly without them. `Validate()` requires the
field to be empty or exactly three elements. This is what makes the planned
one-click WARP outbound generator possible.

`UUID`, `Password`, `Username`, `Flow`, `Encryption` and `AlterID` are cleared.
Exported as
`wireguard://privatekey@host:port?publickey=&presharedkey=&address=&mtu=&reserved=#remark`,
and — because a link is not what these clients import — as a native `wg-quick`
`.conf` from `/subconf/<token>/<n>`, carrying the CLIENT's private key and never
the server's.

---

## AmneziaWG

**Canonical ID** `amneziawg` · **Engine** amneziawg (kernel) · **Uses transport** no

AmneziaWG is WireGuard plus obfuscation: the same cryptography and datapath,
with the handshake and packet shapes altered so the trivially identifiable
WireGuard fingerprint is gone. It is the protocol to reach for where WireGuard
itself is blocked by DPI rather than by address.

It runs through the real [`amneziawg` kernel
module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) +
`awg-quick`, not a userspace shim, so it runs at kernel speed. The host needs
`amneziawg` and `amneziawg-tools` (`ppa:amnezia/ppa` on Ubuntu, plus
`linux-headers-$(uname -r)` for the DKMS build). Until they are installed the
panel still writes the configs and reports the shortfall in engine status rather
than presenting an inbound that cannot serve.

**Generations.** The parameters are two-sided: a key from a newer generation in
a config whose peer speaks an older one does not degrade, it stops the
handshake. So the generation is selected per inbound and only that generation's
keys are written.

| Generation | Adds |
|---|---|
| `1.5` | `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4` |
| `2.0` | `S3`, `S4`, the `I1`–`I3` custom junk packets, and H-value *ranges* (`1500000000-1500999999`) |
| `3.0` | `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, peer-level `AdvancedSecurity` |
| `3.1` | `RandomTrailers`, `DisableCookies` |

Two constraints are enforced because the module reports them with errors that
name no field: `H1`–`H4` must fit in a uint32 (`awg-quick` says only
"Configuration parsing error", with no line number), and `HeaderProtectionKey`
requires `S3` and `S4` of at least 12 — 11 is rejected as "Unable to modify
interface: Invalid argument", because HPK salts with `S1`–`S4`.

Addressing, egress NAT and address-family matching work exactly as for
WireGuard, from the `10.67.` block.

**Client apps.** AmneziaVPN and the standalone AmneziaWG app are different
clients with different formats — `vpn://` and `.conf` respectively — and only
the latter imports what `/subconf/<token>/<n>` serves. AmneziaVPN supports up to
3.0. Handing the file to the wrong app looks exactly like a broken server: the
import appears to succeed and no packet ever leaves the device.

---

## ShadowTLS

**Canonical ID** `shadowtls` · **Engine** sing-box · **Uses transport** no

ShadowTLS is not a standalone proxy — it is a wrapper. It performs a genuine TLS
handshake with a real third-party server (so an observer sees an authentic
certificate chain from an authentic host), and then carries a Shadowsocks stream
inside that session. It reaches a similar goal to REALITY by a different route,
and it is the practical way to give Shadowsocks a legitimate-looking TLS front.

**Required:** `ShadowTLSOptions.Password`, and a `Version` of 1, 2 or 3.
Normalization defaults the version to 3; v1 and v2 have known weaknesses against
active probing and exist for compatibility with older clients. **Optional:**
`HandshakeHost` and `HandshakePort` naming the real server whose handshake is
borrowed, and `StrictMode`, which enforces stricter checks on that handshake at
some cost in compatibility.

ShadowTLS **has no standalone share link**. `export.URI()` returns an explicit
error directing the caller to export the wrapped Shadowsocks node instead,
because a ShadowTLS endpoint without its inner Shadowsocks parameters is not a
connectable configuration. In client formats that model it properly — Clash.Meta,
sing-box — it appears as a plugin or a wrapper on the Shadowsocks outbound.

`UUID`, `Password`, `Username`, `Flow`, `Encryption` and `AlterID` on the node
itself are cleared; the ShadowTLS password lives in its own options block.

---

## SSH

**Canonical ID** `ssh` · **Engine** sing-box · **Uses transport** no

SSH as a tunnel is slow and has an unmistakable handshake — and is nonetheless
one of the most reliably unblocked options in corporate and institutional
networks, because blocking SSH outright breaks the network's own administration.
Where the constraint is a policy filter rather than a national firewall, SSH
often works when everything else does not.

**Required:** `SSHOptions.User`, and **either** `Password` **or** `PrivateKey`.
`Validate()` rejects a node with a user but no authentication method.
**Optional:** `PrivateKeyPassword` for an encrypted key, `HostKeyAlgorithms` to
constrain negotiation, and `ClientVersion` to spoof the version banner (an SSH
client identifying itself as OpenSSH is less interesting to a filter than one
identifying itself as a proxy library).

Server-side, an SSH endpoint can be a restricted system user or a managed
embedded SSH listener the panel operates.

**The `ssh://` share link deliberately carries no credential.** It exports as
`ssh://user@host:port#remark` and nothing more. SSH keys and passwords are
provisioned out of band; embedding them in a URL that gets pasted into chat
applications, stored in client app databases and rendered as QR codes would be a
security regression. This is the one documented, intentional exception to the
round-trip property: the test clears `Password` and `PrivateKey` before
comparison and explains why inline.

`keygen.SSHKeys()` generates ed25519 keypairs, returning the private key in
OpenSSH PEM form, the public key in `authorized_keys` form, and the SHA-256
fingerprint.

---

## Brook

**Canonical ID** `brook` · **Engine** Brook, as an external process · **Uses transport** no

Brook is a small, self-contained proxy with its own protocol family and a
long-standing user base, particularly among clients that support it natively. It
is included for compatibility and because its WebSocket and QUIC server modes are
useful behind CDNs.

**Required:** `Password`. **Optional, via `BrookOptions`:** `Mode`, one of
`server` (the native protocol over TCP and UDP), `wsserver` (WebSocket),
`wssserver` (WebSocket over TLS) or `quicserver`; `Path` for the WebSocket
modes; `UDPOverTCP` for paths that drop UDP; and `WithoutBrookProtocol`, which
strips Brook's own encryption layer when it is redundant behind TLS.

`UUID`, `Username`, `Flow`, `Encryption` and `AlterID` are cleared. Exported in
Brook's own scheme: `brook://<mode>?password=&server=host%3Aport#remark`.

**Licensing.** Brook is GPL-3.0. ForgePanel supervises the upstream binary as a
separate process and never imports, links against, or vendors Brook source. The
boundary is architectural and is documented in [LICENSING.md](LICENSING.md).
Because Brook exposes no stats API, its traffic is accounted by ForgePanel's own
connection accounting rather than by engine counters, which is less precise than
the Xray and sing-box paths.

---

## ForgeDNS

**Canonical ID** `forgedns` · **Engine** ForgeDNS, in-process · **Uses transport** no

ForgeDNS is the protocol that distinguishes ForgePanel. It tunnels traffic inside
ordinary DNS queries and responses, which works in the environments where nothing
else does: captive portals that resolve DNS before you have paid, networks that
whitelist port 53 and nothing else, and blackouts in which the DNS resolver is
the only reachable service. It is slow — tens of kilobytes per second at best —
and it is a lifeline rather than a daily driver.

**Required:** `ForgeDNSOptions.Adapter` and `Zone`. The adapter selects the wire
format (`stormdns`, `masterdns`, `cottendns`); the zone is the delegated tunnel
domain, whose NS records must point at the ForgePanel server for any of this to
function.

**Optional:** `NSHost`, the authoritative nameserver hostname used by the
delegation wizard; `Key`, the pre-shared authentication key where the adapter
supports one; `RRType`, the downstream record type (`TXT`, `NULL`, `CNAME`, `A`,
`AAAA` or `MX`, defaulting to `TXT`); `MaxUpstream` and `MaxDownstream` byte
budgets per query and response; and `EDNSBuffer`, the negotiated EDNS0 buffer
size, defaulting to 1232 — the value chosen to stay below common path MTUs and
avoid IP fragmentation, which many middleboxes drop.

Normalization lowercases the adapter, lowercases the zone and strips its trailing
dot, uppercases the RR type, and applies the TXT and 1232 defaults. `Validate()`
requires both the zone and the adapter; a ForgeDNS node without a delegated zone
is not a configuration, it is a wish.

`UUID`, `Password`, `Username`, `Flow`, `Encryption` and `AlterID` are cleared —
ForgeDNS authentication lives in `Key`. Exported in ForgePanel's native scheme:
`forgedns://<adapter>@<zone>?key=&rr=&ns=#remark`.

Full subsystem documentation — architecture, the adapter interface, the NS
delegation wizard, and hardening — is in [FORGEDNS.md](FORGEDNS.md).

---

## Key generation

Every credential above can be generated by `internal/protocol/keygen`, which is
the same code path used by the UI's generate buttons and `forgectl keygen`. Using
one implementation everywhere is deliberate: hand-rolled key generation is where
panels quietly get things wrong.

| Function | Produces |
|---|---|
| `UUID()` | Random UUID v4 |
| `UUIDFromString(s)` | Xray's deterministic string→UUID mapping — a valid UUID passes through unchanged, anything else is hashed and stamped with version 5 and the RFC 4122 variant. Must match Xray byte-for-byte or users created from a human-friendly id will not authenticate |
| `RealityKeys()` | X25519 keypair, RFC 7748 clamped, base64 raw-url encoded — identical to `xray x25519` |
| `RealityPublicFromPrivate(priv)` | Recovers the client-side public key from a server-only inbound |
| `ShortID(n)` | REALITY shortId, 1–8 bytes as lowercase hex |
| `SS2022PSK(method)` | Base64 PSK of exactly the right length for the method; errors on non-SIP022 methods |
| `Password(n)` | Random URL-safe password with n bytes of entropy (minimum 16) |
| `WireGuardKeys()` | Curve25519 keypair in WireGuard's standard base64 form |
| `SSHKeys()` | ed25519 keypair: OpenSSH PEM private key, `authorized_keys` public key, SHA-256 fingerprint |
| `MLDSA65Seed()` | 32-byte seed for post-quantum REALITY. ForgePanel does not implement ML-DSA in process — the pinned Xray build derives the key material, so derivation matches upstream's known-answer tests exactly |
| `FingerprintCert(der)` | Base64 SHA-256 of a DER certificate, for Hysteria2/TUIC `pinSHA256` |
