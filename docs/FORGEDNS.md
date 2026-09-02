# ForgeDNS — DNS tunneling as a first-class protocol

ForgeDNS tunnels arbitrary TCP traffic inside ordinary DNS queries and
responses. It is the slowest transport ForgePanel offers and the one that works
when nothing else does.

The reason it works is structural. DNS is the one protocol a network essentially
cannot block, because blocking it breaks the network. Captive portals resolve DNS
before you have authenticated. Restrictive corporate and institutional networks
permit UDP/53 to their own resolver even when they permit nothing else. During a
national internet blackout, the recursive resolver at the ISP frequently keeps
answering after everything else has stopped. In all three cases a client that can
send a DNS query and receive an answer has a channel — a bad one, but a channel.

The cost is severe and should be stated plainly. A DNS tunnel carries on the
order of a couple of hundred bytes upstream per query and up to a kilobyte or so
downstream per response, with a full round-trip through a recursive resolver for
every exchange. Real throughput lands in the tens of kilobytes per second under
good conditions and can be far worse. ForgeDNS is a lifeline for reaching a
messaging app, fetching a fresh set of working configurations, or holding an SSH
session open. It is not a daily driver, and the UI says so.

> **Implementation status.** The ForgeDNS protocol is fully represented in the
> canonical model today — `model.ForgeDNSOptions`, validation, normalization, and
> `forgedns://` export and parse are implemented and covered by the round-trip
> test. The runtime described below (the authoritative listener, the three
> adapters, the session manager, the delegation wizard) is specified and not yet
> built. See the Status section of the [README](../README.md).

---

## Architecture

```
                        UDP :53  (and TCP :53 for large responses)
                        authoritative listener — miekg/dns
                                      │
                                      ▼
                              ┌───────────────┐
                              │  zone router  │  QNAME suffix → forgedns_zones row
                              └───────┬───────┘  → adapter profile, user binding,
                                      │             rate limits
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
      ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
      │  StormDNS    │        │  MasterDNS   │        │  CottenDNS   │
      │  adapter     │        │  adapter     │        │  adapter     │
      └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     │  adapter.Frame  (wire-format-neutral)
                                     ▼
                          ┌─────────────────────┐
                          │   session.Manager   │
                          ├─────────────────────┤
                          │ per-client state    │
                          │ keepalive pool +    │
                          │   data pool         │
                          │ AIMD congestion ctl │
                          │ reorder buffer      │
                          │ MTU probing         │
                          │ idle eviction       │
                          │ traffic accounting  │
                          └──────────┬──────────┘
                                     │
                                     ▼
                            upstream egress
                 direct · SOCKS5 · chained into any
                     ForgePanel outbound
```

Traffic that leaves through the egress is accounted into the **same**
`traffic_records` pipeline as proxy traffic. A user's quota is one number
regardless of whether the bytes arrived over VLESS or over DNS, which is the
only sane model for billing and limits, and it means ForgeDNS sessions appear in
the Live Connection Explorer alongside everything else.

### Query lifecycle

1. A client encodes a chunk of upstream data into the labels of a DNS question
   name under its tunnel zone — for example
   `<encoded-payload>.<seq>.t.example.com` — and sends the query to whatever
   recursive resolver the network provides.
2. The recursive resolver, having no cached answer and finding the zone delegated
   to us, forwards the query to the ForgePanel server as the authoritative
   nameserver for that zone.
3. The zone router matches the QNAME suffix against configured zones and selects
   the adapter profile, the bound user and the applicable rate limits.
4. The adapter's `Match` confirms the query belongs to it, and `Decode` converts
   the wire encoding into a neutral `Frame`.
5. The session manager locates or creates the session, feeds the payload into the
   reorder buffer, and hands complete data to the egress connection.
6. Any pending downstream data is packed into a `Frame` sized to the adapter's
   and the resolver's negotiated limits, `Encode`d into the appropriate resource
   record, and returned.
7. The recursive resolver returns the answer to the client, which decodes it and
   sends the next query.

The recursive resolver in the middle is the reason this works and also the source
of nearly every difficulty: it enforces its own limits on name length and
response size, it may rewrite case, it may refuse certain record types, and it
adds a full round-trip of latency to every exchange.

### Apex queries are ordinary DNS, not tunnel traffic

Not every query arriving for a tunnel zone is tunnel traffic. A query for the
zone apex itself — `t.example.com`, with no encoded label in front of it — is an
ordinary DNS question: the parent zone's delegation check, a resolver fetching
`SOA` or `NS`, an uptime monitor, an operator running `dig`.

The two are separated *before* any decoding happens, and the split is deliberate:

| Component | Responsibility |
|---|---|
| `codec.SplitQName` | reports **whether** the name carries an encoded payload |
| `adapter.Match` / `Decode` | decides whether frame parsing should happen at all; returns `ErrNoPayload` for a name that carries none |
| `codec.ParseFrame` | rejects only genuinely invalid frames |

This matters because an apex query yields an empty payload, and an empty payload
is not a malformed frame — it is not a frame at all. Feeding it to the decoder
made it fail the header-length check and be answered `NXDOMAIN`, which meant
`SOA` and `NS` at the apex also returned `NXDOMAIN`, and **a zone in that state
cannot be delegated**: the parent's delegation check and every resolver's `SOA`
lookup both fail. Apex queries are now answered from the zone's authoritative
data, and they never touch the session manager, so a health check can never be
mistaken for a client.

A name under the zone whose type we do not serve is `NOERROR`/`NODATA` with the
`SOA` in the authority section — the name exists, we simply hold no records of
that type. `NXDOMAIN` is reserved for names that genuinely do not exist.

The nameserver hostname the apex advertises is derived the same way the
delegation wizard derives it, from the **registrable** domain: zone
`t.example.com` advertises `ns1.example.com`, never `ns1.com`. The two must agree
or the delegation the panel tells the operator to create will not match what the
server answers.

---

## The adapter interface

Three existing DNS tunnel projects — StormDNS, MasterDnsVPN and CottenDNS — each
define their own wire format. They differ in label alphabet, chunking strategy,
QNAME budget, downstream record type, framing header layout, handshake, and
sequencing and acknowledgement model. They do **not** differ in anything above
the wire: every one of them needs session state, congestion control, reordering
and accounting, and that machinery is difficult enough that writing it three
times would produce three subtly different versions of which at most one would be
correct.

So the wire format is the only thing that varies, and it is isolated behind a
narrow interface:

```go
// internal/forgedns/adapter

type Adapter interface {
    // Match reports whether this query belongs to this adapter. The zone router
    // has already matched the zone; Match validates the format-specific shape of
    // the QNAME (label count, alphabet, magic prefix) so a misrouted or probing
    // query is rejected cheaply and without touching session state.
    Match(*dns.Msg) bool

    // Decode converts a wire query into a neutral Frame. It must be total: any
    // malformed input returns an error rather than panicking, because the input
    // is attacker-controlled and arrives on a public UDP port.
    Decode(*dns.Msg) (Frame, error)

    // Encode packs a Frame into a DNS response using this adapter's downstream
    // record type and encoding. It must respect the size ceiling the session
    // layer passes down via the Frame.
    Encode(Frame) (*dns.Msg, error)

    // Caps reports this adapter's static limits and requirements. The session
    // layer uses these to size windows and chunks rather than hardcoding
    // per-tunnel constants.
    Caps() Capabilities
}

type Capabilities struct {
    MaxUpstreamBytes   int      // payload bytes carriable in one query
    MaxDownstreamBytes int      // payload bytes carriable in one response
    SupportedRRTypes   []string // TXT, NULL, CNAME, A, AAAA, MX
    NeedsHandshake     bool     // requires session establishment before data
}
```

`Frame` is the neutral currency: a session identifier, a sequence number, an
acknowledgement, flags (handshake, data, keepalive, close), and a payload. It is
kept deliberately narrow. The pressure to add per-adapter fields to `Frame` is
constant and must be resisted, because the moment `Frame` contains
`StormDNSSpecificThing` the abstraction has failed.

Everything else in `internal/forgedns` — the listener, the zone router, the
session manager, the codecs, the metrics — is written against `Frame` and
`Capabilities` and knows nothing about any particular tunnel.

**The acceptance criterion is explicit:** adding a fourth DNS tunnel must require
only a new adapter file plus test vectors, with no changes to the session, server
or API layers. If a new adapter forces a change outside `adapter/`, the interface
is wrong and gets revised — not worked around. See
[DECISIONS.md ADR-006](DECISIONS.md#adr-006-forgedns-wire-formats-live-behind-an-adapter-interface).

### Deriving formats from source, not from guesses

Each upstream project is cloned into `third_party/` as read-only reference. Its
behaviour is documented byte-by-byte in `docs/FORGEDNS_WIRE_FORMATS.md` — label
alphabet, chunking and maximum QNAME length, record types, framing and header
layout, handshake, sequencing and ACK model, and any encryption or
authentication — **before** any adapter code is written. Each adapter ships with
test vectors under `test/vectors/forgedns/` recording known-good query and
response pairs.

Guessing at a wire format is not an acceptable shortcut here, because the failure
mode is not an obvious error. It is a tunnel that appears to work in testing and
silently corrupts data under load, reordering, or truncation — which is exactly
the condition a DNS tunnel operates in permanently.

---

## Session management

The session layer is where DNS tunneling is actually hard.

**Dual pools.** Each session maintains two pools of in-flight queries: a
**keepalive pool** of long-outstanding queries the server holds open so it has
somewhere to put downstream data the instant it arrives, and a **data pool** of
queries carrying upstream payload. Without the keepalive pool, downstream data
can only be delivered in response to a client query, so an idle client
downloading a file would have to poll — burning latency and query budget. This
mirrors the design of the StormDNS client and is the standard solution.

**AIMD congestion control.** A DNS tunnel is a lossy, reordering,
latency-variable channel with a hostile middlebox in the path. The session
manager runs additive-increase / multiplicative-decrease over the number of
concurrent outstanding queries, with configurable minimum and maximum window and
RTT-based pacing. Too small a window wastes the available parallelism; too large
a one triggers resolver rate limiting, which looks like sudden total loss.

**Reorder buffer.** Recursive resolvers do not preserve query order, and
different queries from one client may traverse different resolver instances
entirely. Sequence numbers in the `Frame` header let the session layer
reassemble the stream, with a bounded buffer and a retransmission timer.
Upstream frames are de-duplicated: a retransmitted client frame whose sequence
was already consumed is dropped rather than being counted twice or parked in the
reorder buffer forever.

**Downstream delivery is stop-and-wait.** DNS over UDP is unreliable, and a
dropped *answer* is invisible to the server — the client simply repeats the same
query. Downstream bytes are therefore **not** removed from the queue when they
are sent. One chunk is held in flight; a repeat of the same query replays it
byte-for-byte, and the queue advances only once the client has acknowledged it.

Acknowledgement is explicit for v2 peers, which carry `AckSeq` in the frame
extension. For v1 peers it is implicit: a *new* request sequence means the
previous answer arrived, while a repeat of the same request does not. That
implicit rule is what makes the fix work for existing clients without a protocol
change, because the failure the doc describes — "the response was lost so the
client repeats the query" — is precisely a repeat of the same request sequence.

Without this, one lost packet silently deleted bytes from the middle of the
tunnelled stream: the client asked again and got the *next* chunk, and whatever
was in the lost one was gone for good. Downstream bytes are billed once, when a
chunk first goes in flight; replays are never re-billed. An in-flight chunk that
is never acknowledged expires on a timer and is re-sent rather than pinning
memory.

**Session identity and frame authentication.** Because the replay buffer above
hands a stored chunk to whoever asks for a given `(session, sequence)`, session
identity has to be strong enough to carry that weight over a transport whose
source address is trivially spoofable. A v2 session id is a 64-bit CSPRNG value —
not the 16-bit field, which is enumerable in seconds — and every v2 frame carries
a truncated HMAC over `(session, seq, flags, ackseq, payload)` under a key
established at handshake. Frames that fail verification are dropped **before any
session state is read or created**, so forged identifiers can neither retrieve
another session's buffered data, nor forge an acknowledgement that discards it,
nor fill the session table. Authenticated ids are always `>= 2^16` so they cannot
collide with the legacy id space.

v1 (unauthenticated, 16-bit) sessions remain accepted for compatibility and can
be turned off with `Options.AllowLegacy`. They get the retransmission fix but not
the identity guarantees, which is inherent to a wire format with nowhere to put
an authenticator.

**Bounded everywhere.** Live sessions, per-session downstream queue bytes, and
held out-of-order upstream frames all have caps, and every rejection is counted
(`sessions_rejected`, `outbound_dropped`, `auth_failures`, `retransmits`,
`duplicate_queries`, `invalid_sequence`, `expired_frames`, `stale_upstream`), so
memory pressure from a flood is visible rather than fatal.

**Resolver capability probing.** Which downstream encoding actually works depends
on the client's recursive resolver, not on the client and not on us. Some
resolvers pass `NULL` records through intact; some mangle or refuse them. Some
truncate long `TXT` responses. Some normalize case, which breaks base32 encodings
that rely on case for extra bits. At session start the session layer probes what
the specific resolver in front of this client actually passes — TXT/base64 versus
NULL/raw versus CNAME/base32 — selects the best working encoding, and **caches
the result per resolver IP**, so the next client behind the same resolver pays
nothing for the discovery.

**MTU and EDNS0 negotiation.** EDNS0 lets a client advertise a larger UDP payload
than the classic 512-byte limit, which multiplies downstream throughput. The
default advertised buffer is **1232 bytes** — chosen to stay under common path
MTUs so responses are not IP-fragmented, since many middleboxes drop fragments
entirely — and the session probes upward from there where the path allows. When
EDNS0 is unavailable or the negotiated size proves unreliable, the session
degrades gracefully to 512-byte responses rather than failing.

**Idle eviction and limits.** Sessions have an idle timeout and are garbage
collected by a scheduled job. Concurrent sessions per user are capped.

**Metrics.** Every session reports RTT p50 and p95, upstream and downstream
bytes, queries per second, loss rate and current window size, streamed live to
the UI over WebSocket. These numbers are the only way to diagnose a slow tunnel:
they distinguish "the resolver is rate limiting us" (loss up, window collapsing)
from "the path is just long" (RTT high, loss zero) from "the resolver is
truncating responses" (downstream bytes far below the negotiated ceiling).

---

## The NS delegation wizard

For a DNS tunnel to work, the tunnel zone must be **delegated** to the ForgePanel
server — the world's DNS must know that the authoritative nameserver for
`t.example.com` is your box. This is the step that stops most people, because it
requires editing records at a registrar with an interface that varies by
provider, using record types (glue, NS) most people never touch, and because when
it is wrong there is no error message anywhere. The tunnel simply never receives
a query.

The wizard reduces it to: enter your domain and confirm your server IP.

**Generate.** Given `example.com` and the server's public IP, the wizard produces
the exact records to create, ready to copy:

```
ns1.example.com.    A     203.0.113.10       ← glue: names the nameserver
t.example.com.      NS    ns1.example.com.   ← delegation: hands the zone over
```

The record set is rendered in the syntax of the common registrar and DNS-provider
UIs, since a bare zone-file fragment is not what most control panels ask for.

**Verify, live, hop by hop.** After the records are entered, the wizard walks the
authoritative chain from the root and reports pass or fail at every hop:

| Hop | Check |
|---|---|
| 1 | Root servers return a referral for `com` |
| 2 | The `com` TLD servers return NS records for `example.com` |
| 3 | `example.com`'s authoritative servers return an NS record for `t.example.com` pointing at `ns1.example.com` |
| 4 | `ns1.example.com` resolves to the expected server IP (glue present and correct) |
| 5 | A probe query for `<random>.t.example.com` sent to that IP reaches the ForgeDNS listener and is answered |
| 6 | The same probe sent through a public recursive resolver (1.1.1.1, 8.8.8.8) also reaches the listener — proving the delegation is visible from the outside, not just directly |

Hop 5 versus hop 6 is the important distinction, and it is the one that costs
people hours: a query sent directly to your server always works, because it never
touches the delegation. Only hop 6 proves the tunnel will work for a real client
whose queries go through their ISP's resolver. Each failed hop is reported with
what was expected, what was received, and what to change.

**Propagation.** DNS changes are not instant. The wizard reports the observed TTL
and re-checks on a schedule rather than declaring failure on the first miss, so
"you configured it wrong" and "it has not propagated yet" are distinguishable
states rather than one confusing one.

---

## Multi-zone operation

One ForgePanel server hosts many tunnel domains simultaneously. Each zone row
carries its own adapter profile, its own user or group binding and its own rate
limits, and the zone router dispatches on QNAME suffix.

This matters operationally: a zone that gets identified and blocked can be
retired and replaced without disturbing the others, and different user
populations can be separated onto different domains so that one being burned does
not burn all of them. Different zones can also run different adapters
simultaneously, which is useful when a client population is split across client
apps.

---

## Client configuration export

Each session's parameters can be exported in the native configuration format of
whichever adapter it uses — so existing StormDNS, MasterDnsVPN and CottenDNS
clients work unmodified — and in a generic **ForgeDNS JSON profile** carrying the
zone, adapter, key, record type and negotiated limits in a neutral schema
suitable for embedding in a custom or iOS client.

Within ForgePanel, a ForgeDNS node is also a `forgedns://` link like any other
protocol:

```
forgedns://stormdns@t.example.com?key=<key>&rr=TXT&ns=ns1.example.com#fallback-tunnel
```

That link parses back to an identical canonical node — ForgeDNS is covered by the
same round-trip property test as every other protocol, with no exemption.

---

## Security hardening

A DNS tunnel endpoint is an authoritative nameserver listening on UDP/53 on the
public internet, taking attacker-controlled input, and doing non-trivial parsing
on it. It is one of the more exposed things a panel can run, and it is treated
accordingly.

**Never an open resolver.** This is the rule that matters most. ForgeDNS is
**authoritative-only**: it answers for the zones it is configured for and for
nothing else. It performs no recursion, holds no cache, and never forwards a
query upstream on a client's behalf. An open recursive resolver on the public
internet is conscripted into DNS amplification DDoS attacks within hours of being
discovered, gets the server null-routed by its provider, and gets the operator's
account terminated. There is no configuration flag that enables recursion,
because the correct number of ways to accidentally turn on recursion is zero.

**REFUSED for zones we do not serve.** A query for a zone we are not
authoritative for gets `REFUSED` — not a referral, not silence, and *not*
`NXDOMAIN`. `NXDOMAIN` is an authoritative statement that the name does not
exist, and we have no standing to make it about somebody else's zone; a resolver
is entitled to cache that denial. `REFUSED` says the true thing ("not mine"), is
the smaller datagram, and reveals nothing. Sending a referral would make the
server look like it might recurse; silence makes scanners retry.

Inside a zone we *do* serve, `NXDOMAIN` is used exactly where it belongs: a name
under the zone that genuinely does not exist, including a subdomain whose encoded
label is not a decodable frame. Those answers carry the zone's `SOA` so resolvers
can cache the negative result.

**RD never yields RA.** A query with the recursion-desired bit set still gets the
authoritative answer, and the recursion-available bit stays clear. `RA` is the
flag scanners look for when cataloguing open resolvers, and it is never set.

**Minimal ANY responses (RFC 8482).** `QTYPE=ANY` is the classic amplification
lever: a small query soliciting a large response. ForgeDNS does not expand it
into every record it holds and does not refuse it either — it returns the single
synthesised `HINFO` record RFC 8482 prescribes, which is both standards-compliant
and useless as amplification.

**Rate limiting, per source IP and per session.** Two independent limiters. The
per-IP limiter bounds what a single source can extract regardless of session
state and blunts amplification and scanning. The per-session limiter bounds a
single authenticated tunnel's query rate, which is also what keeps one aggressive
client from exhausting the server's own query budget with its upstream resolver.
Both are configurable per zone, because a zone serving ten users and one serving
a thousand need different ceilings.

**Concurrent session caps per user.** Bounds memory and reorder-buffer allocation
per identity and prevents a single credential from being shared across an
unbounded number of clients.

**Response size discipline.** Responses never exceed the negotiated EDNS0 buffer,
and the advertised buffer is itself capped at 1232 bytes — a client asking for
4096 does not get 4096 echoed back, because a large advertised buffer is exactly
what makes a nameserver worth reflecting off. 1232 also keeps responses below
common path MTUs so they are not fragmented. An answer that will not fit is
returned truncated, with `TC` set and the oversized records removed, so the
client retries over TCP instead of the server emitting a large UDP datagram at a
possibly-spoofed source.

**Response rate limiting, per client prefix.** Budgets are keyed on the client
*network* (IPv4 /24, IPv6 /64) rather than the exact address, so rotating the low
bits of a spoofed source does not buy a fresh allowance. Identical responses and
error responses (`NXDOMAIN`/`REFUSED`/`SERVFAIL`) get separate budgets, because
they are abused differently: repeated identical answers are the amplification
lever, while an error flood is the classic reflection pattern. A rate-limited
response is not sent at all. Counters for rate-limited, truncated, refused and
malformed queries are exported so an operator can see the limiter working.

**Adapter parsers must be total.** `Decode` receives attacker-controlled bytes on
a public port. Every adapter returns an error for malformed input rather than
panicking, and every adapter's test vectors include truncated, oversized and
structurally invalid inputs alongside the valid ones. Fuzzing the decoders is part
of the test suite, not an optional extra.

**Authentication.** Where an adapter's wire format supports a pre-shared key, it
is required, and the session is bound to a ForgePanel user so quotas, expiry and
per-user limits apply exactly as they do to proxy traffic. Sessions that fail to
authenticate consume a rate-limit token and are dropped without a distinguishing
response.

**Optional dnstap-style logging, behind a flag.** Full query logging is invaluable
when debugging a wire format and is a privacy liability the rest of the time — it
records every query every user makes. It is therefore off by default, gated
behind an explicit flag, and its state is visible in the UI rather than buried in
a config file.

**Privilege.** Binding UDP/53 requires privilege; the systemd unit grants
`CAP_NET_BIND_SERVICE` rather than running the panel as root, alongside the other
hardening directives described in [SECURITY.md](SECURITY.md).
