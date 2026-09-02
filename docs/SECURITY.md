# Security

ForgePanel is administrative software for infrastructure whose users often depend
on it under adversarial conditions. A compromised panel does not merely leak
configuration — it exposes the identities and traffic patterns of everyone using
it, and hands an adversary the ability to redirect their traffic. The security
posture is set accordingly.

This document states the threat model and gives the hardening checklist for
operators.

---

## Threat model summary

### What is being protected

**User identities and their association with a server.** The database maps
people to credentials to endpoints. In many deployments that mapping is the most
sensitive thing on the machine — considerably more sensitive than any single
proxy credential, because it is a list.

**Server-side secrets.** REALITY private keys, WireGuard private keys, SSH host
and client keys, Shadowsocks PSKs, ML-DSA-65 seeds, ACME account keys and issued
certificate private keys, DNS provider API tokens, the Telegram bot token, node
enrollment keys and the node CA.

**Control of the panel.** An attacker with admin access can add an inbound
pointing anywhere, alter routing, read every user's credentials and enumerate
every node. This is a more severe outcome than reading the database, because it
is active.

**Availability.** For users in a blackout, the panel is the thing that hands out
working configurations. Taking it down is a meaningful attack in itself.

### Adversaries considered

**Untargeted internet background noise.** Continuous scanning for exposed admin
panels, default credentials, known CVEs in web frameworks, and open resolvers.
This is not hypothetical — a new host on a public IP receives it within hours.
Mitigations: randomized admin path, no default credentials at all, login rate
limiting, security headers, an authoritative-only DNS listener, and a small
dependency surface with `govulncheck` in CI.

**An adversary who has found the panel and is attacking authentication.**
Credential stuffing, brute force, session fixation, CSRF from a page the admin
visits while logged in. Mitigations: argon2id, mandatory-capable TOTP with
recovery codes, progressive login delays, session revocation, strict CORS, and
optional IP allowlisting and TLS client certificates for the admin surface.

CSRF is addressed by CONSTRUCTION rather than by tokens: the panel authenticates
only from an `Authorization` header, which a cross-site page cannot set. A
browser attaches cookies to cross-site requests automatically, so cookie auth is
what makes CSRF possible in the first place — and the panel has none. A `token`
cookie fallback did exist in the middleware, unused by the shipped UI and live
for anyone who set it; it was removed rather than defended, because a CSRF token
is machinery to guard a door nobody was using.

This is why there is no CSRF token to configure, and why the deployment
checklist has no cookie hardening step: there are no session cookies to harden.

**An adversary with filesystem or backup access but not a running process.** A
stolen backup archive, a snapshot of the VPS disk, a misconfigured object-storage
bucket. Mitigations: secrets encrypted at rest with AES-GCM under a master key
that lives outside the database, and AES-256-encrypted backups.

**A network observer positioned between users and the panel.** Mitigations: TLS
everywhere with HSTS, and no plaintext subscription endpoints.

**A malicious or compromised node.** In a multi-node deployment the panel trusts
nodes for stats and nodes trust the panel for configuration. A compromised node
sees the traffic of users bound to it — that is inherent — but must not be able
to escalate into the panel or into other nodes. Mitigations: mutual TLS with a
panel-issued per-node client certificate, one-time enrollment tokens, and stats
treated as untrusted input with the panel as the source of truth during
reconciliation.

**A malicious user of the proxy service.** Someone with valid credentials
attempting to exceed their quota, share credentials widely, or reach the panel's
own management interfaces through the tunnel. Mitigations: quota enforcement
within one poll cycle, IP and device limits with a configurable window and
automatic action, and routing rules that deny tunnel traffic to the panel's
management ports.

**A hostile reseller.** In multi-tenant deployments a reseller is a partially
trusted administrator who must not see or affect other resellers' users.
Mitigation: RBAC scoping enforced in the **repository layer**, not only in
handlers, so that a route added later without the right middleware still cannot
read across tenants.

### Explicitly out of scope

Protecting against an attacker with root on the panel host: at that point the
master key, the database and the running process are all theirs. Defending users
against a global passive adversary performing traffic analysis at internet scale —
protocol choice (AnyTLS, REALITY, ForgeDNS) is a mitigation, not a guarantee.
Protecting against a malicious upstream release of Xray, sing-box or Brook beyond
pinning versions and verifying checksums against the published release.

---

## Core mechanisms

### Password hashing: argon2id

Admin passwords are hashed with **argon2id**, the hybrid variant that resists
both GPU-parallel and side-channel attacks, with parameters at or above the
current OWASP recommendation and a per-password random salt. Full parameters are
encoded into the stored hash so they can be raised over time and existing hashes
rehashed transparently on next successful login.

No password is ever logged, returned by an API, or included in a backup in
recoverable form. There is no default password: the first-boot sequence generates
credentials, prints them exactly once, and stores only the hash. An operator who
loses that output resets through a local CLI command that requires filesystem
access, not through a web-facing recovery flow.

### Two-factor authentication: TOTP

TOTP (RFC 6238), implemented in-tree with no third-party dependency
(`internal/auth/totp.go`), provisioned by QR code, with a one-step window either
side to tolerate clock skew.

**Already-used codes are rejected.** The window means a code stays valid for up
to 90 seconds, so accepting it more than once would let anyone who observed it —
by shoulder-surfing, a phishing form, or a proxy — replay it. The account records
the last time step it accepted, and a login presenting that step or earlier is
refused. The record is claimed with a conditional `UPDATE`, so two logins racing
with the same intercepted code cannot both succeed; exactly one wins.

**Recovery codes are real, single-use, and hashed.** They are generated at
enrollment, displayed exactly once, and stored as salted SHA-256 — never
plaintext. Consuming one runs inside a transaction, so two concurrent logins
cannot spend the same code. After the initial display the panel only reports how
many remain. Recovery-code attempts count against the same failed-login lockout
as passwords, so the recovery path is not a way around it.

**Sessions are revocable despite stateless tokens.** Every token carries the
account's session epoch, and the middleware rejects a token whose epoch is behind
the account's current one — including at the refresh endpoint, which would
otherwise launder a revoked session into a fresh access token. The epoch is
advanced whenever the account's authentication state changes: 2FA enabled, 2FA
disabled, a recovery code used, or the password changed. The recovery-code case
matters most: reaching for a recovery code means the authenticator is gone, which
is exactly when someone else may already hold a session. The operator performing
the action is handed a fresh token pair, so their own UI is not signed out.

TOTP shares a secret with the server, so it protects against credential theft and
reuse but not against a compromised panel. That is the correct trade for this
threat model; WebAuthn is the natural upgrade and is a candidate for a future
ADR.

### Encrypted-at-rest secrets

Values that must be recoverable in plaintext to be used — DNS provider API
tokens, the Telegram bot token, node private keys, REALITY private keys, ML-DSA
seeds, ACME account keys — cannot be hashed. They are encrypted with **AES-GCM**
under a master key supplied from an environment variable or a file with
restrictive permissions, **never stored in the database**.

Each value gets a unique nonce, and AES-GCM's authentication tag means tampering
is detected on decrypt rather than producing silent garbage. The consequence to
understand: a database dump alone does not yield these secrets, but a database
dump plus the master key does. Back them up separately, and treat the master key
as the crown jewel it is. Key rotation re-encrypts all secrets under a new key in
a single transaction.

### Randomized admin path

The admin interface is served from a random path generated at install — for
example `/panel/x7Kq2m` — printed once and never shown in an unauthenticated
response. This is obscurity, not security, and is not treated as a control: every
authentication and authorization check applies regardless. Its actual value is
specific and real — it removes the panel from the results of untargeted scanners
probing `/admin`, `/panel` and `/xui`, which is the overwhelming majority of
attack traffic a small VPS receives. It buys nothing against a targeted attacker,
which is why it sits alongside 2FA, rate limiting and optional IP allowlisting
rather than in place of them.

### Audit log

Every mutating action is recorded with the actor, source IP, timestamp, action,
target and a **before/after diff** of what changed. Reads are not logged;
mutations always are. The log covers panel actions, API-key actions and
`forgectl` actions alike, since an attacker who obtains an API key should leave
the same trail as one who logs in.

Audit entries are append-only through the application: no API deletes them and no
role edits them. Retention is configurable, rotation is a scheduled job, and
export is available for external SIEM ingestion. The audit log's purpose is
answering "what did the attacker do" after a compromise, which is impossible to
reconstruct from application state alone.

### Input validation and query safety

Every request body is validated against a schema at the edge before reaching
business logic. Database access is exclusively through parameterized queries —
the ORM's query builder or explicit prepared statements — with no string
concatenation into SQL anywhere, enforced by review and by CI linting.

The canonical model's `Validate()` is the protocol-layer half of this and is
deliberately strict: a Shadowsocks 2022 PSK of the wrong length, a malformed
REALITY shortId, an unknown uTLS fingerprint, a WireGuard MTU outside 576–1500,
an unsupported VLESS flow value, and missing credentials are all hard errors, not
warnings. Config Doctor surfaces them with plain-language explanations and
one-click fixes rather than letting them reach an engine.

Adapter decoders in ForgeDNS receive attacker-controlled bytes on a public UDP
port and are held to a higher standard still: total functions that error rather
than panic on malformed input, with fuzzing and malformed-input test vectors as
part of the suite. See [FORGEDNS.md](FORGEDNS.md#security-hardening).

---

## Hardening checklist

### First boot

- [ ] Record the credentials printed at install. They are shown **once**; only the
      hash is stored.
- [ ] Change the generated admin password to one from a password manager.
- [ ] Enable TOTP 2FA and store the recovery codes somewhere other than the panel.
- [ ] Record the randomized admin path. Do not put it in a public issue tracker,
      a support chat, or a screenshot.
- [ ] Set a strong master key for at-rest encryption via environment or a
      `0600`-mode file, and back it up **separately from the database**.
- [ ] Confirm the panel is reachable only over HTTPS with a valid certificate.

### Network exposure

- [ ] Firewall everything except the ports actually needed: panel `2053`,
      subscription `2096`, API `2054`, ForgeDNS `53/udp`, and the proxy inbound
      ports.
- [ ] Restrict the panel and API ports to an IP allowlist where the admin has a
      stable address. This is the single highest-value control on the list.
- [ ] Consider requiring a TLS client certificate for the panel port.
- [ ] Do not expose the database to the network. SQLite is a local file; a
      MySQL or Postgres backend should listen on loopback or a private network.
- [ ] Verify `/metrics` requires authentication.
- [ ] Verify ForgeDNS answers only for its configured zones, returns `NXDOMAIN`
      for everything else, and performs no recursion. Confirm from an external
      host that it is not an open resolver.
- [ ] Add routing rules denying tunnel traffic to the panel's own management
      ports, so a proxy user cannot reach the admin interface from inside.

### Operating system

- [ ] Run the panel as a dedicated non-root user.
- [ ] Use the provided systemd hardening directives: `NoNewPrivileges=yes`,
      `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, and
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` for binding UDP/53 and TCP/443
      without root.
- [ ] Restrict the data directory to `0700` owned by the panel user.
- [ ] Keep the host patched, particularly the kernel and TLS libraries.
- [ ] Enable unattended security updates or a comparable patching process.

### Application configuration

- [ ] Confirm security headers are being sent: HSTS, CSP, `X-Frame-Options`,
      `X-Content-Type-Options`, `Referrer-Policy`.
- [ ] Confirm CORS is restricted to the panel's own origin.
- [ ] Review API keys: scope each to the minimum it needs, set per-key rate
      limits, and revoke unused keys.
- [ ] Set IP and device limits per user with an automatic action, so a leaked
      credential is bounded rather than unbounded.
- [ ] Configure notifications for authentication failures, node-down events and
      certificate renewal failures — an alert you do not receive is not a control.
- [ ] Leave ForgeDNS `dnstap`-style query logging **off** unless actively
      debugging; it records every query every user makes.
- [ ] Leave post-quantum REALITY (ML-DSA-65) off unless every client is known to
      support it. Enabling it produces links that fail silently in current
      v2rayNG and  builds — see
      [DECISIONS.md ADR-007](DECISIONS.md#adr-007-ml-dsa-65-post-quantum-reality-keys-are-generated-but-default-off).

### Multi-tenant deployments

- [ ] Give resellers the `reseller` role, never `admin`.
- [ ] Set explicit user quotas and traffic credit pools per reseller.
- [ ] Verify tenant isolation empirically: authenticate as one reseller and
      confirm another's users are invisible through the API, not only in the UI.
- [ ] Review the audit log for cross-tenant access attempts.

### Backup and recovery

- [ ] Verify backups are AES-256 encrypted and that the encryption key is stored
      separately from the backups themselves.
- [ ] If backing up to S3 or an equivalent, confirm the bucket is private and
      versioned.
- [ ] **Test a restore.** An untested backup is a hypothesis. Restore into a
      throwaway host and confirm the panel boots, users exist, and a client can
      connect.
- [ ] Back up the at-rest master key separately, and confirm the restore
      procedure works with it — a database restored without its master key yields
      no usable DNS tokens, node keys or REALITY private keys.

### Ongoing

- [ ] Review the audit log periodically, especially after any staff change.
- [ ] Rotate API keys and the at-rest master key on a schedule.
- [ ] Keep engine binaries current; the supervisor pins and checksum-verifies
      versions, but pinned versions still need updating when upstream fixes a
      vulnerability.
- [ ] Watch Config Doctor findings — an expired certificate or a closed firewall
      port is an availability incident waiting for the worst possible moment.
- [ ] Track `govulncheck` results in CI and treat a new finding in a reachable
      code path as a release blocker.

---

## Reporting a vulnerability

Report security issues privately rather than through the public issue tracker.
Include a description, reproduction steps, affected versions, and the impact you
believe it has. Reports are acknowledged and triaged before any public
disclosure, and fixes are released with credit unless the reporter prefers
otherwise.

## Waivers

Any finding from `gosec` or `govulncheck` that is not fixed must be recorded here
with the specific rule or advisory identifier, why it does not apply, and who
accepted the risk. An unexplained suppression comment in the source is not a
waiver.

*No waivers are currently in effect.*

## Supply chain & hardening status (this build)
- **SBOM**: `docs/SBOM-modules.txt` (generated via `go list -m all`; regenerate a
  CycloneDX SBOM in CI with `cyclonedx-gomod`).
- **Login rate limiting**: per-source-IP progressive lockout after 4 failures
  (`internal/api/ratelimit.go`), blunting credential stuffing.
- **Backups**: AES-256-GCM encrypted (`internal/backup`), key derived from the
  panel master secret; tested backup→wipe→restore cycle; wrong-key rejected.
- **Deployment**: distroless non-root container, `no-new-privileges`,
  `CAP_NET_BIND_SERVICE` only; systemd unit with `ProtectSystem=strict`.
- **Dependencies pinned** to go1.25-compatible versions; `govulncheck`/`gosec`
  are intended CI gates.
