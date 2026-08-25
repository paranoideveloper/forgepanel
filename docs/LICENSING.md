# Licensing

ForgePanel is **MIT** licensed (see [LICENSE](../LICENSE)). That choice constrains
what may enter this repository, and the constraint is not negotiable per-feature:
copyleft source cannot be copied into an MIT project without relicensing the
whole thing.

This document records how ForgePanel relates to third-party work, so the
question "may we use this?" has a written answer rather than a per-pull-request
argument. Two files in the tree point here — `internal/protocol/model/model.go`
and `internal/deploy/compose.go` — because they touch the two cases below.

## The rule

| Upstream licence | What we may do |
|---|---|
| MIT, Apache-2.0, BSD | Adapt the source **with attribution** and the upstream notice. |
| GPL-2.0, GPL-3.0, AGPL-3.0, MPL | **Never copy.** Study behaviour, write a fresh implementation. A GPL binary may still be *executed* as a separate process (see Brook). |
| No licence at all | **Never copy.** Absence of a licence means all rights reserved; it is not permission. Observable behaviour only. |

The distinction that matters for GPL tools is **linking versus running**.
Importing GPL code into this binary would relicense ForgePanel. Downloading a
GPL binary and supervising it as its own process, communicating over its
documented CLI or network interface, does not — it is ordinary use of a program.

## Third-party engines we execute, never link

ForgePanel downloads, pins, verifies and supervises proxy cores. None of them
are imported as Go packages.

- **Xray-core** (MPL-2.0) — supervised process; configured with JSON, validated
  with `xray run -test`.
- **sing-box** (GPL-3.0) — supervised process; configured with JSON, validated
  with `sing-box check`.
- **Brook** (GPL-3.0) — supervised process, driven entirely by CLI flags. It is
  deliberately never imported or linked; `internal/protocol/model/model.go` says
  so at the definition of `BrookOptions`, and `internal/deploy/compose.go`
  repeats it where the container profile is declared.
- **AmneziaWG** (GPL-2.0) — the kernel module and `awg-quick` are installed on
  the host and invoked as programs.

Because these are separate processes, their licences do not reach ForgePanel's
own source.

## Adapted with attribution

### CottenRouter — `internal/forgedns/frontrouter`

- Upstream: <https://github.com/TaJirax/CottenRouter>
- Licence: **MIT** — compatible with ForgePanel's MIT licence, so adaptation is
  permitted with attribution.

`internal/forgedns/frontrouter` lets one public port 53 sit in front of several
DNS tunnels. The design it follows — read the first question, select the backend
whose configured suffix is the longest match, and forward the datagram byte for
byte without re-encoding it — is CottenRouter's, and the longest-suffix route
table follows the same approach.

The implementation is ForgePanel's own, written against ForgePanel's zone model
rather than copied: the route table is built from `ForgeDNSZone` records, and the
QNAME reader enforces the RFC 1035 255-octet limit *during* the walk so an
oversized name never allocates.

MIT requires that the copyright notice and permission notice accompany
substantial portions of the software. This section is that notice; the package
doc comment in `qname.go` carries the same attribution at the point of use.

## Project Nayuki — QR code generator (MIT)

`frontend/src/lib/vendor/qrcodegen.ts` and
`deploy/cloudflare/forgeedge/src/vendor/qrcodegen.ts` are Project Nayuki's QR
Code generator library, vendored unmodified under the MIT licence. The full
copyright and permission notice is retained verbatim at the top of each file, as
MIT requires.

Both copies exist because the panel frontend and the Cloudflare Worker are
separate build roots with no shared module path. `TestVendoredQREncoderCopies-
AreIdentical` asserts they are byte-identical, so the two cannot drift into
different behaviour — or into a state where only one of them has a security fix
from upstream.

It replaced a hand-written function that was not a QR encoder at all: it drew
finder patterns and filled the data area from a string hash, producing an image
that looked like a QR code and decoded to nothing. `tools/qrverify/verify_qr.py`
re-establishes the property that matters by decoding the panel's output back to
its input with an independent decoder.

## Reference material used for behaviour only

The platform programme studies a corpus of proxy-panel projects to identify
capabilities ForgePanel should have. Most of that corpus is GPL, AGPL, or carries
no licence at all. For those, research agents record **observable behaviour and
capability with file-path evidence**, and implementation is written fresh against
that specification. No upstream file, function body, or comment block is copied.

Where a reference is permissively licensed and code is genuinely adapted rather
than reimplemented, it is recorded in this file, as CottenRouter is above.
