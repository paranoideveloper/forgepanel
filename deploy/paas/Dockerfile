# syntax=docker/dockerfile:1
#
# ForgePanel on a PaaS (Railway, Render, Fly, Koyeb).
#
# It differs from the root Dockerfile in what it does NOT do, and each omission
# is a thing the platform either forbids or has already done:
#
#   * no CAP_NET_BIND_SERVICE — nothing binds a privileged port here. The edge
#     owns :443 and hands the container a high port of its choosing.
#   * no wireguard/iptables/nftables — the platform routes TCP only, so the
#     protocols that need them cannot be served and their tooling is dead weight.
#   * cores are baked in — the panel can fetch them at boot, but on a deploy
#     with no volume that is a download on every restart, and on a restricted
#     build network it is a panel that comes up with no cores at all.
#
# Build from the repository ROOT:
#   docker build -f deploy/paas/Dockerfile -t forgepanel-paas .

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# libgcc/libstdc++ are what the bun binary is linked against; without them it
# installs fine and every invocation dies with a bare "not found" (exit 127).
RUN apk add --no-cache bash curl unzip libgcc libstdc++
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"
COPY . .
RUN cd frontend && bun install && bun run build

ARG VERSION=paas
ARG COMMIT=""
ARG BUILD_DATE=""
ARG TARGETOS
ARG TARGETARCH
RUN VP=github.com/forgepanel/forgepanel/internal/version && \
    LD="-s -w -X ${VP}.Version=${VERSION} -X ${VP}.Commit=${COMMIT} -X ${VP}.Date=${BUILD_DATE}" && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD}" -o /out/forgepanel ./cmd/forgepanel && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD}" -o /out/forgectl ./cmd/forgectl && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD}" -o /out/forgenode ./cmd/forgenode

# ---- metered sing-box -------------------------------------------------------
# The sing-box ForgePanel ships: the official tag set plus with_v2ray_api, the
# one tag that makes Hysteria2/TUIC/AnyTLS/ShadowTLS/WireGuard traffic countable
# per user. The official archive staged below lacks it, so on that binary those
# protocols are unmetered and a user can exhaust a plan on them forever.
#
# build-singbox.sh pins the Go toolchain, so this produces the exact bytes
# binmgr pins (pinnedSHA256 "sing-box-<ver>-linux-<arch>"). binmgr verifies it
# before adopting it; a mismatch is refused and the official build is used, so a
# toolchain surprise costs metering, never the deploy. The check below says so in
# the build log, where an operator on a platform can actually see it.
#
# Debian, not Alpine, on purpose: with_purego makes the binary dynamically
# linked, and Go writes the BUILD machine's C loader into it — musl's on Alpine,
# glibc's everywhere else, upstream's release builder included. That one path
# was the only byte that differed from the pinned build. The runtime image's
# gcompat provides the glibc loader, which is how the official binary runs too.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS singbox
ARG TARGETARCH
ARG SINGBOX_VERSION=1.14.2
WORKDIR /src
COPY scripts/build-singbox.sh scripts/build-singbox.sh
COPY licenses/sing-box licenses/sing-box
RUN SINGBOX_VERSION="${SINGBOX_VERSION}" TARGETS="${TARGETARCH:-amd64}" \
      bash scripts/build-singbox.sh /out

# ---- cores -------------------------------------------------------------------
# Staged under /opt/forgepanel-cores in the exact layout binmgr expects, so the
# entrypoint only has to copy them into the data directory. The version numbers
# MUST match internal/core/binmgr/binmgr.go: binmgr looks for
# <data>/bin/<engine>-<version>/<binary> and downloads when it is not there, so
# a stale version here is not an error — it is a silent download at every boot.
#
# Every download is checked against the SHA-256 binmgr pins for the same file.
# The panel refuses an unverified core at runtime; the image must not be the one
# place that installs whatever the URL returned. TestThePaaSImagePinsWhatBinmgrPins
# keeps the versions and digests here equal to binmgr's.
FROM alpine:3.21 AS cores
ARG TARGETARCH
ARG XRAY_VERSION=v26.7.28
ARG SINGBOX_VERSION=1.14.2
ARG BROOK_VERSION=v20270101
RUN apk add --no-cache curl unzip tar
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) XRAY_ASSET=Xray-linux-64.zip; \
             XRAY_SHA=8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40; \
             BROOK_ASSET=brook_linux_amd64; \
             BROOK_SHA=1541081e05e1e0de3a55eb548e8c9b5a99bfdac360c2eb98702ec5c20c968b7e; \
             SB_TAIL=linux-amd64; \
             SB_SHA=a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6 ;; \
      arm64) XRAY_ASSET=Xray-linux-arm64-v8a.zip; \
             XRAY_SHA=f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501; \
             BROOK_ASSET=brook_linux_arm64; \
             BROOK_SHA=8f81c73a778a244a778eb27315808dd2b41e1532f797bbf1a0e8af66c3c02793; \
             SB_TAIL=linux-arm64; \
             SB_SHA=b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f ;; \
      *) echo "no pinned cores for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    \
    mkdir -p "/opt/forgepanel-cores/xray-${XRAY_VERSION}"; \
    fetch /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ASSET}" "$XRAY_SHA"; \
    unzip -o /tmp/xray.zip -d "/opt/forgepanel-cores/xray-${XRAY_VERSION}"; \
    chmod +x "/opt/forgepanel-cores/xray-${XRAY_VERSION}/xray"; \
    \
    mkdir -p "/opt/forgepanel-cores/brook-${BROOK_VERSION}"; \
    fetch "/opt/forgepanel-cores/brook-${BROOK_VERSION}/brook" \
      "https://github.com/txthinking/brook/releases/download/${BROOK_VERSION}/${BROOK_ASSET}" "$BROOK_SHA"; \
    chmod +x "/opt/forgepanel-cores/brook-${BROOK_VERSION}/brook"; \
    \
    mkdir -p "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}"; \
    fetch /tmp/sb.tar.gz \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-${SB_TAIL}.tar.gz" "$SB_SHA"; \
    tar -xzf /tmp/sb.tar.gz -C /tmp; \
    cp "/tmp/sing-box-${SINGBOX_VERSION}-${SB_TAIL}/sing-box" \
       "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}/sing-box"; \
    chmod +x "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}/sing-box"; \
    rm -f /tmp/xray.zip /tmp/sb.tar.gz

# The metered build, beside forgepanel where binmgr looks first. Not fatal when
# it does not match the pin: binmgr refuses it and falls back to the official
# core staged above, and this line is the only place that says why.
COPY --from=singbox /out/ /opt/forgepanel-singbox/
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) SBM_SHA=68b791b100c962f985d37480a005de412aea2f657604d21f3327ca5898217bda ;; \
      arm64) SBM_SHA=819ba16bc02583d399e135cfbc5c757e3d6666ccfd5c2d6abeb57a6f447f25d6 ;; \
    esac; \
    f="/opt/forgepanel-singbox/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH:-amd64}"; \
    mkdir -p /opt/forgepanel-singbox/bin /opt/forgepanel-singbox/licenses; \
    if echo "${SBM_SHA}  ${f}" | sha256sum -c -; then \
      echo "metered sing-box matches the pinned build"; \
      mv "$f" /opt/forgepanel-singbox/bin/; \
    else \
      echo "WARNING: metered sing-box does not match the pin; the panel will use the official, unmetered build" >&2; \
    fi; \
    mv /opt/forgepanel-singbox/sing-box-LICENSE /opt/forgepanel-singbox/sing-box-NOTICE.md \
       /opt/forgepanel-singbox/licenses/

# ---- runtime -----------------------------------------------------------------
FROM alpine:3.21

LABEL org.opencontainers.image.title="ForgePanel (PaaS)" \
      org.opencontainers.image.description="ForgePanel behind a platform edge: every inbound on the one HTTP port the platform routes." \
      org.opencontainers.image.source="https://github.com/paranoideveloper/forgepanel" \
      org.opencontainers.image.licenses="MIT"

# gcompat: the upstream sing-box release binary is glibc-linked and Alpine is
# musl, so without the shim every exec fails with a bare "not found".
RUN apk add --no-cache ca-certificates tzdata gcompat

COPY --from=build /out/forgepanel /usr/local/bin/forgepanel
COPY --from=build /out/forgectl   /usr/local/bin/forgectl
# The panel serves this to a node being enrolled, reading it off its own
# filesystem — see agentBinaryPath. Without it every enrolment against a PaaS
# deploy gets a 503 naming paths the operator cannot create.
COPY --from=build /out/forgenode  /usr/local/bin/forgenode
COPY --from=cores /opt/forgepanel-cores /opt/forgepanel-cores
# Next to the panel binary: the first place binmgr looks for the shipped build.
# sing-box is GPL-3.0: its licence and notice travel with the binary.
COPY --from=cores /opt/forgepanel-singbox/bin/ /usr/local/bin/
COPY --from=cores /opt/forgepanel-singbox/licenses/ /usr/share/licenses/sing-box/
COPY deploy/paas/entrypoint.sh /usr/local/bin/forgepanel-paas-entrypoint
RUN chmod +x /usr/local/bin/forgepanel-paas-entrypoint

ENV FORGEPANEL_DATA=/var/lib/forgepanel \
    FORGEPANEL_PAAS=1
RUN mkdir -p /var/lib/forgepanel && chmod 700 /var/lib/forgepanel
WORKDIR /var/lib/forgepanel

# The platform tells us which port to bind through PORT; 8080 is the fallback
# for one that does not. EXPOSE is documentation here — the platform routes to
# whatever the process actually listens on.
EXPOSE 8080

# Root, unlike the root Dockerfile's non-root user. A platform volume is
# mounted root-owned and cannot be chown'd from the image, so a non-root panel
# cannot write its own database; there is no privileged port to protect and the
# container is single-tenant and disposable.
ENTRYPOINT ["/usr/local/bin/forgepanel-paas-entrypoint"]
