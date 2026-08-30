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

# ---- cores -------------------------------------------------------------------
# Staged under /opt/forgepanel-cores in the exact layout binmgr expects, so the
# entrypoint only has to copy them into the data directory. The version numbers
# MUST match internal/core/binmgr/binmgr.go: binmgr looks for
# <data>/bin/<engine>-<version>/<binary> and downloads when it is not there, so
# a stale version here is not an error — it is a silent download at every boot.
FROM alpine:3.21 AS cores
ARG XRAY_VERSION=v26.3.27
ARG SINGBOX_VERSION=1.13.15
ARG BROOK_VERSION=v20260101.0
RUN apk add --no-cache curl unzip tar
RUN set -eux; \
    mkdir -p "/opt/forgepanel-cores/xray-${XRAY_VERSION}"; \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"; \
    unzip -o /tmp/xray.zip -d "/opt/forgepanel-cores/xray-${XRAY_VERSION}"; \
    chmod +x "/opt/forgepanel-cores/xray-${XRAY_VERSION}/xray"
# Brook, which used to be fetched at first use. That is the failure this whole
# stage exists to prevent, and it was the worst case of it: a platform with no
# volume re-downloads on every restart, so a Brook inbound on a host that sleeps
# was configured, enabled, and dead — with the download failure nowhere an
# operator would look. brook ships a bare binary, not an archive.
RUN set -eux; \
    mkdir -p "/opt/forgepanel-cores/brook-${BROOK_VERSION}"; \
    curl -fsSL -o "/opt/forgepanel-cores/brook-${BROOK_VERSION}/brook" \
      "https://github.com/txthinking/brook/releases/download/${BROOK_VERSION}/brook_linux_amd64"; \
    chmod +x "/opt/forgepanel-cores/brook-${BROOK_VERSION}/brook"

RUN set -eux; \
    mkdir -p "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}"; \
    curl -fsSL -o /tmp/sb.tar.gz \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"; \
    tar -xzf /tmp/sb.tar.gz -C /tmp; \
    cp /tmp/sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box \
       "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}/sing-box"; \
    chmod +x "/opt/forgepanel-cores/sing-box-${SINGBOX_VERSION}/sing-box"

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
