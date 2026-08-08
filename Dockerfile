# syntax=docker/dockerfile:1
#
# ForgePanel — multi-stage build producing fully static binaries.
#
#   docker build -t forgepanel:latest .
#   docker run -d --name forgepanel -p 2053:2053 \
#     -v forgepanel-data:/var/lib/forgepanel forgepanel:latest
#
# ---- build ------------------------------------------------------------------
# go.mod requires go 1.25; keep this image at or above that.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src

# Resolve dependencies first so edits to the source do not invalidate the
# module cache layer.
COPY go.mod go.sum ./
RUN go mod download
# Same mirror-resilient apk as the runtime stage (see the note there).
RUN set -eux; \
    v="v$(cut -d. -f1,2 /etc/alpine-release)"; \
    ok=; \
    for m in \
      https://dl-cdn.alpinelinux.org/alpine \
      https://alpine.global.ssl.fastly.net/alpine \
      https://uk.alpinelinux.org/alpine \
      https://mirror.leaseweb.com/alpine ; do \
      printf '%s/%s/main\n%s/%s/community\n' "$m" "$v" "$m" "$v" > /etc/apk/repositories; \
      n=0; while [ "$n" -lt 3 ]; do \
        if apk add --no-cache bash curl libgcc libstdc++ unzip; then ok=1; break; fi; \
        n=$((n+1)); echo "apk via $m failed (try $n) — retrying"; sleep 3; \
      done; \
      [ -n "$ok" ] && break; \
    done; \
    [ -n "$ok" ] || { echo 'ERROR: every Alpine mirror was unreachable from the build network'; exit 1; }
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"
COPY . .
RUN cd frontend && bun install && bun run build

# Build identity, passed by the release workflow so a container reports the same
# version as the binaries cut from the same tag. The defaults keep a local
# `docker build` honest: it says "dev" rather than claiming a release.
ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_DATE=""

# The sqlite driver is pure Go, so cgo stays off and the result is static.
ARG TARGETOS
ARG TARGETARCH
RUN VP=github.com/forgepanel/forgepanel/internal/version && \
    LD="-s -w -X ${VP}.Version=${VERSION} -X ${VP}.Commit=${COMMIT} -X ${VP}.Date=${BUILD_DATE}" && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD}" -o /out/forgepanel ./cmd/forgepanel && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD} -X main.version=${VERSION}" -o /out/forgectl ./cmd/forgectl && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="${LD} -X main.version=${VERSION}" -o /out/forgenode ./cmd/forgenode

# ---- runtime ----------------------------------------------------------------
# Alpine rather than distroless: the panel is an operations tool, and having a
# shell for `docker exec` when a tunnel misbehaves is worth the ~8MB.
FROM alpine:3.21

ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_DATE=""

LABEL org.opencontainers.image.title="ForgePanel" \
      org.opencontainers.image.description="Self-hosted multi-protocol proxy management panel with a config studio, subscriptions, DNS tunnelling and remote nodes." \
      org.opencontainers.image.source="https://github.com/paranoideveloper/forgepanel" \
      org.opencontainers.image.url="https://github.com/paranoideveloper/forgepanel" \
      org.opencontainers.image.documentation="https://github.com/paranoideveloper/forgepanel/blob/main/docs/INSTALL.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# ca-certificates: required to talk to Let's Encrypt and any outbound HTTPS.
# libcap: to grant the narrow port-binding capability below.
# gcompat: the official sing-box release binaries (fetched at runtime by binmgr)
#   are glibc-dynamically-linked (interpreter /lib64/ld-linux-x86-64.so.2). Alpine
#   is musl, so without a glibc shim every sing-box exec fails with "no such file
#   or directory" (exit 127) and Hysteria2/TUIC/AnyTLS/ShadowTLS/WireGuard/SSH are
#   all dead in the container. gcompat provides the loader + libc shim; verified by
#   running the pinned sing-box-1.13.15 binary under it. (Xray ships static and
#   does not need it, but gcompat is harmless there.)
# apk index fetches fail on flaky, rate-limited or partly-censored build networks
# ("temporary error (try again later)"). Retry across several mirrors so the build
# succeeds anywhere with any working egress instead of dying on one bad CDN.
RUN set -eux; \
    v="v$(cut -d. -f1,2 /etc/alpine-release)"; \
    pkgs="ca-certificates tzdata libcap gcompat wireguard-tools iptables nftables iproute2"; \
    ok=; \
    for m in \
      https://dl-cdn.alpinelinux.org/alpine \
      https://alpine.global.ssl.fastly.net/alpine \
      https://uk.alpinelinux.org/alpine \
      https://mirror.leaseweb.com/alpine \
      https://mirrors.edge.kernel.org/alpine ; do \
      printf '%s/%s/main\n%s/%s/community\n' "$m" "$v" "$m" "$v" > /etc/apk/repositories; \
      n=0; while [ "$n" -lt 3 ]; do \
        if apk add --no-cache $pkgs; then ok=1; break; fi; \
        n=$((n+1)); echo "apk via $m failed (try $n) — retrying"; sleep 3; \
      done; \
      [ -n "$ok" ] && break; \
    done; \
    [ -n "$ok" ] || { echo 'ERROR: every Alpine mirror was unreachable from the build network'; exit 1; }

COPY --from=build /out/forgepanel /usr/local/bin/forgepanel
COPY --from=build /out/forgectl   /usr/local/bin/forgectl
COPY --from=build /out/forgenode /usr/local/bin/forgenode

# PRIVILEGES. The container runs as a non-root user. The panel still needs to
# bind privileged ports (80/443 for ACME and HTTPS, 53/udp for ForgeDNS), so it
# is granted exactly CAP_NET_BIND_SERVICE on the binary — the one capability
# that covers "bind below 1024" — instead of reverting the whole container to
# root for it. Nothing else is granted.
#
# Two features need more, and only if you use them:
#   --cap-add=NET_ADMIN   hysteria2 port-hopping (installs nftables/iptables
#                         redirect rules), and some ForgeDNS setups.
# Without it the panel runs normally; those specific features report an error
# rather than failing silently.
RUN addgroup -g 65532 -S forge && \
    adduser -u 65532 -S -G forge -h /var/lib/forgepanel forge && \
    mkdir -p /var/lib/forgepanel && \
    chown -R forge:forge /var/lib/forgepanel && \
    chmod 700 /var/lib/forgepanel

ENV FORGEPANEL_DATA=/var/lib/forgepanel

WORKDIR /var/lib/forgepanel
VOLUME ["/var/lib/forgepanel"]

# 2053 panel · 2054 REST API · 2096 subscriptions · 80/443 ACME + HTTPS.
# ForgeDNS listens on 53/udp when enabled; publish it with `-p 53:53/udp`.
EXPOSE 2053 2054 2096 80 443

USER forge

# `forgectl healthcheck` probes HTTPS then HTTP and follows the configured port,
# so the check keeps working once a domain turns the panel into an HTTPS server.
# A plain `wget http://…` probe would report unhealthy in exactly that case.
# Timeout covers both attempts (4s each) with margin.
HEALTHCHECK --interval=30s --timeout=12s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/forgectl", "healthcheck"]

# Exec form, so the panel is PID 1 and receives SIGTERM directly for a clean
# shutdown (it stops the engines and releases the data-directory lock).
# No credentials or state are generated at build time: the first-run setup token
# is minted on first boot, is single-use and expires on a timer.
CMD ["/usr/local/bin/forgepanel"]
