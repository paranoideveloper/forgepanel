# syntax=docker/dockerfile:1
#
# ForgePanel — multi-stage build producing fully static binaries.
#
#   docker build -t forgepanel:latest .
#   docker run -d --name forgepanel -p 2053:2053 -v forgepanel-data:/var/lib/forgepanel forgepanel:latest
#
# NOTE ON PRIVILEGES: the container runs as root so the panel can bind the low
# ports it needs (80/443 for ACME + HTTPS, 53/udp for ForgeDNS). If you only
# expose the panel port you can drop privileges with `--user 65532:65532`.
# Features that reshape host networking (hysteria2 port-hopping, ForgeDNS)
# additionally need `--cap-add=NET_ADMIN`.

# ---- build ------------------------------------------------------------------
# go.mod requires go 1.25; keep this image at or above that.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src

# Resolve dependencies first so edits to the source do not invalidate the
# module cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The sqlite driver is pure Go, so cgo stays off and the result is static.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="-s -w" -o /out/forgepanel ./cmd/forgepanel && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath -ldflags="-s -w" -o /out/forgectl   ./cmd/forgectl

# ---- runtime ----------------------------------------------------------------
# Alpine rather than distroless: the panel is an operations tool, and having a
# shell for `docker exec` when a tunnel misbehaves is worth the ~8MB.
FROM alpine:3.21

# ca-certificates: required to talk to Let's Encrypt and any outbound HTTPS.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /out/forgepanel /usr/local/bin/forgepanel
COPY --from=build /out/forgectl   /usr/local/bin/forgectl

ENV FORGEPANEL_DATA=/var/lib/forgepanel \
    FORGEPANEL_PANEL_PORT=2053

WORKDIR /var/lib/forgepanel
VOLUME ["/var/lib/forgepanel"]

# 2053 panel · 2054 REST API · 2096 subscriptions · 80/443 ACME + HTTPS.
# ForgeDNS listens on 53/udp when enabled; publish it with `-p 53:53/udp`.
EXPOSE 2053 2054 2096 80 443

# `forgectl healthcheck` probes HTTPS then HTTP and follows the configured port,
# so the check keeps working once a domain turns the panel into an HTTPS server.
# A plain `wget http://…` probe would report unhealthy in exactly that case.
# Timeout covers both attempts (4s each) with margin.
HEALTHCHECK --interval=30s --timeout=12s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/forgectl", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/forgepanel"]
