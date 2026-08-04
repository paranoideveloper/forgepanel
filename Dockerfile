# ForgePanel — multi-stage build, distroless runtime, non-root (spec §14).
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/forgepanel ./cmd/forgepanel \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/forgectl  ./cmd/forgectl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/forgepanel /usr/local/bin/forgepanel
COPY --from=build /out/forgectl  /usr/local/bin/forgectl
ENV FORGEPANEL_DATA=/data
VOLUME ["/data"]
EXPOSE 2053 2096 2054 53/udp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/forgepanel"]
