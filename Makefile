# ForgePanel build orchestration.
#
#   make build      static binaries into ./bin
#   make check      vet + test (what CI runs)
#   make install    install binaries + systemd unit onto this host
#   make snapshot   local goreleaser build, no tag required

GO      ?= go
BIN     := bin
PREFIX  ?= /usr/local
DESTDIR ?=
DATADIR ?= /var/lib/forgepanel
UNITDIR ?= /etc/systemd/system

CMDS    := forgepanel forgectl forgenode
LDFLAGS := -s -w
# Pure-Go sqlite driver, so cgo stays off and the binaries are fully static.
BUILDENV := CGO_ENABLED=0
BUILDFLAGS := -trimpath -ldflags "$(LDFLAGS)"

IMAGE ?= forgepanel:latest

.PHONY: all build install uninstall check test race vet fmt tidy run \
        docker docker-run release snapshot clean help edge-bundle

all: build

web-build:
	cd frontend && bun install && bun run build

# edge-bundle compiles the ForgeEdge Worker (deploy/cloudflare/forgeedge/src) into
# a single ESM module embedded by internal/edge (//go:embed). Run after changing
# the Worker source; the committed artifact keeps `go build` free of a JS toolchain.
#
# USE BUN 1.4.0 — the same version pinned in the forgeedge-worker CI job. CI
# compares the committed bundle byte-for-byte against a fresh build, and bun's
# minifier renames identifiers between releases, so a bundle built with any
# other bun is rejected even when the source is identical.
edge-bundle:
	cd deploy/cloudflare/forgeedge && bun install && \
	  bun build src/worker.ts --outfile ../../../internal/edge/assets/forgeedge.worker.js \
	  --format=esm --target=browser --external cloudflare:sockets --minify

build: web-build
	@mkdir -p $(BIN)
	@for cmd in $(CMDS); do \
	  echo "  build  $$cmd"; \
	  $(BUILDENV) $(GO) build $(BUILDFLAGS) -o $(BIN)/$$cmd ./cmd/$$cmd || exit 1; \
	done

ifneq ($(strip $(DESTDIR)),)
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN)/forgepanel $(DESTDIR)$(PREFIX)/bin/forgepanel
	install -m 0755 $(BIN)/forgectl   $(DESTDIR)$(PREFIX)/bin/forgectl
	install -m 0755 $(BIN)/forgenode  $(DESTDIR)$(PREFIX)/bin/forgenode
	install -d -m 0700 $(DESTDIR)$(DATADIR)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 packaging/systemd/forgepanel.service $(DESTDIR)$(UNITDIR)/forgepanel.service
	@echo "Installed. Enable with: systemctl daemon-reload && systemctl enable --now forgepanel"
else
install:
	@echo "Host installation is managed by the verified installer or a package; use sudo bash install.sh."
	@exit 2
endif

uninstall:
	@if [ -n "$(DESTDIR)" ]; then \
	  echo "DESTDIR uninstall is intentionally unsupported; remove staged package files with the package manager."; exit 1; \
	fi
	@$(PREFIX)/bin/forgectl uninstall --keep-data

check: frontend-check vet test
	@echo "make check passed"

frontend-check:
	cd frontend && bun run check && bun run test

test:
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

run: build
	./$(BIN)/forgepanel

docker:
	docker build -t $(IMAGE) .

docker-run: docker
	docker run --rm -it \
	  -p 2053:2053 \
	  -v forgepanel-data:/var/lib/forgepanel \
	  --name forgepanel $(IMAGE)

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf $(BIN) dist .singbox-stage

help:
	@grep -E '^[a-z-]+:' $(MAKEFILE_LIST) | cut -d: -f1 | sort -u

e2e: build ## Build the panel and run the Playwright end-to-end suite
	@cp bin/forgepanel e2e/forgepanel-test
	@cd e2e && bunx playwright test
