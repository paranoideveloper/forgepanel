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
        docker docker-run release snapshot clean help

all: build

build:
	@mkdir -p $(BIN)
	@for cmd in $(CMDS); do \
	  echo "  build  $$cmd"; \
	  $(BUILDENV) $(GO) build $(BUILDFLAGS) -o $(BIN)/$$cmd ./cmd/$$cmd || exit 1; \
	done

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN)/forgepanel $(DESTDIR)$(PREFIX)/bin/forgepanel
	install -m 0755 $(BIN)/forgectl   $(DESTDIR)$(PREFIX)/bin/forgectl
	install -m 0755 $(BIN)/forgenode  $(DESTDIR)$(PREFIX)/bin/forgenode
	install -d -m 0700 $(DESTDIR)$(DATADIR)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 packaging/systemd/forgepanel.service $(DESTDIR)$(UNITDIR)/forgepanel.service
	@echo "Installed. Enable with: systemctl daemon-reload && systemctl enable --now forgepanel"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/forgepanel $(DESTDIR)$(PREFIX)/bin/forgectl $(DESTDIR)$(PREFIX)/bin/forgenode
	rm -f $(DESTDIR)$(UNITDIR)/forgepanel.service
	@echo "Removed binaries and unit. Data left in $(DATADIR)."

check: vet test
	@echo "make check passed"

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
	rm -rf $(BIN) dist

help:
	@grep -E '^[a-z-]+:' $(MAKEFILE_LIST) | cut -d: -f1 | sort -u
