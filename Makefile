# ForgePanel build orchestration (spec §15 `make check`).
GO ?= go
BIN := bin
LDFLAGS := -s -w

.PHONY: all build check test vet fmt run studio clean install-tools

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/forgepanel ./cmd/forgepanel
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/forgectl  ./cmd/forgectl

check: vet test
	@echo "✅ make check passed"

test:
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

run: build
	./$(BIN)/forgepanel

clean:
	rm -rf $(BIN)
