VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
    -X main.version=$(VERSION) \
    -X main.commit=$(COMMIT) \
    -X main.date=$(DATE)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/vaultless ./cmd/vaultless/

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/vaultless/

.PHONY: test
test:
	go test -race ./...

.PHONY: test-integration
test-integration:
	go test -race -tags=integration ./...

.PHONY: test-e2e
test-e2e: build
	bash scripts/test-e2e.sh

.PHONY: lint
lint:
	golangci-lint run

.PHONY: bench
bench:
	go test -bench=. -benchmem ./...

.PHONY: clean
clean:
	rm -rf bin/ dist/

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: all
all: fmt vet test build
