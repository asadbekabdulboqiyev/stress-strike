# Makefile for stress-strike — build, test, lint, release helpers.
#
# Usage:
#   make build      build stress-strike + demo server into ./bin
#   make test       run tests with the race detector
#   make vet        run go vet
#   make lint       go vet + gofmt formatting check
#   make coverage   produce a test coverage report (coverage.out)
#   make bench      run benchmarks
#   make clean      remove build artifacts (bin/, dist/, coverage)
#   make install    install stress-strike into PATH (GOBIN/GOPATH/bin)
#   make release    cross-compile for all platforms into ./dist
#   make help       list all targets

# Release version used for dist/ naming and Docker image labels.
# Override on the CLI:  make release VERSION=1.2.3
VERSION ?= 0.2.0

GO       ?= go
GOFLAGS  ?=
BIN_DIR   := bin
DIST_DIR  := dist

.PHONY: build
build: ## Build stress-strike and the demo server into ./bin
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/stress-strike ./cmd/stress-strike
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/demo-server ./examples/demo_server.go
	@echo "built: $(BIN_DIR)/stress-strike, $(BIN_DIR)/demo-server"

.PHONY: test
test: ## Run the full test suite with the race detector
	$(GO) test -race ./...

.PHONY: vet
vet: ## Run go vet across the whole module
	$(GO) vet ./...

.PHONY: lint
lint: vet ## go vet + gofmt formatting check (fails on any unformatted file)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: unformatted files found:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "gofmt: all files formatted"

.PHONY: coverage
coverage: ## Run tests and write coverage.out (+ overall summary line)
	$(GO) test -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1

.PHONY: bench
bench: ## Run Go benchmarks (no regular tests)
	$(GO) test -bench=. -run=^$$ ./...

.PHONY: clean
clean: ## Remove build artifacts: bin/, dist/, coverage files
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out coverage.html

.PHONY: install
install: ## Install stress-strike into PATH (defaults to GOBIN/GOPATH/bin)
	$(GO) install $(GOFLAGS) ./cmd/stress-strike

.PHONY: release
release: ## Cross-compile for all platforms into ./dist (static binaries)
	VERSION=$(VERSION) ./scripts/build-all.sh

.PHONY: help
help: ## List all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'
