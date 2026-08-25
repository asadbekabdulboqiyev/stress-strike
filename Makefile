# Makefile for stress-strike — build, test, lint, release helpers.
#
# Usage:
#   make build       Build all stress-strike binaries into ./bin
#   make test        Run tests with the race detector
#   make lint        go vet + gofmt check
#   make clean       Remove bin/ and reports/
#   make release     Cross-compile for all platforms
#   make docker      Build Docker image
#   make run         Build and run demo server
#   make help        List all targets

VERSION ?= 0.4.0

GO      ?= go
GOFLAGS ?=
BIN_DIR  := bin
DIST_DIR := dist

.PHONY: build
build: ## Build all binaries into ./bin
	./scripts/build-all.sh

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

.PHONY: clean
clean: ## Remove bin/ and reports/
	rm -rf $(BIN_DIR) $(DIST_DIR) reports coverage.out coverage.html

.PHONY: release
release: ## Cross-compile for all platforms into ./dist
	VERSION=$(VERSION) ./scripts/release.sh v$(VERSION)

.PHONY: docker
docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) -t stress-strike:$(VERSION) .
	docker tag stress-strike:$(VERSION) stress-strike:latest
	@echo "docker image built: stress-strike:$(VERSION)"

.PHONY: run
run: build ## Build and run the demo server
	$(GO) run ./examples/demo_server.go &
	@sleep 1
	$(BIN_DIR)/stress-strike run --url http://localhost:8080 --users 10 --duration 5

.PHONY: help
help: ## List all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'
