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

VERSION ?= 0.14.0

GO      ?= go
GOFLAGS ?=
BIN_DIR  := bin
DIST_DIR := dist

.PHONY: build
build: ## Build all binaries into ./bin
	./scripts/build-all.sh $(VERSION)

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

.PHONY: worker-linux
worker-linux: ## Cross-compile Linux worker packages (amd64 + arm64) into ./dist
	VERSION=$(VERSION) ./scripts/build-worker-linux.sh $(VERSION)

.PHONY: docker-worker
docker-worker: ## Build the distributed worker Docker image
	docker build -f Dockerfile.worker --build-arg VERSION=$(VERSION) -t stress-strike-worker:$(VERSION) .
	@echo "docker worker image built: stress-strike-worker:$(VERSION)"

.PHONY: docker-master
docker-master: ## Build the master/coordinator Docker image
	docker build -f Dockerfile.master --build-arg VERSION=$(VERSION) -t stress-strike-master:$(VERSION) .
	@echo "docker master image built: stress-strike-master:$(VERSION)"

.PHONY: deploy
deploy: ## Friendly launcher: Docker fleet (local) or VPS fleet (SSH)
	./scripts/deploy.sh

.PHONY: deploy-docker
deploy-docker: ## Run a Docker fleet locally (master + N workers)
	./scripts/deploy-docker.sh

.PHONY: deploy-fleet
deploy-fleet: ## Put workers on real Linux hosts over SSH (interactive wizard)
	./scripts/deploy-fleet.sh

.PHONY: docker-down
docker-down: ## Stop + remove the locally deployed Docker fleet
	./scripts/deploy-docker.sh down

.PHONY: coverage
coverage: ## Run tests with coverage report
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: bench
bench: ## Run all benchmarks
	$(GO) test -bench=. -benchmem ./...

.PHONY: bench-power
bench-power: ## Real-world throughput sweep against the demo server (POWER)
	./scripts/bench.sh

.PHONY: install
install: ## Build and install stress-strike into PATH
	$(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(GOBIN)/stress-strike ./cmd/stress-strike

.PHONY: version
version: ## Print the current version
	@echo "stress-strike v$(VERSION)"

.PHONY: run
run: build ## Build and run the demo server
	$(GO) run ./examples/demo_server.go &
	@sleep 1
	$(BIN_DIR)/stress-strike run --url http://localhost:8080 --users 10 --duration 5

.PHONY: demo-store
demo-store: ## Run the VoltStore e-commerce demo (VeriGate OFF)
	$(GO) run ./examples/demo_store

.PHONY: demo-store-protect
demo-store-protect: ## Run the VoltStore demo with VeriGate protection ON
	$(GO) run ./examples/demo_store -protect

.PHONY: demo-sla
demo-sla: ## VeriGate SLA verify gate demo (ON->SLA FAIL, OFF->SLA PASS)
	./scripts/demo-store-sla.sh

.PHONY: help
help: ## List all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'
