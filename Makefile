# Makefile for Sift — build, test, lint, release helpers.
#
# Usage:
#   make build       Build all Sift binaries into ./bin
#   make test        Run tests with the race detector
#   make lint        go vet + gofmt check
#   make verifier    Verify the browser verifier (tests + drift guard + Go<=>JS parity)
#   make gosec       Run the gosec ratchet (new error-level findings fail)
#   make gosec-test  Self-test the ratchet's own logic (no gosec needed)
#   make clean       Remove bin/ and reports/
#   make release     Cross-compile for all platforms
#   make docker      Build Docker image
#   make run         Build and run demo server
#   make help        List all targets

VERSION ?= 0.15.0

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

.PHONY: verifier
verifier: ## Verify the browser verifier: unit tests + drift guard + Go<=>JS parity
	@command -v node >/dev/null || { echo "verifier: node is required (the JavaScript verifier runs on it)"; exit 1; }
	node --test web/verifier/vpmp.test.mjs
	node web/verifier/build-html.mjs --check
	bash scripts/verify-html-parity.sh

.PHONY: verifier-page
verifier-page: ## Regenerate docs/VERIFIER.html from the tested verifier module
	node web/verifier/build-html.mjs

.PHONY: demo-verified
demo-verified: ## Run the LIVE Sift demo (seal -> verify -> one-byte tamper -> restore)
	bash scripts/demo-verified.sh

GOSEC ?= gosec

.PHONY: gosec-test
gosec-test: ## Self-test the gosec ratchet's own logic (synthetic reports; needs only jq)
	bash scripts/gosec-ratchet-test.sh

.PHONY: gosec
gosec: ## Run the gosec ratchet: new error-level findings outside G204/G304 fail
	@command -v $(GOSEC) >/dev/null || { \
		echo "gosec: not on PATH. Install the version CI pins (v2.29.0):"; \
		echo "  GOBIN=$$(go env GOPATH)/bin go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0"; \
		exit 1; \
	}
	$(GOSEC) -no-fail -fmt sarif -out gosec.sarif ./...
	bash scripts/gosec-ratchet.sh gosec.sarif

.PHONY: clean
clean: ## Remove bin/ and reports/
	rm -rf $(BIN_DIR) $(DIST_DIR) reports coverage.out coverage.html gosec.sarif

.PHONY: release
release: ## Cross-compile for all platforms into ./dist
	VERSION=$(VERSION) ./scripts/release.sh v$(VERSION)

.PHONY: docker
docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) -t Sift:$(VERSION) .
	docker tag Sift:$(VERSION) Sift:latest
	@echo "docker image built: Sift:$(VERSION)"

.PHONY: worker-linux
worker-linux: ## Cross-compile Linux worker packages (amd64 + arm64) into ./dist
	VERSION=$(VERSION) ./scripts/build-worker-linux.sh $(VERSION)

.PHONY: docker-worker
docker-worker: ## Build the distributed worker Docker image
	docker build -f Dockerfile.worker --build-arg VERSION=$(VERSION) -t Sift-worker:$(VERSION) .
	@echo "docker worker image built: Sift-worker:$(VERSION)"

.PHONY: docker-master
docker-master: ## Build the master/coordinator Docker image
	docker build -f Dockerfile.master --build-arg VERSION=$(VERSION) -t Sift-master:$(VERSION) .
	@echo "docker master image built: Sift-master:$(VERSION)"

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
install: ## Build, install and macOS-sign every binary into PATH
	./scripts/install-local.sh $(VERSION)

.PHONY: sign
sign: ## Repair macOS code signatures in place (fixes "zsh: killed" / rc=137)
	@dest="$${SIFT_INSTALL_DIR:-$$(go env GOBIN)}"; \
	[ -n "$$dest" ] || dest="$$(go env GOPATH)/bin"; \
	if [ "$$(uname -s)" != "Darwin" ]; then echo "not macOS — nothing to sign"; exit 0; fi; \
	for b in Sift Sift-dashboard Sift-scan Sift-master Sift-replay Sift-worker; do \
	  [ -f "$$dest/$$b" ] || continue; \
	  xattr -d com.apple.provenance "$$dest/$$b" 2>/dev/null || true; \
	  codesign --force --sign - --timestamp=none "$$dest/$$b" >/dev/null 2>&1 || true; \
	  "$$dest/$$b" --version >/dev/null 2>&1; rc=$$?; \
	  if [ $$rc -eq 137 ]; then echo "  FAIL $$b (SIGKILL — still invalid)"; else echo "  ok   $$b"; fi; \
	done

.PHONY: version
version: ## Print the current version
	@echo "Sift v$(VERSION)"

.PHONY: run
run: build ## Build and run the demo server
	$(GO) run ./examples/demo_server.go &
	@sleep 1
	$(BIN_DIR)/Sift run --url http://localhost:8080 --users 10 --duration 5

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
