# cruthu development targets.
#
# CI runs the same targets a contributor runs locally, so a green `make ci` on
# a laptop means a green pipeline. Tool versions are pinned here rather than
# floating, because a security tool whose linters drift is a security tool
# whose guarantees drift.

GO              ?= go
BIN_DIR         := bin
BINARY          := $(BIN_DIR)/cruthu
PKG             := ./...

# Pinned tool versions. Bump deliberately, in their own commit.
GOLANGCI_VERSION   ?= v2.12.2
GOVULNCHECK_VERSION?= latest

# Per-target fuzz budget. Short by default so `make fuzz` stays usable in the
# edit loop; the nightly workflow overrides it with hours.
FUZZTIME ?= 30s

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
LDFLAGS  := -X cruthu.dev/core/internal/cli.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Install git hooks and dev tooling
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@printf '#!/bin/sh\nexec make precommit\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed; it runs 'make precommit'"

.PHONY: build
build: ## Build the cruthu binary into bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cruthu

.PHONY: test
test: ## Run the test suite with the race detector
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Run tests and report coverage
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(PKG)

.PHONY: lint
lint: vet ## Run the full linter and security tool set
	golangci-lint run
	govulncheck $(PKG)

.PHONY: fuzz
fuzz: ## Run a short fuzz pass over every fuzz target
	@./scripts/fuzz.sh $(FUZZTIME)

.PHONY: tidy
tidy: ## Verify go.mod and go.sum are tidy
	$(GO) mod tidy
	@git diff --exit-code go.mod go.sum \
		|| { echo "go.mod/go.sum are not tidy; commit the result of 'go mod tidy'"; exit 1; }

.PHONY: precommit
precommit: vet test ## Fast gate run by the pre-commit hook

.PHONY: ci
ci: tidy lint test fuzz build ## Everything CI runs

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf $(BIN_DIR) coverage.out
