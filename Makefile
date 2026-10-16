# Syncbox developer tasks.
#
# Toolchains are picked up from the usual user-level install locations so these
# tasks work on a machine where cargo and go are not on PATH. Those entries are
# harmless when the tools are already available.

export PATH := $(HOME)/.cargo/bin:$(HOME)/.local/go/bin:$(HOME)/go/bin:$(PATH)

CLIENT       := client
SERVER       := server
COMPOSE      := docker compose -f deploy/docker-compose.yml

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "Syncbox developer tasks:"
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) \
		| sed 's/^\([a-zA-Z0-9_.-]*\):.*## /\1\t/' \
		| awk -F '\t' '{ printf "  %-12s %s\n", $$1, $$2 }'

.PHONY: fmt
fmt: ## Format Rust and Go sources in place
	@$(MAKE) --no-print-directory rust-fmt go-fmt

.PHONY: check
check: ## Format check, lint, and test both languages
	@$(MAKE) --no-print-directory rust-check go-check

.PHONY: test
test: ## Run every test
	@$(MAKE) --no-print-directory rust-test go-test

.PHONY: build
build: ## Build the client workspace and the server binary
	@$(MAKE) --no-print-directory rust-build go-build

.PHONY: tidy
tidy: ## Tidy the Go module
	cd $(SERVER) && go mod tidy

# --- Rust -------------------------------------------------------------------

.PHONY: rust-fmt
rust-fmt:
	cd $(CLIENT) && cargo fmt --all

.PHONY: rust-check
rust-check:
	cd $(CLIENT) && cargo fmt --all -- --check
	cd $(CLIENT) && cargo clippy --workspace --all-targets -- -D warnings
	cd $(CLIENT) && cargo test --workspace

.PHONY: rust-build
rust-build:
	cd $(CLIENT) && cargo build --workspace

.PHONY: rust-test
rust-test:
	cd $(CLIENT) && cargo test --workspace

# --- Go ---------------------------------------------------------------------

.PHONY: go-fmt
go-fmt:
	cd $(SERVER) && gofmt -w .

.PHONY: go-check
go-check:
	@out="$$(cd $(SERVER) && gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	cd $(SERVER) && go vet ./...
	@$(MAKE) --no-print-directory go-lint
	cd $(SERVER) && go test -race ./...

.PHONY: go-lint
go-lint: ## Run staticcheck, if it is installed
	@if command -v staticcheck >/dev/null 2>&1; then \
		cd $(SERVER) && staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

.PHONY: go-build
go-build:
	cd $(SERVER) && go build -o bin/syncboxd ./cmd/syncboxd

.PHONY: go-test
go-test:
	cd $(SERVER) && go test -race ./...

.PHONY: go-cover
go-cover: ## Write an HTML coverage report for the server
	cd $(SERVER) && go test -coverprofile=coverage.out ./...
	cd $(SERVER) && go tool cover -html=coverage.out -o coverage.html

# --- Local server -----------------------------------------------------------

.PHONY: serve
serve: ## Run the server on the host, without Docker
	cd $(SERVER) && go run ./cmd/syncboxd serve

.PHONY: up
up: ## Build and start the server with docker compose
	$(COMPOSE) up --build

.PHONY: down
down: ## Stop the server
	$(COMPOSE) down

.PHONY: clean
clean: ## Remove build artefacts
	cd $(CLIENT) && cargo clean
	rm -rf $(SERVER)/bin $(SERVER)/coverage.out $(SERVER)/coverage.html
