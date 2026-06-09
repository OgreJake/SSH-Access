# Use '>' as the recipe prefix so the file doesn't depend on literal tabs.
.RECIPEPREFIX := >
.DEFAULT_GOAL := help

GO            ?= go
BIN           := bin/broker
MIGRATIONS    := internal/store/migrations
MIGRATE_DSN   ?= $(SSHBROKER_DATABASE_URL)
PG_CONTAINER  ?= sshbroker-pg

# Run golang-migrate via `go run` so no separate install / PATH setup is
# needed. Override with `make migrate-up MIGRATE=migrate` if you have the CLI
# installed and on your PATH.
MIGRATE       ?= $(GO) run -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1

.PHONY: help
help: ## Show this help
> @grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
>   awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## Resolve and pin module dependencies
> $(GO) mod tidy

.PHONY: build
build: ## Build the broker binary
> $(GO) build -o $(BIN) ./cmd/broker

.PHONY: run
run: ## Run the broker
> $(GO) run ./cmd/broker

.PHONY: test
test: ## Run tests
> $(GO) test ./...

.PHONY: vet
vet: ## go vet
> $(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint (must be installed)
> golangci-lint run

.PHONY: vulncheck
vulncheck: ## Scan dependencies for known vulnerabilities
> govulncheck ./...

.PHONY: gen-ca
gen-ca: ## Generate a dev CA key (ECDSA P-256, matching the prod KMS key spec)
> mkdir -p dev
> ssh-keygen -t ecdsa -b 256 -f dev/ca_key -C "ssh-broker-dev-ca" -N ""
> @echo "Add this line to each target's TrustedUserCAKeys:"
> @cat dev/ca_key.pub

.PHONY: gen-secret-key
gen-secret-key: ## Print a fresh base64 AES-256 key for SSHBROKER_SECRET_STORE_KEY
> @openssl rand -base64 32

.PHONY: gen-host-key
gen-host-key: ## Generate the broker's SSH host key (front door identity)
> mkdir -p dev
> ssh-keygen -t ed25519 -f dev/host_key -C "ssh-broker-host" -N ""

.PHONY: migrate-up
migrate-up: ## Apply all migrations (uses `go run` golang-migrate; needs SSHBROKER_DATABASE_URL)
> $(MIGRATE) -path $(MIGRATIONS) -database "$(MIGRATE_DSN)" up

.PHONY: migrate-down
migrate-down: ## Roll back the last migration
> $(MIGRATE) -path $(MIGRATIONS) -database "$(MIGRATE_DSN)" down 1

.PHONY: db-load
db-load: ## Apply the schema by piping SQL into the Postgres container (no migrate CLI)
> docker exec -i $(PG_CONTAINER) psql -U broker -d broker < $(MIGRATIONS)/0001_init.up.sql

.PHONY: db-reset
db-reset: ## Drop the schema (down migration) via the Postgres container
> docker exec -i $(PG_CONTAINER) psql -U broker -d broker < $(MIGRATIONS)/0001_init.down.sql

.PHONY: docker-up
docker-up: ## Start local Postgres (compose plugin, docker-compose, or plain docker run)
> @if docker compose version >/dev/null 2>&1; then \
>   docker compose up -d; \
> elif command -v docker-compose >/dev/null 2>&1; then \
>   docker-compose up -d; \
> else \
>   echo "compose not found; starting a plain container named $(PG_CONTAINER)"; \
>   docker run -d --name $(PG_CONTAINER) \
>     -e POSTGRES_USER=broker -e POSTGRES_PASSWORD=broker -e POSTGRES_DB=broker \
>     -p 127.0.0.1:5432:5432 postgres:16; \
> fi

.PHONY: docker-down
docker-down: ## Stop local Postgres
> @if docker compose version >/dev/null 2>&1; then \
>   docker compose down; \
> elif command -v docker-compose >/dev/null 2>&1; then \
>   docker-compose down; \
> else \
>   docker rm -f $(PG_CONTAINER); \
> fi
