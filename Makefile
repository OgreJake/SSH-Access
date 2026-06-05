# Use '>' as the recipe prefix so the file doesn't depend on literal tabs.
.RECIPEPREFIX := >
.DEFAULT_GOAL := help

GO            ?= go
BIN           := bin/broker
MIGRATIONS    := internal/store/migrations
MIGRATE_DSN   ?= $(SSHBROKER_DATABASE_URL)

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

.PHONY: migrate-up
migrate-up: ## Apply all migrations (needs golang-migrate + SSHBROKER_DATABASE_URL)
> migrate -path $(MIGRATIONS) -database "$(MIGRATE_DSN)" up

.PHONY: migrate-down
migrate-down: ## Roll back the last migration
> migrate -path $(MIGRATIONS) -database "$(MIGRATE_DSN)" down 1

.PHONY: docker-up
docker-up: ## Start local Postgres
> docker compose up -d

.PHONY: docker-down
docker-down: ## Stop local Postgres
> docker compose down
