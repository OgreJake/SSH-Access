# sshbroker

A self-hosted SSH access broker: it brokers user connections to internal hosts,
issues short-lived SSH certificates (with a brokered-credential fallback for
legacy targets), authorizes access via group-to-group grants, and records
session activity. See [`DECISIONS.md`](./DECISIONS.md) for the architecture and
rationale.

> **Status: Phase 0 — Foundations.** This repo currently contains the project
> skeleton: configuration, the data model and migrations, the CA-signer and
> secret-store interfaces with their dev (file-based) backends, and a health
> server. The SSH proxy, certificate issuance, RBAC engine, API, and web UI
> arrive in later phases.

## Layout

```
cmd/broker/            Entry point (wiring + health server)
internal/config/       Environment-based configuration
internal/model/        Domain types (mirror the DB schema)
internal/signer/       CA abstraction (Authority) + dev FileAuthority
internal/secrets/      Credential store (Store) + dev FileStore
internal/store/        PostgreSQL pool + migrations/
```

The `signer.Authority` and `secrets.Store` interfaces are the seams where the
production AWS KMS backends drop in later (ADR-006 / ADR-009) without touching
callers.

## Prerequisites

- Go 1.22+
- Docker (for local Postgres) or your own PostgreSQL 13+
- `ssh-keygen` and `openssl` (for dev key generation)
- Optional: [`golang-migrate`](https://github.com/golang-migrate/migrate) CLI,
  `golangci-lint`, `govulncheck`

## Quickstart

```bash
# 1. Resolve dependencies (needs normal network access to the Go module proxy)
make tidy

# 2. Start Postgres
make docker-up

# 3. Apply the schema
export SSHBROKER_DATABASE_URL='postgres://broker:broker@localhost:5432/broker?sslmode=disable'
make migrate-up

# 4. Generate a dev CA key and a secret-store key
make gen-ca
export SSHBROKER_SECRET_STORE_KEY="$(make -s gen-secret-key)"

# 5. Run
make run
# -> health:  curl localhost:8080/healthz
# -> ready:   curl localhost:8080/readyz   (also pings the DB)
```

All settings come from `SSHBROKER_*` environment variables — see
[`.env.example`](./.env.example).

## Development

```bash
make test       # unit tests
make vet        # go vet
make lint       # golangci-lint
make vulncheck  # govulncheck
```

## Security notes

- The dev CA key (`dev/`) and secret-store key are **for local use only** and
  must never be committed or used in production. Production keys live in AWS
  KMS.
- Certificates issued by this broker are short-lived and source-address-pinned
  (ADR-007); the dev backend exists only so the system is runnable end-to-end
  before the KMS wiring lands.
