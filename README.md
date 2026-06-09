# sshbroker

A self-hosted SSH access broker: it brokers user connections to internal hosts,
issues short-lived SSH certificates (with a brokered-credential fallback for
legacy targets), authorizes access via group-to-group grants, and records
session activity. See [`DECISIONS.md`](./DECISIONS.md) for the architecture and
rationale.

> **Status: Phase 1 (+ KMS CA backend).** On top of the Phase 0 foundations,
> the broker mints short-lived, tightly-constrained SSH user certificates
> (`internal/ca`). The CA key can be a dev file key (`SSHBROKER_CA_BACKEND=file`)
> or an **AWS KMS** asymmetric key that never leaves KMS
> (`SSHBROKER_CA_BACKEND=kms`, `internal/signer/kmsca`, ADR-006). The SSH proxy
> that uses these certs to broker connections arrives in Phase 2.

## Production CA: AWS KMS

Set `SSHBROKER_CA_BACKEND=kms` and `SSHBROKER_KMS_KEY_ID` to an asymmetric KMS
key (`ECC_NIST_P256`, key usage `SIGN_VERIFY`). The broker authenticates with
its EC2 instance role — no static credentials. The private key never leaves
KMS: signing sends KMS the certificate digest and KMS returns the signature,
and every call is logged to CloudTrail. The broker fetches and validates the
public key at startup, so a missing key or insufficient permissions fails fast.

## Layout

```
cmd/broker/            Entry point (wiring + health server)
internal/config/       Environment-based configuration
internal/model/        Domain types (mirror the DB schema)
internal/signer/       CA key custody (Authority) + dev FileAuthority
internal/ca/           Certificate issuance policy (Issuer) + serial allocator
internal/secrets/      Credential store (Store) + dev FileStore
internal/store/        PostgreSQL pool + migrations/
```

The `signer.Authority` and `secrets.Store` interfaces are the seams where the
production AWS KMS backends drop in later (ADR-006 / ADR-009) without touching
callers. `ca.Issuer` is the policy layer that decides what every certificate
may contain (lifetime, principals, source-address pin, capabilities, audit key
ID) regardless of which signing backend is in use.

## Prerequisites

- Go 1.24+ (the AWS SDK requires it; 1.25 recommended)
- Docker (for local Postgres) or your own PostgreSQL 13+
- `ssh-keygen` and `openssl` (for dev key generation)
- Optional: [`golang-migrate`](https://github.com/golang-migrate/migrate) CLI,
  `golangci-lint`, `govulncheck`

## Quickstart

```bash
# 1. Resolve dependencies (needs normal network access to the Go module proxy)
make tidy

# 2. Start Postgres (uses the compose plugin, docker-compose, or a plain
#    `docker run` — whichever is available; container is named sshbroker-pg)
make docker-up

# 3. Apply the schema. Either via golang-migrate (run through `go run`, no
#    install needed) ...
export SSHBROKER_DATABASE_URL='postgres://broker:broker@localhost:5432/broker?sslmode=disable'
make migrate-up
#    ... or, with no migrate tooling at all, pipe the SQL into the container:
# make db-load

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
