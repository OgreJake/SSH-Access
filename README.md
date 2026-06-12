# sshbroker

A self-hosted SSH access broker: it brokers user connections to internal hosts,
issues short-lived SSH certificates (with a brokered-credential fallback for
legacy targets), authorizes access via group-to-group grants, and records
session activity. See [`DECISIONS.md`](./DECISIONS.md) for the architecture and
rationale.

> **Status: Phase 2 complete (through 2e).** The broker authenticates the
> user, resolves `login+host`, authorizes against policy, mints a per-session
> certificate (file or KMS CA), dials the target, and proxies the session with
> capability gating and host-key verification. Every brokered session is now
> recorded to PostgreSQL (`sessions`) and appended to a tamper-evident,
> hash-chained `audit_log` (ADR-015); `broker -verify-audit` re-checks the
> chain. Authentication and authorization can now both run against the
> database (`SSHBROKER_AUTH_BACKEND=db`, `SSHBROKER_AUTHZ_BACKEND=db`): keys
> resolve to users (multi-key) or service accounts with disabled accounts
> refused, and access is decided by group-to-group RBAC grants (capabilities
> union, longest permitted TTL). Connections may be addressed as
> `account+host` (explicit), or `host` / `you+host` to let the broker derive
> the account from your grant (ADR-019) — so a user reaches many shared-account
> hosts via one grant, while sessions stay attributed to the user. The
> `broker admin` CLI manages these records, and a separate management plane — a
> JSON API (`cmd/api`) plus a Vite/React admin UI (`web/`) — exposes the same
> operations over HTTP. Sessions can be **terminated** on demand or when an
> account is disabled (ADR-016), and grants can opt into **full session
> recording** to asciinema `.cast` files (ADR-011). Port forwarding has been
> descoped (ADR-014). Still deferred: a real login flow + MFA, the KMS-backed
> secret store, Mode B legacy credentials, grant-recertification surfacing, and
> session timeouts/rotation/alerting.

Connect with `ssh <target-login>+<target-host>@broker -p 2222`. The broker
identifies you by your key; the username carries the target.

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
internal/proxy/        SSH front door: auth, target resolution, authorization,
                       cert minting, target dial, and session proxying
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

## Managing the database (admin CLI)

`broker admin` seeds and manages the records the DB backends read. It needs only
`SSHBROKER_DATABASE_URL`. Keys are normalized to the exact form authentication
looks up, so a key added here will resolve at connect time.

```sh
broker admin add-user            -username alice -email alice@example.com
broker admin add-key             -user alice -key-file ~/.ssh/id_ed25519.pub -comment laptop
broker admin add-server          -hostname web01 -address 10.0.0.5 -port 22 \
                                  -host-key-fp SHA256:... -principals deploy,ec2-user
broker admin create-user-group   -name deployers
broker admin add-user-to-group   -user alice -group deployers
broker admin create-server-group -name web-tier
broker admin add-server-to-group -server web01 -group web-tier
broker admin add-grant           -subject-group deployers -server-group web-tier \
                                  -principals deploy -ttl 10m -shell -exec
broker admin set-user-status     -username alice -status disabled

broker admin list-users | list-servers | list-grants
```

Run `broker admin` with no arguments for the full command list.
