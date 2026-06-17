# sshbroker

A self-hosted **SSH access broker** (jump host) for teams that need
auditable, least-privilege access to internal hosts without distributing
long-lived keys. Users connect to the broker; the broker authenticates them,
authorizes the request against a role-based policy, mints a **short-lived,
tightly-constrained SSH certificate** for that one session, re-originates the
connection to the target, and records the session to a tamper-evident audit
log. Humans sign in through your identity provider in the browser (SSO + MFA);
automation uses registered keys.

See [`DECISIONS.md`](./DECISIONS.md) for the full architecture and the 21
Architecture Decision Records behind it, and
[`docs/auth-setup.md`](./docs/auth-setup.md) for the end-to-end deployment and
troubleshooting guide.

---

## Why this exists

Traditional SSH access tends to sprawl into long-lived keys on laptops, shared
accounts with no attribution, and no central record of who reached what. This
broker addresses that:

- **No standing credentials for humans.** Each connection is gated by a fresh
  browser SSO/MFA approval; the certificate the broker mints lives only for the
  session and is constrained to a single target and principal.
- **The broker is the only path in.** It terminates the user's SSH session and
  opens a *separate* connection to the target, so every session can be
  authorized, attributed to a real person, and recorded — there is no tunnel to
  ride around the policy.
- **Authorization is centralized and reviewable.** Access is expressed as
  group-to-group grants (your users → target accounts) with capabilities and
  TTLs, recertification dates, and a CSV "who can access what" export.
- **Everything is audited.** Session metadata and management actions are written
  to a hash-chained `audit_log` that can be verified for tampering, and grants
  can opt into full session recording.

---

## Key features

- **SSH certificate authority** with a production **AWS KMS** backend
  (`ECC_NIST_P256`, `SIGN_VERIFY`, EC2 instance role, IMDSv2) and a file backend
  for development. The CA private key never leaves KMS.
- **Browser SSO/MFA for interactive users** (ADR-021): stock `ssh`, nothing
  installed on the client. The broker prints an approval URL; the user
  authenticates through your identity provider (via oauth2-proxy) and approves;
  the handshake completes. Per-connection by design.
- **Service accounts** authenticate by registered key and are MFA-exempt, so
  automation (Ansible, CI, etc.) is never prompted.
- **`login+host` addressing** with grant-derived accounts (ADR-019): connect as
  `account+host`, or just `host` / `you+host` to let the broker pick the account
  your grant allows — one grant reaches many shared-account hosts while sessions
  stay attributed to you.
- **RBAC grants** (ADR-010): group-to-group, capability union, longest permitted
  TTL, with recertification surfacing (ADR-017).
- **Session recording** (ADR-011): metadata always; opt-in full recording to
  asciinema `.cast`, uploaded to a self-hosted asciinema server and viewed
  behind SSO.
- **Tamper-evident audit log** (ADR-015): hash-chained, exportable, with a
  verification command/endpoint. Failed authorizations and management mutations
  are audited with the real client IP.
- **On-demand session termination** and immediate de-provisioning when an
  account is disabled (ADR-016).
- **Management plane**: a JSON API (`cmd/api`) and a React admin UI (`web/`),
  protected by the same SSO with granular RBAC roles (admin/auditor) and a
  password-based **break-glass** local admin for when the IdP is unavailable
  (ADR-008/020).

---

## Architecture at a glance

```
                              ┌─────────────────────────────────────────┐
   ssh you+web01@broker       │                 broker host              │
  ───────────────────────────▶  cmd/broker  (SSH front door :2222)       │
        (1) keyboard-          │     │  authenticate → authorize →        │
            interactive        │     │  mint cert (KMS CA) → dial target  │──▶ target host
            browser approval   │     ▼                                    │   (trusts broker CA)
                               │  PostgreSQL  (users, grants, sessions,   │
   browser ── SSO/MFA ──┐      │              hash-chained audit_log)     │
                        │      │     ▲                                    │
                        ▼      │  cmd/api  (management JSON API :8081) ◀───┼── React UI (web/)
              oauth2-proxy ────┼─────┘         behind oauth2-proxy/NGINX  │
              (auth.<domain>)  └─────────────────────────────────────────┘
```

Both processes share PostgreSQL. The SSH broker creates a pending login row; the
API (which the browser reaches behind oauth2-proxy) marks it approved — that's
how the out-of-band browser approval correlates to the waiting SSH handshake.

---

## Requirements

- **Go 1.25+** (to build).
- **PostgreSQL 14+** (16 recommended).
- **Node.js 18+** (to build the `web/` UI).
- **oauth2-proxy + a reverse proxy (NGINX)** in front of the management API and
  the SSH-login approval page, wired to your OIDC IdP (e.g. Entra ID). See
  [`docs/auth-setup.md`](./docs/auth-setup.md).
- For production CA custody: an **AWS KMS** asymmetric key and an EC2 instance
  role (IMDSv2).
- Optional: a self-hosted **asciinema server** for full session recording.

---

## Quick start (local development)

This brings up the broker against a local Postgres with a file-based CA and
file-based policy — no AWS, no oauth2-proxy — so you can exercise the proxy and
the management API quickly.

```bash
# 1. Dependencies
make tidy

# 2. Start local Postgres and apply migrations
make docker-up
make db-load                      # applies internal/store/migrations/*

# 3. Generate dev keys
make gen-host-key                 # broker SSH host key (front-door identity)
make gen-ca                       # dev CA key (ECDSA P-256)
make gen-secret-key               # prints a base64 AES-256 key for the secret store

# 4. Configure
cp .env.example .env              # then edit; see Configuration below

# 5. Build
make build                        # broker  -> ./bin/broker
make build-api                    # API     -> ./bin/sshbroker-api

# 6. Seed an admin + a user/target/grant via the CLI
./bin/broker admin add-user -username alice -email alice@example.com
./bin/broker admin add-key -username alice -key "$(cat ~/.ssh/id_ed25519.pub)"
./bin/broker admin add-server -name web01 -address 10.0.0.10:22 \
    -host-key-fingerprint "SHA256:..."
./bin/broker admin create-user-group -name devs
./bin/broker admin add-user-to-group -username alice -group devs
./bin/broker admin create-server-group -name web
./bin/broker admin add-server-to-group -server web01 -group web
./bin/broker admin add-grant -user-group devs -server-group web \
    -login deploy -capabilities shell,exec

# 7. Run
make run                          # or ./bin/broker

# 8. Connect
ssh deploy+web01@localhost -p 2222
```

To run the management UI in dev: `cd web && npm install && npm run dev` (it
proxies API calls to `cmd/api`). For production, `npm run build` and serve
`web/dist/` as static files behind your reverse proxy.

---

## Usage

### Connecting (interactive users)

```bash
ssh <account>+<host>@broker -p 2222     # explicit target account
ssh <host>@broker -p 2222               # broker derives the account from your grant
ssh you+<host>@broker -p 2222           # same, explicit "me"
```

If you have no registered key, the broker offers `keyboard-interactive` and
prints an approval URL. Open it, complete SSO/MFA, approve the connection (the
page shows the target and source IP so you can spot a forged request), and the
session continues. The approval is single-use and expires after
`SSHBROKER_SSH_LOGIN_TIMEOUT`.

### Service accounts (automation)

Register the public key on a service account; it authenticates by key and is
never prompted for the browser flow:

```bash
./bin/broker admin add-service-account -name ci-deploy \
    -key "$(cat ci_deploy.pub)"
```

### Admin CLI (`broker admin`)

Manage users, keys, groups, targets, and grants from the command line:

| Command | Purpose |
|---|---|
| `add-user`, `set-user-status` | Create users; enable/disable (disable kills live sessions) |
| `add-key`, `add-service-account` | Register public keys / create key-based service accounts |
| `create-user-group`, `add-user-to-group` | Manage user groups |
| `add-server`, `create-server-group`, `add-server-to-group` | Register targets and group them |
| `add-grant` | Grant a user group access to a server group (login, capabilities, TTL, review date) |
| `list-users`, `list-servers`, `list-grants` | Inspect current state |
| `recertify-grant` | Mark a grant reviewed (access reviews, ADR-017) |
| `terminate-session` | Kill a live session by id |
| `set-local-admin` | Create/update a break-glass admin (`-generate` for a random password) |

Run `./bin/broker admin <command> -h` for flags. The broker also has
`broker -verify-audit` to re-check the hash-chained audit log.

### Management UI / API

The React UI (`web/`) and the JSON API (`cmd/api`) expose the same operations
over HTTP, protected by SSO with role-aware controls. Sign in with SSO, or use
the break-glass local admin when the IdP is down. Auditors get read-only access;
admins get full control. See [`docs/auth-setup.md`](./docs/auth-setup.md) for the
oauth2-proxy/NGINX wiring.

---

## Configuration

All configuration is via `SSHBROKER_*` environment variables (see
[`.env.example`](./.env.example) for a starting point). The broker (`cmd/broker`)
and API (`cmd/api`) read overlapping subsets — set shared values (database, proxy
secret) on both.

### Core

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_ENV` | `dev` | Environment label |
| `SSHBROKER_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `SSHBROKER_DATABASE_URL` | — | PostgreSQL DSN (required) |
| `SSHBROKER_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown window |

### SSH front door (`cmd/broker`)

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_SSH_LISTEN_ADDR` | `:2222` | SSH listen address |
| `SSHBROKER_SSH_HOST_KEY_PATH` | — | Broker host key (front-door identity) |
| `SSHBROKER_BROKER_SOURCE_ADDR` | — | Source address used when dialing targets |
| `SSHBROKER_HEALTH_ADDR` | `:8080` | Health/readiness endpoint |

### Certificate authority

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_CA_BACKEND` | `file` | `file` or `kms` |
| `SSHBROKER_CA_KEY_PATH` | — | File CA key path (`file` backend) |
| `SSHBROKER_CA_KEY_PASSPHRASE` | — | Optional passphrase for the file CA key |
| `SSHBROKER_KMS_KEY_ID` | — | KMS key id/ARN (`kms` backend) |
| `SSHBROKER_AWS_REGION` | — | AWS region for KMS |
| `SSHBROKER_CERT_MAX_TTL` | `5m` | Max minted certificate lifetime |
| `SSHBROKER_CERT_CLOCK_SKEW` | `30s` | Allowed clock skew on cert validity |

### Auth / authorization backends

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_AUTH_BACKEND` | `file` | `db` or `file` (key → user/service-account resolution) |
| `SSHBROKER_AUTHZ_BACKEND` | `file` | `db` or `file` (grant evaluation) |
| `SSHBROKER_AUTHORIZED_USERS_PATH` | — | Dev `authorized_keys`-style file (`file` backend) |
| `SSHBROKER_TARGETS_PATH` | — | Dev targets/grants JSON (`file` backend) |
| `SSHBROKER_REVOCATION_INTERVAL` | — | How often revocation state is refreshed |

### Secret store

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_SECRET_STORE_DIR` | — | Directory for sealed secrets |
| `SSHBROKER_SECRET_STORE_KEY` | — | Base64 AES-256 key (dev; KMS in prod) |

### SSH browser SSO/MFA (ADR-021)

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_SSH_LOGIN_URL_BASE` | — | Public broker origin used to build the approval URL; **enables** browser SSO when set |
| `SSHBROKER_SSH_LOGIN_TIMEOUT` | `2m` | Approval wait + one-time code lifetime |
| `SSHBROKER_SSH_JIT_PROVISION` | `true` | Auto-create an unknown SSO user with **no grants** |

### Session recording (ADR-011)

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_RECORDING_DIR` | — | Where `.cast` files are written |
| `SSHBROKER_ASCIINEMA_SERVER_URL` | — | Self-hosted asciinema upload target |
| `SSHBROKER_ASCIINEMA_BIN` | `asciinema` | asciinema CLI to invoke |
| `SSHBROKER_ASCIINEMA_PUBLIC_URL` | — | Public viewer origin (API prepends to stored path) |
| `SSHBROKER_DELETE_LOCAL_RECORDING_AFTER_UPLOAD` | `true` | Remove local `.cast` after a successful upload (fail-closed) |

### Management API (`cmd/api`) and SSO

| Variable | Default | Description |
|---|---|---|
| `SSHBROKER_API_ADDR` | `:8081` | API listen address |
| `SSHBROKER_API_TOKEN` | — | Static token (legacy; bearer retired by default) |
| `SSHBROKER_ALLOW_BEARER_TOKEN` | `false` | Opt back into bearer-token auth |
| `SSHBROKER_AUTH_URL` | — | Public oauth2-proxy origin, returned to the SPA so it can build SSO links |
| `SSHBROKER_PROXY_SECRET` / `SSHBROKER_PROXY_SECRET_HEADER` | — / `X-Proxy-Auth` | Shared secret proving requests came via the trusted proxy |
| `SSHBROKER_OIDC_EMAIL_HEADER` | `X-Auth-Request-Email` | Header carrying the authenticated identity |
| `SSHBROKER_OIDC_GROUPS_HEADER` / `SSHBROKER_OIDC_GROUPS_DELIM` | `X-Auth-Request-Groups` / `,` | Group claim header + delimiter |
| `SSHBROKER_OIDC_GROUP_ROLES` | — | Map IdP groups → broker roles, e.g. `sg-admins:admin,sg-audit:auditor` |
| `SSHBROKER_ADMIN_SESSION_ABSOLUTE` / `SSHBROKER_ADMIN_SESSION_IDLE` | `12h` / `1h` | Management session lifetimes |
| `SSHBROKER_ADMIN_COOKIE_INSECURE` | `false` | Allow non-Secure cookies (dev only) |
| `SSHBROKER_REVIEW_INTERVAL_DAYS` | `90` | Default grant recertification interval |

---

## Repository layout

| Path | What's there |
|---|---|
| `cmd/broker/` | The SSH broker daemon (front door, dial, recording wiring), the `admin` CLI, the browser-login adapter, and asciinema upload |
| `cmd/api/` | The management JSON API server entrypoint |
| `internal/proxy/` | SSH server config, public-key and keyboard-interactive auth, target parsing, authorization, target dialing, session proxying, and recording |
| `internal/ca/` | Certificate issuer (builds tightly-constrained certs) |
| `internal/signer/` | Signing backends — `kmsca` (AWS KMS) and file |
| `internal/store/` | PostgreSQL persistence, repositories, the hash-chained audit log, and SQL migrations (`migrations/`) |
| `internal/auth/` | Management-plane RBAC (permissions/roles), argon2id passwords, session tokens |
| `internal/api/` | HTTP handlers, middleware (auth resolution, body limits, content-type/CSRF, audit), JSON helpers |
| `internal/config/` | Environment configuration loading |
| `internal/model/` | Core domain types |
| `internal/secrets/` | Secret store (file + KMS-envelope) |
| `web/` | React + Vite admin UI and the `/ssh-login` approval page |
| `docs/auth-setup.md` | Operator guide: oauth2-proxy/NGINX/Entra setup, SSH SSO, recording viewer, troubleshooting |
| `DECISIONS.md` | The 21 Architecture Decision Records |
| `security-review.md` | SOC 2-oriented security review and findings |
| `Makefile` | Build, test, migrate, key-gen, and Docker helpers |
| `.env.example` | Annotated environment template |

---

## Build and test

```bash
make build          # broker binary
make build-api      # management API binary
make test           # unit + integration tests (see below)
make vet            # go vet
make lint           # golangci-lint (if installed)
make vulncheck      # govulncheck dependency scan
cd web && npm run build   # UI
```

Integration tests that touch the database are gated on a test DSN:

```bash
export SSHBROKER_TEST_DATABASE_URL='postgres://broker:broker@127.0.0.1:5432/broker_test?sslmode=disable'
go test -race ./...
```

---

## Database migrations

Migrations live in `internal/store/migrations/` (`0001`–`0008`). Apply them with
the migrate CLI or by piping into your Postgres:

```bash
make migrate-up      # golang-migrate; needs SSHBROKER_DATABASE_URL
make migrate-down    # roll back the last migration
make db-load         # apply all by piping SQL into the local Postgres container
make db-reset        # roll everything back
```

---

## Security

The CA private key is held in KMS and never leaves it; certificates are
short-lived and constrained to a single target/principal; passwords use
argon2id; tokens and one-time codes are stored only as hashes; secret/secret
comparisons are constant-time; the audit log is hash-chained and verifiable;
SQL is fully parameterized; and the broker fails closed. Management mutations and
denied authorizations are audited with the real client IP, request bodies are
size-capped, and mutating requests require `application/json` as CSRF
defense-in-depth.

A detailed, code-grounded review mapped to SOC 2 Common Criteria — including
remediated findings and the remaining hardening backlog (break-glass TOTP,
grant-revocation-driven session kill, retention jobs) — is in
[`security-review.md`](./security-review.md). At-rest encryption of recordings
relies on KMS-encrypted volumes plus fail-closed delete-after-upload (see
ADR-011).

---

## Troubleshooting

Common deployment issues — OIDC scopes, oauth2-proxy `auth_request` behavior,
cross-subdomain session cookies (`cookie_domains`), the JSON-401/`auth_url`
fall-through pattern, the SSH browser-login flow, and the recording viewer — are
documented with fixes in [`docs/auth-setup.md`](./docs/auth-setup.md).

---

## Contributing

- Keep changes `gofmt`-clean and passing `make vet` / `make test` (with the test
  DSN exported for integration coverage).
- Architectural changes should be recorded as a new ADR in `DECISIONS.md`.
- The module path `github.com/yourorg/sshbroker` is a placeholder — set it to
  your organization's path before publishing.

---

## License

Add your chosen license here (e.g. `LICENSE` file) before release.
