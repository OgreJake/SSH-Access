# DECISIONS.md

Architecture Decision Record (ADR) and implementation plan for the **SSH Access Broker** — a self-hosted server that brokers user connections to internal hosts, manages SSH keys, and provisions access only when a user is authorized.

> **Status legend:** `ACCEPTED` (decided), `PROPOSED` (recommended, pending confirmation), `OPEN` (needs input before we commit).

---

## 1. Context & Requirements

**Functional**
- Broker user connections to internal servers over SSH.
- Manage SSH keys centrally; provisioning is done **solely on the broker side**.
- Provision access **only** when the user is authorized for a given server.
- Credentials presented to the user are **ephemeral** wherever the target supports it.
- Management interface for **user management** and **session statistics**.
- **Users** and **servers** can be **grouped** for management and authorization.
- Support **interactive shells, SCP/SFTP, and automation (Ansible)** through the broker.

**Environment & constraints (confirmed)**
- **Deployment:** **self-hosted broker application on EC2** (assumes an IAM instance role; no static credentials). **Key custody is delegated to AWS KMS** — we use AWS extensively and want portability across compute (no VMware/host lock-in). Trade: the trust boundary now includes our AWS account + IAM, and new-session brokering depends on KMS reachability.
- **Identity:** start with local accounts; add **Entra ID (OIDC) SSO** later for *authentication only*. **Group membership lives solely in this application**, never sourced from the IdP. Local accounts persist for **break-glass / IdP-outage** use.
- **Session recording:** **metadata by default**, with **opt-in full recording** for highly sensitive systems.
- **Scale:** minimal — DevOps team plus select IT support and developers.
- **Target fleet:** ~80–90% OpenSSH (cert-capable); a minority are **legacy systems that may not support certificate auth**.
- **Compliance:** **SOC 2** in progress — design for its controls from the start.

---

## 2. Core Architecture Decisions

### ADR-001 — SSH Certificate Authority as the primary access mechanism
**Status:** ACCEPTED

The broker is an SSH CA. Cert-capable targets trust the CA public key (`TrustedUserCAKeys`). On an authorized connection, the broker mints a **short-lived signed certificate** (TTL in minutes) scoped to the user and target, and uses it for the onward hop. Satisfies *ephemeral*, *server-side provisioning*, and *agentless targets* simultaneously. (See ADR-012 for the legacy fallback.)

### ADR-002 — Broker as an SSH proxy (jump host)
**Status:** ACCEPTED

All sessions traverse the broker: it terminates the user's connection, authenticates/authorizes, then opens an onward connection to the target. Required for session statistics and recording, lets us pin certs to the broker's source IP, and centralizes network reachability (targets accept connections only from the broker). Users connect via `ssh -J broker …` or a generated client config.

### ADR-003 — Implementation language: Go
**Status:** ACCEPTED

Go with `golang.org/x/crypto/ssh`. Domain standard (Teleport, Boundary, smallstep), full control over SSH server/client/cert primitives, single static binary for easy self-hosted deployment and fast patching.

### ADR-004 — Data store: PostgreSQL
**Status:** ACCEPTED

Relational data (group memberships, grants), transactional authorization decisions, append-only audit. SQLite acceptable for local dev only.

### ADR-005 — Management interface: API + React web UI
**Status:** ACCEPTED

API is the source of truth; web UI covers user management and session statistics first. A CLI may follow.

---

## 3. Access Modes (cert + legacy)

### ADR-012 — Dual access mode: certificates primary, brokered credentials for legacy
**Status:** ACCEPTED

Each target is tagged with an **access mode**:

- **Mode A — Certificate (default, ~80–90% of fleet).** Broker mints a short-lived cert per session. Fully ephemeral, nothing left on the target.
- **Mode B — Brokered credential (legacy, non-cert).** The broker holds the target credential in its **encrypted secret store** and injects it at connect time; the **user never sees it**. Two sub-modes by target capability:
  - **B1 — JIT key injection** (target supports `authorized_keys` but not certs): broker generates an ephemeral keypair, writes the public key to the target's `authorized_keys` just before the session, then **removes it on session end**. Preserves ephemerality.
  - **B2 — Stored credential** (target supports only passwords or a fixed key): broker uses a long-lived stored credential. Access is still brokered, gated per session, fully audited, and instantly revocable — **but the underlying target credential is not ephemeral**.

**Honest tradeoff for SOC 2 / the original "ephemeral" goal:** Modes A and B1 keep credentials ephemeral. Mode B2 does not — the target-side secret is long-lived. We mitigate with: per-session authorization, the credential never leaving the broker, mandatory recording for B2 targets, and a documented rotation schedule for stored credentials. We should aim to minimize B2 over time and, where feasible, migrate legacy hosts to B1 or A.

> **Bootstrapping note:** Mode B requires the broker to already possess a privileged credential per legacy target (to inject keys or authenticate). Onboarding a legacy host therefore includes securely loading that bootstrap credential into the secret store.

### ADR-014 — Proxy supports shell, exec, and SFTP subsystem
**Status:** ACCEPTED (revised — port forwarding descoped)

The proxy is **not** shell-only. Per the Ansible/SCP/SFTP requirement it brokers:
- **shell** (interactive PTY) — default for human sessions.
- **exec** (single commands) — needed by Ansible and scripts.
- **sftp subsystem** — SCP (modern OpenSSH uses SFTP underneath) and SFTP transfers.

Each channel type is a capability flag on the grant. Recording adapts per channel: shell → terminal stream; exec → command + exit status; sftp → file-transfer log (path, direction, size).

**Revision (port forwarding dropped).** `direct-tcpip` port forwarding was originally listed as an opt-in per-grant capability. It has been **descoped**: the per-grant flag is removed from the schema, API, CLI, and UI, and the proxy continues to reject all non-`session` channels. The low-level certificate capability (`ca.Permissions.PortForwarding`) and the `channel_type` enum value are retained but are never enabled by policy, so the feature can be reintroduced later without a model change if a concrete need arises.

---

## 4. Automation & Service Accounts

### ADR-013 — First-class service accounts for automation (Ansible)
**Status:** ACCEPTED

Non-human identities are modeled explicitly:
- A **ServiceAccount** is a distinct principal with its own grants, separate from human users.
- It authenticates to the broker non-interactively via a **registered SSH key** (preferred) or a scoped API/token credential — **not** via SSO.
- Ansible reaches targets through the broker as a jump host, e.g. `ansible_ssh_common_args='-o ProxyJump=svc-ansible@broker'`; the broker authorizes each target per the service account's grants and performs the onward hop (cert or brokered credential as the target requires).
- Service-account sessions are audited like any other and are subject to recording policy. Their credentials are rotated on a schedule and are individually attributable (no shared automation identity).

---

## 5. Identity, Authentication & Authorization

### ADR-008 — Local accounts first; Entra ID OIDC later for authn only; groups in-app
**Status:** ACCEPTED

- **Phase one:** local accounts with **mandatory MFA (TOTP)**.
- **Later:** **Entra ID via OIDC for authentication only.** On SSO login the Entra identity is mapped to a local user record. **Group membership and all authorization live in this application's database** and are never imported from Entra.
- **Break-glass:** local accounts remain permanently for IdP outages. They are **individually named** (no shared root account), MFA-protected, heavily recorded, alert on use, and reviewed regularly.

### ADR-010 — RBAC via group-to-group grants
**Status:** ACCEPTED

Entities: **User**, **ServiceAccount**, **UserGroup**, **Server** (address, port, host-key fingerprint, access mode, allowed login principals, secret reference for legacy), **ServerGroup**, **Grant**.

A **Grant** links a UserGroup/User/ServiceAccount to a ServerGroup/Server and specifies: allowed login principal(s), max TTL, channel capabilities (shell/exec/sftp/forwarding), recording policy, and a **review-by date** (ADR-017). Access is authorized iff a Grant connects the requester (directly or via group) to the target and permits the requested principal and channel.

```
User ─member of─> UserGroup ──┐
ServiceAccount ───────────────┼── Grant(principals, ttl, caps, recording, review_by)
Server ─member of─> ServerGroup┘
```

---

## 6. Security & Cryptography

### ADR-006 — CA signing key in AWS KMS (asymmetric); pluggable signer
**Status:** ACCEPTED

The CA signing key is the crown jewel. Abstract signing behind a `Signer` interface:
- **Dev:** encrypted key file, decrypted at startup.
- **Production:** an **AWS KMS asymmetric key** (`ECC_NIST_P256`, key usage `SIGN_VERIFY`). The private key never leaves KMS; the broker calls the `Sign` API with the certificate's to-be-signed bytes. Implementation: a `crypto.Signer` that delegates to KMS (KMS returns the DER-encoded ECDSA signature `crypto.Signer` expects), wrapped via `ssh.NewSignerFromSigner`. Validated end-to-end in Phase 1.

**Why KMS over self-hosted hardware/Vault.** No HSM to buy and no Vault to run/patch (fits the ~$0-ops goal; KMS cost is ~$1/mo per key + negligible per-request at our volume). Key custody is **portable across compute** — directly addresses the VMware-lock-in concern, since the CA key is decoupled from any host. Every signing operation is independently logged to **CloudTrail**, so a compromised broker cannot conceal key usage (strong SOC 2 evidence).

**Tradeoffs (recorded deliberately).** (a) Trust boundary now includes the **AWS account + IAM**, not just our host. (b) **Availability dependency:** brokering a *new* session requires reaching KMS; if KMS/region is unreachable, no new sessions start (acceptable at our scale, but real). (c) **Manual CA rotation:** asymmetric KMS keys have no auto-rotation, so rotation stays a documented runbook (new key → distribute new CA pubkey to targets' `TrustedUserCAKeys` → overlap → retire old).

**Broker→KMS auth (decided):** the broker runs on **EC2 and assumes an IAM instance role** — no static credentials. The KMS key policy and the role's IAM policy are scoped to exactly the operations needed (`kms:Sign` with the CA key; `kms:Decrypt`/`kms:GenerateDataKey` for the secret store) and nothing else. **IMDSv2** is enforced on the instance to prevent SSRF-based credential theft. Region is single-region by default (see §9).

### ADR-007 — Tightly constrained short-lived certificates
**Status:** ACCEPTED

Each cert: **TTL in minutes** (just long enough to establish the session); **principals** limited to the granted login(s); **`source-address`** pinned to the broker's egress IP; **extensions** minimal (`permit-pty` only by default; forwarding opt-in); **key ID** encoding request ID + user for audit correlation; logged **serial** for optional revocation lists.

### ADR-009 — Encryption in transit and at rest
**Status:** ACCEPTED

TLS on the web/API; mTLS between components if/when split. **At rest:** the secret store (legacy/bootstrap credentials, recordings of sensitive systems) and database are encrypted via **KMS envelope encryption** — a KMS data key (or KMS as KEK) protects the legacy credentials in Postgres, reusing the same KMS dependency as the signer and keeping all `Decrypt` calls in CloudTrail. Host runs full-disk encryption.

---

## 7. Sessions, Auditing & SOC 2 Controls

### ADR-011 — Session metadata always; full recording opt-in for sensitive systems
**Status:** ACCEPTED

- **Always:** metadata — who, source IP, target, login principal, grant used, access mode, cert serial (Mode A), channel type, start/stop, duration, exit status, bytes, file-transfer manifest for SFTP.
- **Opt-in per ServerGroup/grant:** full recording — terminal stream for shells, full command capture for exec, file-transfer detail for SFTP — stored encrypted on the self-hosted volume. Mandatory for Mode B2 legacy targets.

**Implemented.** Full recording captures the target→user terminal stream as an asciinema v2 (`.cast`) file under `SSHBROKER_RECORDING_DIR`, one per session (`<session-id>.cast`), referenced by `sessions.recording_ref`. Policy composes across matching grants (any `full` wins). User keystrokes are deliberately **not** recorded (they can contain typed secrets). Recordings are downloadable via the API/UI and play with `asciinema play`. At-rest encryption of the recording volume remains an ops/deployment concern (ADR-009).

### ADR-015 — Tamper-evident, time-synced, retained, exportable audit log
**Status:** ACCEPTED (SOC 2)

- **Append-only / tamper-evident** audit log (e.g., hash-chained records) covering auth events, authorization decisions, session lifecycle, admin/config changes, and break-glass use.
- **Time sync:** broker host runs NTP; all records UTC-timestamped.
- **Retention:** default **1 year** (confirm against your SOC 2 scope — see §9).
- **Export:** stream to a SIEM / external log store so logs survive broker compromise.

### ADR-016 — Immediate de-provisioning and active-session termination
**Status:** ACCEPTED (SOC 2)

Admins can **instantly disable a user/service account or revoke a grant**, which **terminates that principal's active sessions** and blocks new ones. Supports the joiner/mover/leaver lifecycle SOC 2 expects.

### ADR-017 — Access reviews / grant recertification
**Status:** ACCEPTED (SOC 2)

Every grant carries a **review-by date**. The UI provides a **"who can access what"** report and surfaces grants due for recertification, supporting periodic (e.g., quarterly) access reviews. Optional auto-expiry of un-recertified grants.

### ADR-018 — Account & session hardening + alerting
**Status:** ACCEPTED (SOC 2)

- **MFA** mandatory for all interactive accounts.
- **Idle and absolute session timeouts.**
- **Secret rotation** policy for stored legacy/bootstrap credentials and service-account keys.
- **Alerting** on break-glass use, repeated auth failures, and privileged config changes.
- **Backups** of DB, secret store, and recordings, with periodic restore testing (relevant if Availability is in your SOC 2 scope).
- **Change management:** documented SDLC, code review, CI, dependency/vuln scanning — aligned with your "patch fast" goal.

### ADR-019 — Subject-addressed connections / principal derivation
**Status:** ACCEPTED

Reinterprets the `login+host` addressing of ADR-002. The token left of `+` is no longer required to be the target OS account; the broker can **derive the target account from the matching grant's permitted principals**. This lets a person be onboarded to many hosts via a single grant against shared/standard OS accounts, instead of provisioning a per-person account on every target.

**Motivation.** Giving a new hire access to hundreds of servers should not require creating (and later cleaning up) an OS account on each one. Broker-managed provisioning/deprovisioning across many hosts introduces mutable per-host state, partial-failure/drift, a larger blast radius, and exactly the per-host account sprawl a broker exists to remove. Keeping identity at the broker and mapping to shared target accounts avoids all of that and is the convergent industry pattern (Boundary, Teleport, commercial PAM).

**Accepted forms.** `account+host` (explicit, unchanged), `host` (bare; derive), `+host` / `me+host` / `<self-username>+host` (derive).

**Resolution rule** (after identity and the grants matching subject→target are resolved; `permitted` = union of those grants' principals, intersected with the server's `allowed_principals` gate where set):
- left token is one of `permitted` → use it (explicit; backward compatible);
- left token is empty / the user's own username / `me` → **derive**: if exactly one usable principal, use it; if none, deny; if more than one, **reject as ambiguous and list the options** (the broker never guesses);
- any other token → deny.

**Attribution is unchanged.** Authentication identity is independent of the landed account: the certificate key ID remains `u=<user>;host=<host>;login=<account>`, and the session `subject_label` and audit actor remain the authenticated user. Only the certificate principal and the target login are the resolved account.

**Security.** Derivation can only select a principal that a grant already permits and that the server's `allowed_principals` already allows (the defense-in-depth gate of ADR-014 applies to the resolved account), so there is no privilege escalation — it is convenience over information the broker already holds. **Trade-off:** people sharing one target OS account share the same *on-host* (kernel) identity; the broker authorizes and attributes them separately but cannot isolate them at the host filesystem/`sudo` level. Per-person on-host isolation requires distinct target accounts, which should be owned by configuration management, not broker-provisioned.

**Scope.** Implemented in the DB-backed authorizer; the dev file/`targets.json` authorizer remains explicit-only. Fully backward compatible with existing `account+host` usage.

---

## 8. Connection Flows

**Interactive (cert target):**
```
1. ssh -J broker alice@prod-db-01
2. Broker authenticates alice (local+MFA now; Entra OIDC later).
3. Resolve target -> check Grants -> authorize principal + channel.
4. Mint cert: principals=[alice], ttl=2m, source-address=<broker>, key-id=<reqid:alice>.
5. Onward SSH to prod-db-01 using the cert; target trusts the CA.
6. Proxy session; record metadata (+ stream if policy requires).
7. Cert expires in minutes; nothing durable left on the target.
```

**Legacy target (Mode B1 JIT key):**
```
3. Authorize -> 4. Generate ephemeral keypair; inject pubkey into target authorized_keys.
5. Onward SSH with the ephemeral key. 6. Proxy + record.
7. On session end, remove the injected key from authorized_keys.
```

**Ansible (automation, SFTP/exec):**
```
ansible -> ProxyJump=svc-ansible@broker -> broker authn (service-account key)
        -> per-target authorize -> onward hop (cert or brokered cred)
        -> exec/sftp channels proxied + audited (file-transfer manifest).
```

---

## 9. Open Questions (remaining)

1. **AWS region for the CA key:** confirm the region (single-region default; note the availability dependency — if that region's KMS is unreachable, no new sessions start). Multi-region replica only if you later want regional resilience.
2. **SOC 2 scope:** which Trust Services Criteria are in scope — Security only, or also **Availability / Confidentiality**? This sets how hard we push backups/HA (ADR-018) and retention (ADR-015).
3. **Log retention period:** confirm the exact retention requirement (default assumed 1 year). Existing **SIEM** to export to?
4. **Legacy targets detail:** of the non-cert hosts, how many are key-capable (eligible for **B1**, ephemeral) vs. password-only (**B2**, stored credential)? This sizes how much non-ephemeral surface remains.

---

## 10. Phased Implementation Plan

**Phase 0 — Foundations**
- Repo, CI with dependency/vuln scanning, lint/test.
- Data model + migrations: users, service accounts, user groups, servers (with access mode + secret ref), server groups, grants (caps, recording, review_by), sessions, append-only audit.
- Config loading; `Signer` interface with dev (encrypted file) impl; secret-store interface.

**Phase 1 — SSH CA core (Mode A)**
- CA key load; publish CA public key for target trust.
- Constrained cert minting (ADR-007); **validate the KMS-backed `crypto.Signer` → `ssh.NewSignerFromSigner` path end-to-end** (dev file signer first, then KMS).
- Test target trusting the CA; prove cert auth manually.

**Phase 2 — Broker proxy + sessions**
- SSH proxy authenticating a (stub) local user, minting a cert, proxying to target.
- Channel support: shell + exec + sftp subsystem (ADR-014).
- Session metadata recording (ADR-011).

**Phase 3 — Authorization, accounts & API**
- RBAC decision engine (ADR-010); local accounts + MFA (ADR-008).
- Service accounts + key auth (ADR-013).
- Immediate disable + session kill (ADR-016).
- REST/gRPC API for all management entities.

**Phase 4 — Legacy access (Mode B)**
- Secret store integration; B1 JIT key injection + cleanup; B2 stored-credential injection.
- Mandatory recording for B2 (ADR-011).

**Phase 5 — Web UI**
- User/group/server/grant management; session statistics dashboard.
- Access-review report + recertification surfacing (ADR-017).

**Phase 6 — Production hardening & SOC 2**
- Entra ID OIDC (authn only) + break-glass policy (ADR-008).
- KMS-backed signer + KMS envelope encryption for the secret store (ADR-006, ADR-009); broker→KMS auth via instance role / Roles Anywhere.
- Tamper-evident audit + SIEM export + retention (ADR-015); alerting, timeouts, rotation, backups (ADR-018).
- Optional full session recording rollout for sensitive groups.

**Phase 7 — Operability**
- Backups + restore testing, key/credential rotation runbooks, metrics, health checks. HA only if Availability is in SOC 2 scope.

---

## 11. Decision Log

| ID | Decision | Status |
|----|----------|--------|
| ADR-001 | SSH Certificate Authority (primary) | ACCEPTED |
| ADR-002 | Broker as SSH proxy / jump host | ACCEPTED |
| ADR-003 | Go + x/crypto/ssh | ACCEPTED |
| ADR-004 | PostgreSQL | ACCEPTED |
| ADR-005 | API + React web UI | ACCEPTED |
| ADR-006 | CA key in AWS KMS (asymmetric); EC2 instance role; KMS envelope encryption for secret store | ACCEPTED |
| ADR-007 | Tightly constrained short-lived certs | ACCEPTED |
| ADR-008 | Local+MFA first; Entra OIDC (authn only) later; groups in-app | ACCEPTED |
| ADR-009 | Encryption in transit and at rest | ACCEPTED |
| ADR-010 | RBAC via group-to-group grants | ACCEPTED |
| ADR-011 | Metadata always; full recording opt-in | ACCEPTED |
| ADR-012 | Dual access mode (cert + legacy brokered credential) | ACCEPTED |
| ADR-013 | First-class service accounts for automation | ACCEPTED |
| ADR-014 | Proxy supports shell/exec/sftp (port forwarding descoped) | ACCEPTED |
| ADR-015 | Tamper-evident, time-synced, retained, exportable audit | ACCEPTED |
| ADR-016 | Immediate de-provisioning + session termination | ACCEPTED |
| ADR-017 | Access reviews / grant recertification | ACCEPTED |
| ADR-018 | Account/session hardening + alerting + backups | ACCEPTED |
| ADR-019 | Subject-addressed connections; broker derives target account from grant | ACCEPTED |
