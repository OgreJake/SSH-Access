# security-review.md

**Project:** `sshbroker` — SSH access broker / jump host
**Repository:** `github.com/OgreJake/SSH-Access` (placeholder module path `github.com/yourorg/sshbroker`)
**Reviewed at commit:** `740a8a5` (branch `main`, README update)
**Reviewer:** Code-grounded security review
**Date:** 2026-06-19
**Scope (SOC 2):** Security (CC1–CC9), Confidentiality, Availability
**Out of scope:** SOC 2 organizational controls (HR, vendor management, policy administration). This document covers technical controls demonstrable in code, configuration, and the SDLC.

---

## 1. Executive summary

`sshbroker` is well-architected for a SOC 2-aligned access broker. The CA path is sound (KMS-resident asymmetric key, tightly-constrained short-lived certificates, dev/prod parity behind a `signer.Authority` interface). Authentication uses argon2id, opaque hashed session tokens, and constant-time comparisons. The audit log is hash-chained, serialized under a Postgres advisory lock, and DB-trigger-protected against UPDATE/DELETE. SQL is fully parameterized and the React frontend avoids the typical XSS sinks. The 21 ADRs (`DECISIONS.md`) reflect mature SOC 2 reasoning.

The review identified **5 High**, **16 Medium**, and **13 Low** findings, plus a list of strengths and a residual backlog. The dominant themes:

- **Supply-chain and change-management gaps** — `go.sum` is not committed; CI tools use `@latest` and floating tags. This breaks CC8.1 / CC9.1 evidence for build integrity.
- **Production guard-rails are advisory, not enforced** — `cfg.IsProd()` exists but is never used to refuse unsafe combinations (file CA backend, empty target host-key fingerprint, in-memory cert serial allocator, `ADMIN_COOKIE_INSECURE`, transitional bearer token, missing `PROXY_SECRET`).
- **Operational hygiene gaps that block Availability evidence** — no retention/cleanup jobs for `audit_log`, `ssh_login_requests`, or recording files; no SIEM export shipped; no recording-file size cap; no write/idle timeouts on the API; unbounded SSH accept loop and login-limiter map.
- **Audit reliability** — most `AppendAudit` call sites discard the error; a transient DB failure silently drops the event.

None of the findings are remote unauthenticated code execution. The system fails closed on the main authorization path. Remediating the High and Medium items above will produce a defensible SOC 2 Type II posture for Security + Confidentiality, with Availability still requiring backup/restore and HA work outside the application code.

---

## 2. Scope and methodology

### What was reviewed

- **Go code:** 65 files / ~11k LOC across `cmd/`, `internal/`. All authentication, authorization, signing, secrets, sessions, audit, store, and HTTP/SSH handlers were read in full.
- **SQL migrations:** `internal/store/migrations/0001`–`0008`.
- **React frontend:** all of `web/src/**`, plus `index.html`, `vite.config.js`, `package.json`.
- **CI and tooling:** `.github/workflows/ci.yml`, `Makefile`, `.golangci.yml`, `go.mod`, `.gitignore`, `docker-compose.yml`.
- **Operator surface:** `.env.example`, `targets.example.json`, `README.md`, `docs/auth-setup.md`, `DECISIONS.md`.

### What was *not* reviewed

- Live infrastructure (AWS account, KMS key policy, NGINX/oauth2-proxy config files, EBS volume encryption status, RDS configuration, IAM roles). This review treats deployment-side artifacts as descriptions in `DECISIONS.md` and `docs/auth-setup.md`.
- Penetration testing / dynamic analysis. All findings are from static review.
- The asciinema server itself (third-party).

### Methodology

Files were read end-to-end (not sampled). Findings were derived from manual reading rather than automated scanners. The scope corresponds to **SOC 2 Common Criteria CC1–CC9 (Security)**, with Availability and Confidentiality criteria called out where applicable.

---

## 3. Findings summary

| ID | Title | Severity | SOC 2 |
|----|-------|----------|-------|
| H-1 | `go.sum` not committed — dependency hashes not pinned | High | CC8.1, CC9.1 |
| H-2 | No production KMS-backed secret store implemented | High | CC6.1, Conf. |
| H-3 | Target host-key fingerprint may be empty in production (accept-any MITM) | High | CC6.1 |
| H-4 | Audit retention, SIEM export, and table cleanup not implemented | High | CC7.2, CC7.3, Avail. |
| H-5 | In-process counter used for certificate serials (resets on restart) | High | CC7.2 |
| M-1 | `AppendAudit` errors silently discarded by most callers | Medium | CC7.2 |
| M-2 | `api.New()` default `AllowBearerToken=true` (embedder-unsafe default) | Medium | CC6.1 |
| M-3 | `config.Load()` permits unsafe combinations when `SSHBROKER_ENV=prod` | Medium | CC8.1 |
| M-4 | API HTTP server has no `WriteTimeout` / `IdleTimeout` | Medium | Avail. |
| M-5 | SSH front-door has no connection rate-limit; unbounded goroutines on accept | Medium | Avail. |
| M-6 | `X-Forwarded-For` source-IP trust is unconditional | Medium | CC7.2 |
| M-7 | Recording files have no size cap and are not fsync'd | Medium | Avail., Conf. |
| M-8 | Login limiter is in-process, fixed-window, with unbounded memory growth | Medium | CC6.1, Avail. |
| M-9 | Break-glass admin uses single-factor (password only); ADR-018 TOTP deferred | Medium | CC6.1 |
| M-10 | Session/login cookie `SameSite=Lax`, no `__Host-` prefix | Medium | CC6.1 |
| M-11 | Grant revocation/deletion does not terminate the affected live sessions | Medium | CC6.3 |
| M-12 | No security response headers / CSP (defence-in-depth) | Medium | CC6.1 |
| M-13 | `splitAndTrim` accepts unbounded groups header (DoS / parser) | Medium | CC6.1, Avail. |
| M-14 | JIT user provisioning unconditionally writes on any new SSO subject | Medium | CC6.1 |
| M-15 | SSH approval code carried in query string (leaks to logs, history) | Medium | CC6.1 |
| M-16 | Authorization denials are silenced from the SSH user-facing path | Medium | CC2.3 |
| L-1 | Audit middleware skips GET — reads of audit data not recorded | Low | CC7.2 |
| L-2 | `Content-Disposition` of recording download not quoted | Low | CC6.1 |
| L-3 | Certificate `KeyID` may contain user-controlled host string (log injection) | Low | CC7.2 |
| L-4 | `recertifyGrant` audit uses subject from context but generic actor in CLI | Low | CC7.2 |
| L-5 | `last_seen_at` written on every API request (DB amplification) | Low | Avail. |
| L-6 | Audit export capped at 100k rows with no pagination | Low | Avail. |
| L-7 | CI actions are not pinned to commit SHAs; `govulncheck@latest` | Low | CC8.1 |
| L-8 | Placeholder module path `github.com/yourorg/sshbroker` still in `go.mod` | Low | CC8.1 |
| L-9 | SSH server config does not set `MaxAuthTries` or a banner | Low | CC6.1 |
| L-10 | Bearer-token actor recorded as `bearer-token` (loses per-person attribution) | Low | CC7.2 |
| L-11 | `getRecording` opens any `.cast` matching the stored ref (no path canonicalisation beyond `filepath.Base`) | Low | CC6.1 |
| L-12 | `BrowserLogin.keyboardInteractive` ignores parent context — broker shutdown does not unblock pending logins | Low | Avail. |
| L-13 | No app-side TLS / mTLS check between API and Postgres (env-only) | Low | Conf. |

---

## 4. Findings — detail

### High

#### H-1. `go.sum` not committed
- **Where:** repo root (`go.sum` absent); CI step "Verify modules are tidy" in `.github/workflows/ci.yml:22-25`.
- **Detail:** `go.mod` lists pinned versions, but `go.sum` (the cryptographic hash file) is not in the repository. The CI step `go mod tidy && git diff --exit-code go.mod go.sum` generates a fresh `go.sum` on every build; without a committed copy there is no trust anchor against module-proxy or registry tampering for direct or indirect dependencies (notably `pgx/v5`, `aws-sdk-go-v2/service/kms`, `golang.org/x/crypto`).
- **Impact:** A compromised module proxy or upstream tag-replay can introduce malicious code without detection. Reproducible builds are not possible.
- **SOC 2:** CC8.1 (change management — build integrity), CC9.1 (supply-chain risk).
- **Fix:** `go mod tidy && git add go.sum && git commit`. Remove `.gitignore` rules that would exclude it (none present today — `go.sum` is simply absent). Verify CI by re-running.

#### H-2. No production KMS-backed secret store
- **Where:** `internal/secrets/filestore.go` (only implementation); `cmd/broker/main.go:93-97` (instantiates `FileStore` unconditionally regardless of `cfg.IsProd()`).
- **Detail:** ADR-006 / ADR-009 specify KMS envelope encryption for the secret store in production. Only `FileStore` exists. Even when `SSHBROKER_ENV=prod`, the broker uses an AES-256-GCM key supplied via `SSHBROKER_SECRET_STORE_KEY` env var, sealed only by file permissions on the broker host. Anyone with read access to broker memory, container env, or backup snapshots holds the data-encryption key.
- **Impact:** Future legacy-target credentials (Mode B2 stored creds) and any other secret-bearing data have no KMS envelope. Confidentiality control is the broker host's filesystem ACL plus EBS encryption only.
- **SOC 2:** CC6.1 (logical access to encryption keys), Confidentiality (data classification & encryption).
- **Fix:** Implement `KMSStore` (or `KMSEnvelopeStore`) behind `secrets.Store`. Re-encrypt the per-secret DEK with a `GenerateDataKey` call from the existing broker KMS key. Refuse to start in prod if `SSHBROKER_SECRET_STORE_KEY` is the only key configured. Until then, document the gap in `DECISIONS.md` §9.

#### H-3. Empty target host-key fingerprint is accepted with only a warning
- **Where:** `internal/proxy/dial.go:69-76`.
- **Detail:** When a server is registered without `host_key_fingerprint`, the broker logs a warning and accepts whatever key the target presents. This is documented as "dev only," but neither `config.Load()` nor `CreateServer` enforce that prod targets have a fingerprint.
- **Impact:** Any attacker who can intercept the broker→target TCP stream (same VPC, redirected route, DNS hijack, ARP poisoning) can MITM the session, harvest the certificate, and impersonate the target. The certificate is short-lived but the attacker can replay it for its TTL.
- **SOC 2:** CC6.1 (logical access — endpoint authentication).
- **Fix:** In `cfg.IsProd()` mode, refuse to dial a target whose `host_key_fingerprint` is empty. As a deeper control, accept a TOFU step the first time, then pin and require admin re-approval for changes. Add a startup audit log of any server rows lacking a fingerprint.

#### H-4. Audit-log retention, SIEM export, and table cleanup not implemented
- **Where:** `internal/store/audit.go` (no retention queries); `internal/store/ssh_login.go:135-144` (`DeleteExpiredSSHLogins` defined but never called); `cmd/broker/main.go` (no scheduled jobs registered); no SIEM exporter.
- **Detail:** ADR-015 commits to "default 1-year retention" and "export to SIEM so logs survive broker compromise." Today the `audit_log` table grows monotonically, `ssh_login_requests` is never swept, and there is no out-of-broker shipping of audit events. A successful broker compromise can both stop new audit appends and (after acquiring DB credentials) drop the entire database — leaving no external trail.
- **Impact:** SOC 2 evidence requirement for log retention is unmet; tamper-evidence is only as strong as the DB itself.
- **SOC 2:** CC7.2 (monitoring), CC7.3 (incident response evidence), Availability.
- **Fix:** Ship audit events to an external store (Kinesis Firehose, S3 with object lock, Splunk, etc.) in near-real time, ideally with append-only retention at the destination. Add a periodic retention job (e.g., daily) that:
  - Deletes `ssh_login_requests` older than 24h with status in `('consumed','denied','expired')`.
  - Snapshots and archives `audit_log` rows older than retention to cold storage, then deletes from the live table (after the retention period — typically 1 year).
  - Sweeps orphaned recording files.

#### H-5. In-process counter for certificate serial numbers
- **Where:** `internal/ca/serial.go:19-35`; used at `cmd/broker/main.go:103` (`ca.NewCounterAllocator(0)`).
- **Detail:** Cert serials are generated by `atomic.Uint64` starting at 1 each restart. The package comment says "must not be used in production" but `cmd/broker/main.go` instantiates it unconditionally. Serials collide across restarts.
- **Impact:** Per ADR-007 serials feed audit correlation and would feed revocation lists. Two different brokered sessions can carry the same serial across a restart, breaking unique-correlation evidence.
- **SOC 2:** CC7.2 (logging integrity for issued credentials), ADR-007.
- **Fix:** Implement a `SequenceAllocator` backed by a Postgres sequence (`CREATE SEQUENCE cert_serial`); have `cmd/broker/main.go` select it when `cfg.IsProd()`. Document collision-recovery (the audit `key_id` already carries `u=… host=… login=…` so historical lookup is still possible, but the cert serial should be globally unique).

### Medium

#### M-1. `AppendAudit` errors silently discarded
- **Where:** `internal/api/auth_middleware.go:189` (`auditDenied`), `:231-241` (`auditMW`); `internal/api/auth_handlers.go:69-71, 107-110`; `internal/api/ssh_login_handlers.go:77-82`; `cmd/broker/main.go:319-324` (reaper). The pattern `_ = s.store.AppendAudit(...)` appears 8+ times.
- **Impact:** A transient Postgres outage (or row-lock contention on `audit_log`) silently drops the event. The chain stays internally consistent (because the dropped event is never inserted), but operators have no signal that an event went missing — defeating the SOC 2 commitment to record auth/authz events.
- **SOC 2:** CC7.2 (logging completeness).
- **Fix:** At minimum log `AppendAudit` errors at `error` level (the reaper already does; extend to all sites). Better: for high-severity mutations (grant changes, user disable, terminate-session, role changes, break-glass login), fail the request when audit write fails — the operation should not appear "successful" if its audit record is lost.

#### M-2. `api.New()` default `AllowBearerToken=true`
- **Where:** `internal/api/server.go:75-87`.
- **Detail:** Constructor default is `AllowBearerToken: true` with comment "transitional; A3 retires the bearer token." `cmd/api/main.go:78` overrides this to `false` unless `SSHBROKER_ALLOW_BEARER_TOKEN` is set, so the production binary is safe. But any future embedder of `api.New` (tests, in-process integrations) inherits the open default.
- **Impact:** Defence-in-depth weakness; not currently exploited by the prod binary.
- **SOC 2:** CC6.1.
- **Fix:** Default `AllowBearerToken: false` in `api.New` and let `cmd/api/main.go` opt in explicitly.

#### M-3. `config.Load()` permits unsafe combinations under `SSHBROKER_ENV=prod`
- **Where:** `internal/config/config.go` (no `cfg.IsProd()` gating during validation).
- **Detail:** With `SSHBROKER_ENV=prod`, the broker still accepts:
  - `SSHBROKER_CA_BACKEND=file` (private CA key in-process).
  - Empty `SSHBROKER_BROKER_SOURCE_ADDR` (no source-address pin on issued certs).
  - Empty `SSHBROKER_API_TOKEN` together with `SSHBROKER_ALLOW_BEARER_TOKEN=1` (refuses to start, good — but bearer + insecure cookie is permitted).
  - `SSHBROKER_ADMIN_COOKIE_INSECURE=1` (HTTP cookie).
  - Empty `SSHBROKER_PROXY_SECRET` (oauth2-proxy headers fully untrusted, falling back to break-glass + bearer only).
- **Impact:** Misconfiguration in production cannot be detected until it manifests.
- **SOC 2:** CC8.1 (change management hygiene).
- **Fix:** Add a `validateProd()` pass that, when `cfg.IsProd()`, refuses to start on these combinations. Log refusal reasons and exit non-zero so deployment systems catch the regression.

#### M-4. API HTTP server has no `WriteTimeout` / `IdleTimeout`
- **Where:** `cmd/api/main.go:92-96` (`&http.Server{ReadHeaderTimeout: 10s, …}`).
- **Detail:** Only `ReadHeaderTimeout` is configured. Slow clients keeping a TCP connection alive after sending headers can hold goroutines indefinitely. No `IdleTimeout` means connections in `keep-alive` can sit.
- **SOC 2:** Availability.
- **Fix:** Set `WriteTimeout: 30 * time.Second`, `IdleTimeout: 90 * time.Second`. Add `ReadTimeout` for total request read.

#### M-5. SSH front-door spawns unbounded goroutines per TCP accept
- **Where:** `internal/proxy/server.go:117-128`.
- **Detail:** `for { conn, _ := ln.Accept(); go s.handleConn(...) }`. No bound on concurrent connections, no per-source-IP rate limit, no SYN-cookie equivalent. The handshake itself has the (default) x/crypto/ssh timeout, but an attacker can flood the listener to exhaust scheduler/memory.
- **SOC 2:** Availability.
- **Fix:** Wrap accept in a semaphore (e.g., `golang.org/x/sync/semaphore`) sized to a configurable maximum (e.g., 1024 concurrent handshakes). Add a `net.Listener` middleware that buckets by source IP and drops on excess.

#### M-6. `X-Forwarded-For` source-IP trust is unconditional
- **Where:** `internal/api/auth_handlers.go:147-162` (`clientIP`).
- **Detail:** The leftmost `X-Forwarded-For` value is trusted whenever present. The comment says the API is "reachable only via the loopback proxy" — but that's a deployment assumption, not an enforced check. If the API listens on `:8081` reachable from outside the trusted proxy (default config), a direct caller can inject any source IP they like.
- **Impact:** Audit-log `source_ip` cannot be relied upon if the API is ever exposed beyond the proxy. Login limiter keyed on `(username, clientIP)` becomes trivial to bypass.
- **SOC 2:** CC7.2 (audit integrity).
- **Fix:** Bind the API to `127.0.0.1:8081` by default; if a non-loopback bind is needed, require `SSHBROKER_TRUSTED_PROXY_CIDRS` and enforce that `r.RemoteAddr` matches one of them before reading XFF.

#### M-7. Recording files have no size cap and are not fsync'd
- **Where:** `internal/proxy/recording.go:80-101`.
- **Detail:** `castRecording.Output` appends every target output chunk to disk via `json.Encoder.Encode`. No `Sync` is called, and there is no upper bound on file size. A long-running session, or an attacker who can cause continuous output, can fill the recording volume.
- **Impact:** Disk-exhaustion DoS to the broker; on crash, the most recent recording events are lost (the user-stream-only design helps but doesn't eliminate the risk for SOC 2 evidence).
- **SOC 2:** Availability; ADR-011 evidence (full recording reliability).
- **Fix:** Enforce a per-session cap (e.g., 200 MiB or configurable); when exceeded, close the recording with an event noting truncation, append a `recording.truncated` audit event, and either (a) start a new file or (b) stop full recording for the rest of the session (and let metadata-only continue). Call `f.Sync()` on close. Monitor `RECORDING_DIR` free space at startup and ready-check.

#### M-8. Login limiter is in-process, fixed-window, unbounded map
- **Where:** `internal/api/auth_handlers.go:14-47`.
- **Detail:** `loginLimiter.hits` is a `map[string][]time.Time` keyed by `(username, clientIP)`. Old entries are pruned only when that key is queried — entries for keys never seen again stay forever. Multiple API instances (HA) do not share state. An attacker can iterate usernames or spoofed IPs to bypass the 5-per-minute cap.
- **Impact:** Memory growth under attack; cap bypass with diverse keys.
- **SOC 2:** CC6.1, Availability.
- **Fix:** Move the limiter into the database (e.g., a `local_admin_login_attempts` table with TTL'd rows), or to a shared cache (Redis) when HA is in scope. Add a global per-IP cap and an exponential lockout schedule per-username. Surface lockout in a `local_admin.locked_until` field that `localLogin` consults before even hashing.

#### M-9. Break-glass admin is single-factor (password only)
- **Where:** `internal/store/migrations/0007_management_auth.up.sql`; `internal/auth/password.go`; `internal/api/auth_handlers.go:49-113`.
- **Detail:** ADR-018 lists "MFA mandatory for all interactive accounts" and ADR-008/020 contemplates TOTP for break-glass; not implemented. The break-glass operator authenticates with username + password only.
- **Impact:** A leaked break-glass credential bypasses MFA entirely — and break-glass holds `admin`. Exposure is mitigated by the limiter (M-8) and audit, but the underlying control is weaker than SOC 2 expects for emergency admin paths.
- **SOC 2:** CC6.1, ADR-018.
- **Fix:** Add TOTP enrollment for `local_admins` (the `mfa_secret`/`mfa_enrolled` columns already exist on `users` — add equivalents to `local_admins`). Require a TOTP code on every login. Allow a one-time recovery code generated at enrolment.

#### M-10. Session/login cookie attributes
- **Where:** `internal/api/auth_handlers.go:98-106`.
- **Detail:** Cookie is `HttpOnly`, `Secure` (config-gated), `SameSite=Lax`. The cookie name (`sshbroker_admin_session`) has no `__Host-` prefix, so it inherits the parent domain's scope. `Lax` allows the cookie on top-level navigation — fine for most purposes, but `Strict` would prevent any cross-site request from carrying it, which is appropriate for a privileged management plane.
- **Impact:** Marginal — CSRF defence still rests on the `requireJSONMW` Content-Type check, which is solid. The lack of `__Host-` means a subdomain takeover or relaxed scope can leak the cookie.
- **SOC 2:** CC6.1.
- **Fix:** Rename to `__Host-sshbroker_admin_session`, require `Path=/`, drop `Domain` (already absent), and set `SameSite=Strict`. If the SPA is on a different subdomain than the API, keep `Lax` but address the cross-subdomain question in `auth-setup.md`.

#### M-11. Grant revocation/deletion does not terminate live sessions
- **Where:** `internal/store/sessions_terminate.go:74-106` (`SessionsToTerminate`); `internal/store/updates.go:146-155` (`DeleteGrant`).
- **Detail:** The revocation reaper kills sessions when the **subject** is disabled or the **session row** is explicitly flagged. It does **not** kill sessions whose grant was modified or deleted while the session was live. A grant change that removes a principal does not terminate the in-flight session that was authorized under it.
- **Impact:** SOC 2 expects immediate de-provisioning. A grant revoke can take up to the session's natural lifetime to take effect.
- **SOC 2:** CC6.3, ADR-016.
- **Fix:** When a grant is updated/deleted, identify active sessions whose `grant_id` matches and flag them for termination in the same transaction. Add a periodic re-evaluation: for each live session, re-run `Authorize`; if denied, kill. This catches grant deletions that did not propagate through subject-disable.

#### M-12. No security response headers / CSP
- **Where:** All HTTP handlers (`internal/api/*.go`, `cmd/broker/main.go:223-244`); `web/index.html`.
- **Detail:** No `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, or `Strict-Transport-Security` on API responses. The React app's `index.html` carries no CSP meta tag.
- **Impact:** Defence-in-depth: with no `dangerouslySetInnerHTML` and no third-party JS, current XSS surface is small, but any future regression is unmitigated.
- **SOC 2:** CC6.1.
- **Fix:** Add a `securityHeadersMW` to the API server that sets the headers above. Add a strict CSP either via the HTML meta tag or via an API/`/`-route handler (`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'`). Make sure NGINX is not stripping or duplicating.

#### M-13. `splitAndTrim` accepts unbounded groups header
- **Where:** `internal/api/auth_middleware.go:99, 133-148`.
- **Detail:** The OIDC groups header is split on the configured delimiter with no upper bound on count or length. A maliciously large header (oauth2-proxy is generally trusted, but the broker has no defence) results in a large slice and a large permission-resolution loop.
- **Impact:** Minor DoS surface if the proxy ever forwards an attacker-controlled groups value.
- **SOC 2:** Availability, CC6.1.
- **Fix:** Cap the groups header at, e.g., 64 entries / 8 KiB total. Discard above the cap and log a warning.

#### M-14. JIT user provisioning writes on any new SSO subject
- **Where:** `cmd/broker/browserlogin.go:48-67`; `internal/store/repositories.go:380-387`.
- **Detail:** When `SSHBROKER_SSH_JIT_PROVISION=true`, any subject who completes oauth2-proxy SSO causes a user row to be inserted (with no grants). This is intentional per ADR-021 but means an Entra tenant misconfiguration (e.g., conditional access wildcards) could populate the broker's user table with arbitrary email addresses.
- **Impact:** Low (no grants are issued), but creates noise in the user list and an indirect DoS-by-table-growth path.
- **SOC 2:** CC6.1.
- **Fix:** Rate-limit JIT creations per source IP / per minute. Add an allowlist regex on email domain (`SSHBROKER_SSH_JIT_EMAIL_DOMAIN=disdev.net`). Audit each JIT create with the source IP.

#### M-15. SSH approval code carried in URL query string
- **Where:** `cmd/broker/browserlogin.go:36`; `internal/api/ssh_login_handlers.go:13-32`.
- **Detail:** The single-use approval URL is `https://broker.example.com/ssh-login?code=<opaque>`. Query-string codes leak into web-server logs, oauth2-proxy logs, browser history, and the `Referer` header on any subsequent navigation. The code is 32 bytes of random + base64url + single-use + 2-minute TTL, so the risk window is narrow.
- **Impact:** Low absolute risk given the constraints, but query-string credentials are an antipattern.
- **SOC 2:** CC6.1.
- **Fix:** Move the code to a `#fragment` (never sent to the server) and have the SPA POST it back in the body. Or use a path segment with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. At minimum, set `Referrer-Policy: no-referrer` on `/ssh-login` responses.

#### M-16. Authorization denials show same generic message to the SSH user
- **Where:** `internal/proxy/dbauthz.go` (descriptive errors); `internal/proxy/server.go:248-256` (collapses to `"sshbroker: not authorized to reach %q"`).
- **Detail:** The server-side error contains the precise reason (no grant, principal mismatch, ambiguous derivation) and is logged with the actor — good. The user, however, only sees "not authorized" — this is mostly correct but the *ambiguous derivation* case (`multiple accounts available on %q for %q…`) should be surfaced to the user so they know how to retry. As written, the user gets the same opaque denial as a brute-force probe.
- **Impact:** Operational, not a security risk per se; it's listed here because it directly affects SOC 2 CC2 (communications about access).
- **SOC 2:** CC2.3.
- **Fix:** Whitelist the "ambiguous principal" error for client-visible relay; keep all other reasons opaque.

### Low

#### L-1. Audit middleware skips GET
- **Where:** `internal/api/auth_middleware.go:217-221`.
- **Detail:** Read endpoints (sessions, audit log, recordings) are not audited. SOC 2 does not strictly require auditing reads of audit logs, but doing so adds attribution for reviewers downloading evidence (especially `audit/export` and `recordings/{id}`).
- **Fix:** Special-case `GET /api/v1/audit/export`, `GET /api/v1/audit/verify`, and `GET /api/v1/sessions/{id}/recording` for audit logging.

#### L-2. `Content-Disposition` of recording download not quoted
- **Where:** `internal/api/handlers.go:583-584`.
- **Detail:** `w.Header().Set("Content-Disposition", \`attachment; filename="`+name+`"`)`. `name = filepath.Base(ref)` — and `ref` is internally generated (session-UUID + `.cast`), so user influence is nil today. If `recording_ref` ever becomes user-influenced, header injection is possible.
- **Fix:** Use `mime.FormatMediaType("attachment", map[string]string{"filename": name})` or strict allow-listed characters.

#### L-3. Certificate `KeyID` may contain user-controlled host string
- **Where:** `internal/proxy/dial.go:35`.
- **Detail:** `keyID := fmt.Sprintf("u=%s;host=%s;login=%s", id.Label, spec.Host, d.Login)`. `spec.Host` is parsed from the SSH user field (`alice+web01`). If a user submits `web01\nsomething`, the KeyID — recorded in the certificate and logged by the target's sshd — contains a newline.
- **Impact:** Log-injection on target sshd logs; not a SQL vector (audit log target field comes from elsewhere).
- **Fix:** Validate `spec.Host` against `^[A-Za-z0-9.\-_]+$` in `ParseTarget`, reject anything else.

#### L-4. CLI recertify uses generic actor
- **Where:** `cmd/broker/admin.go:443-462`. The API recertify (`internal/api/handlers.go:378-400`) uses the resolved principal. The CLI hard-codes `"admin-cli"`. ADR-017 already notes this gap.
- **Fix:** When run interactively, capture `os.Getenv("USER")` or a `--operator` flag and combine: `admin-cli:<operator>`. Document the policy.

#### L-5. `last_seen_at` written on every API request
- **Where:** `internal/store/admins.go:129`.
- **Detail:** Sliding-idle requires a write per access. For an admin browsing the UI, this is many writes per minute.
- **Fix:** Update only when the elapsed time since `last_seen_at` exceeds a granularity (e.g., 60s).

#### L-6. Audit export caps at 100k with no pagination
- **Where:** `internal/store/updates.go:198-220`.
- **Detail:** `AllAudit` returns at most 100k rows. For a 1-year retention SOC 2 log this can exceed 100k. The CSV/JSON export silently truncates.
- **Fix:** Add `since`/`until` and `cursor` query params; iterate from the SPA for large exports.

#### L-7. CI actions not SHA-pinned; `govulncheck@latest`
- **Where:** `.github/workflows/ci.yml`.
- **Detail:** `actions/checkout@v4`, `actions/setup-go@v5`, `golangci/golangci-lint-action@v6`, `go install golang.org/x/vuln/cmd/govulncheck@latest`. Major-version tags can be moved; `@latest` pulls fresh on every run.
- **SOC 2:** CC8.1 (build integrity).
- **Fix:** Pin every action to a 40-character commit SHA; pin `govulncheck` to a version (`@v1.1.4` at the time of writing).

#### L-8. Placeholder module path
- **Where:** `go.mod:1` (`module github.com/yourorg/sshbroker`).
- **Detail:** README acknowledges this. If the org publishes this package somewhere and someone registers `yourorg/sshbroker` first, supply-chain confusion is possible (unlikely for a private repo).
- **Fix:** Replace with the actual org path before any external publication; update all import paths.

#### L-9. SSH server defaults
- **Where:** `internal/proxy/server.go:131-160`.
- **Detail:** No `MaxAuthTries` set (defaults to 6); no banner. Not a security gap, just a hardening miss.
- **Fix:** Set `MaxAuthTries: 3` (publickey + keyboard-interactive only); add a short banner advising connections are recorded and authorized per ADR.

#### L-10. Bearer-token actor recorded as `bearer-token`
- **Where:** `internal/api/auth_middleware.go:107` (`p := auth.NewPrincipal("bearer-token", ...)`).
- **Detail:** When the transitional bearer token is used, the audit actor is the literal string `bearer-token` — no per-person attribution.
- **Fix:** When the bearer token is enabled, add a startup log loud warning and audit the `bearer.in_use` event on each use. This is consistent with the transition intent; the goal is to ensure bearer use is visible to the auditor.

#### L-11. `getRecording` path joining
- **Where:** `internal/api/handlers.go:562-586`.
- **Detail:** `name := filepath.Base(ref); f := os.Open(filepath.Join(s.recordingDir, name))` — `filepath.Base` strips traversal, but on Windows this could behave differently. The deployment is Linux per `docs/auth-setup.md`, so this is informational.
- **Fix:** Also verify the resolved path stays under `s.recordingDir` via `filepath.Clean` + a `strings.HasPrefix` check, or use `os.Root` (Go 1.24+).

#### L-12. `keyboardInteractive` uses `context.Background()` (broker shutdown doesn't unblock)
- **Where:** `internal/proxy/server.go:167-217`.
- **Detail:** The browser-login poll uses a fresh `context.Background()` rather than the broker's serve context. On shutdown, in-flight `keyboardInteractive` calls only end on the 2-minute timeout.
- **Fix:** Plumb the serve context through `Serve → handleConn → keyboardInteractive`, deriving the timeout from it.

#### L-13. App-side DB SSL not enforced
- **Where:** `internal/store/store.go:19-29`; `.env.example:13`.
- **Detail:** The example DSN uses `sslmode=disable`. Production operators are expected to set `sslmode=verify-full` in `SSHBROKER_DATABASE_URL`; nothing in the binary refuses to connect over plaintext.
- **Fix:** Refuse to start in `cfg.IsProd()` if the DSN's `sslmode` resolves to `disable` or `allow`. Parse with `pgconn.ParseConfig` and inspect.

---

## 5. Strengths

These controls work and should be preserved.

- **Cryptography:**
  - **Argon2id** with `t=3, m=64 MiB, p=4, keyLen=32, saltLen=16` (`internal/auth/password.go:13-22`).
  - **Constant-time comparisons** on tokens, password hashes, and the proxy shared secret (`crypto/subtle.ConstantTimeCompare` throughout `auth_middleware.go`, `password.go`).
  - **AES-256-GCM** with random nonce and AAD bound to the secret ref in the FileStore (`secrets/filestore.go`), preventing silent secret-substitution.
  - **Session tokens / SSH login codes** are 32 random bytes encoded base64url and stored only as SHA-256 hashes (`auth/session.go`).
- **Certificate authority:**
  - **KMS-resident asymmetric key** with key-spec validation at startup (`kmsca/kmsca.go:104-133`); thin `crypto.Signer` wrapper preserves SSH wire-format correctness (`kmsca.go:160-197`).
  - **Tightly constrained issuance:** non-empty principals required, KeyID required (for audit correlation), TTL clamped to `CertMaxTTL`, source-address pin available, capabilities derived from grant flags (`ca/issuer.go`).
  - **Per-session ephemeral target key** (Ed25519) — the user's key never reaches the target (`proxy/dial.go:22-33`).
- **Audit log:**
  - **Hash-chained** with length-prefixed field encoding (`store/audit.go:112-128`).
  - **Serialized via Postgres advisory lock** so concurrent appends cannot fork the chain (`store/audit.go:39-41`).
  - **DB triggers reject UPDATE/DELETE** on `audit_log` (`migrations/0001_init.up.sql:204-213`).
  - **Verification CLI/endpoint** rebuilds the chain and identifies the first tampered record (`VerifyAuditChain`).
- **HTTP API:**
  - Body size capped at 1 MiB (`auth_middleware.go:28-38`).
  - CSRF defended via `Content-Type=application/json` requirement on state-changing methods (`auth_middleware.go:44-59`).
  - Recovery middleware converts handler panics to 500s (`auth_middleware.go:62-72`).
  - Per-route permission checks; auditor role exists for SOC 2 separation-of-duties (`auth/rbac.go`).
  - Generic `writeStoreError` masks internal errors from clients while logging server-side (`api/json.go:42-54`).
- **SQL hygiene:** All queries reviewed are parameterised. Polymorphic FK gaps (`grants.subject_id`/`target_id`) are noted in the migration comments and handled by application-layer deletes.
- **SSH proxy:**
  - **User keystrokes are never recorded** (only target output) — protects typed secrets (`proxy/session.go:22`).
  - **Capabilities gated per channel type** (`shell` / `exec` / `subsystem(sftp)`) (`proxy/session.go:69-105`).
  - **Subsystem allowlist** — only `sftp` accepted (`session.go:99-105`).
  - **Subject-addressed connections** never invent principals not in the grant (`dbauthz.go:152-178`).
- **Frontend:**
  - React with no `dangerouslySetInnerHTML`, no `innerHTML`, no `eval`.
  - `window.open` with `noopener,noreferrer` on recording links (`Sessions.jsx:82`).
  - Cookie-based auth (no token-in-storage XSS exfil surface).
- **CI:**
  - `govulncheck` is wired in (`.github/workflows/ci.yml:36-47`).
  - `gosec` is enabled via `golangci-lint` (`.golangci.yml:12`).
  - `go test -race` on every CI run.
- **ADR record:** the `DECISIONS.md` document is itself SOC 2 evidence — every architectural choice is mapped to a Common Criterion or a documented motivation.

---

## 6. SOC 2 mapping

### CC1 — Control environment
ADRs are recorded in version control (`DECISIONS.md`, 21 entries). Architectural changes require a new ADR per repo policy. **Gap:** SDLC policy text (code review, branch-protection rules, signed commits) is not in the repo. Add a `CONTRIBUTING.md` and configure branch protection on `main` (require PR + 1 review + passing CI). [Action]

### CC2 — Communication and information
Operator-facing docs (`README.md`, `docs/auth-setup.md`, `DECISIONS.md`) describe how the system works and the security boundaries (oauth2-proxy header-trust, header-trust-secret, MFA via Entra Conditional Access). **Gap:** User-visible authorization denials are too opaque to recover from (M-16).

### CC3 — Risk assessment
ADR-018 enumerates the risks (long-lived keys, shared accounts, no central record) the broker addresses. **Gap:** No formal threat model document. Recommend a STRIDE-style addendum to `DECISIONS.md`.

### CC4 — Monitoring activities
The `runReaper` loop polls live sessions; `verifyAudit` validates chain integrity on demand. **Gap:** No continuous chain verification (H-4); no SIEM shipping (H-4); no alerting (no Prometheus metrics, no log shipping). Add at minimum a daily `/audit/verify` cron and alert on `ok=false`.

### CC5 — Control activities
Code review (PR-based), CI (build/test/vet/govulncheck/golangci-lint) — present. **Gap:** Some controls are advisory (e.g., file CA backend permitted in prod, M-3). Promote to enforced.

### CC6 — Logical access
- **CC6.1 (logical access):** Solid foundation — argon2id, hashed tokens, MFA on Entra, RBAC. Gaps: H-3 (host-key pinning), M-9 (break-glass MFA), M-2/M-3 (transitional / config-permitted weakness), M-10 (cookie attrs), M-12 (CSP), L-9 (`MaxAuthTries`).
- **CC6.2 (registration & authorisation):** Admin CLI + API + JIT (gated). Gap: M-14 JIT allow-domain.
- **CC6.3 (revocation):** Reaper kills sessions on subject-disable. Gap: M-11 grant-revoke does not propagate to live sessions.
- **CC6.6 (transmission):** TLS terminated at NGINX (operator responsibility). Gap: L-13 enforce `sslmode=verify-full` for Postgres in prod.
- **CC6.7 (transmission of sensitive data):** Recordings (which may contain sensitive output) traverse the broker→asciinema-server upload over HTTP per `.env.example:85`. **Action:** require HTTPS for `SSHBROKER_ASCIINEMA_SERVER_URL` in prod.
- **CC6.8 (malicious code):** No upload-from-user surface; React app is statically built; no eval; govulncheck. Adequate.

### CC7 — System operations
- **CC7.1 (boundaries):** Body limit + Content-Type CSRF + structured logging. OK.
- **CC7.2 (monitoring):** Hash-chained audit log is good. Gaps: H-4 retention/SIEM; M-1 silent audit failures; M-6 source-IP trust; L-1 read auditing.
- **CC7.3 (evaluation & response):** Audit verify endpoint and CLI exist. Gap: no continuous verification scheduled; no incident-response runbook.
- **CC7.4 (incident management):** `terminate-session`, `set-user-status`, audit-chain verify are the primitives. Gap: no automated alerting; no break-glass usage alert (ADR-018 backlog).
- **CC7.5 (recovery):** `make migrate-down`, `make db-reset` for DB. Gap: no backup/restore tested per ADR-018.

### CC8 — Change management
PR-based, CI, ADR-recorded. Gaps: H-1 (`go.sum` missing); L-7 (action SHA pinning); L-8 (placeholder module path); M-3 (prod guards).

### CC9 — Risk mitigation / vendor management
KMS dependency is documented. Gaps: H-2 (no KMS-backed secret store implemented); L-7 (`govulncheck@latest`).

### Availability
- Present: graceful shutdown, health/ready endpoints (`cmd/broker/main.go:223-244`), connection pooling, KMS sign timeout (5s).
- Gaps: M-4 (no `WriteTimeout`/`IdleTimeout`); M-5 (unbounded SSH accept); M-7 (no recording size cap); M-8 (in-process limiter); L-6 (export cap); H-4 (retention/cleanup jobs); HA/multi-AZ not addressed in code. Confirm with operations whether HA is in scope for the Type II audit (DECISIONS.md §9 lists this as open).

### Confidentiality
- Present: encryption-at-transit via TLS/NGINX (operator), KMS-encrypted EBS (operator), AES-256-GCM for FileStore, recordings stream only target→user output.
- Gaps: H-2 (no app-level KMS envelope for secrets); M-7 (recording disk cap / handling); L-13 (Postgres TLS not enforced). Recommend a data-classification annex listing every persisted field and its sensitivity (e.g., `users.email` → PII; `audit_log.detail.source_ip` → operational PII; `sessions.recording_ref` → sensitive operational data).

---

## 7. Recommended remediation order

1. **Same-day** (1–3 hours): H-1 (commit `go.sum`); L-7 (pin actions); L-8 (module path); M-3 (`cfg.IsProd()` guards).
2. **This sprint** (1 week): H-3 (require host-key fp in prod); H-5 (Postgres-sequence serial allocator); M-1 (log all audit failures, fail mutations on audit-write failure); M-2 (default-off bearer); M-4 (HTTP timeouts); M-6 (trusted-proxy CIDR check); M-12 (security headers / CSP); L-13 (DB sslmode enforcement); L-9 (MaxAuthTries).
3. **Next sprint** (2–4 weeks): H-2 (KMS-backed secret store); H-4 (retention + SIEM); M-7 (recording size cap + fsync); M-8 (DB-backed limiter); M-11 (grant-revoke → session-kill); M-13/M-14 (groups header cap, JIT allow-domain).
4. **Backlog** (per ADR-018): M-9 (break-glass TOTP); M-15 (move SSH code out of query string); L-1 (read auditing); L-2, L-3, L-4, L-5, L-6, L-10, L-11, L-12.

---

## 8. Backlog and forward-looking items

These remain after the above remediations:

- **HA / multi-region** if Availability is in audit scope (read-replica Postgres, multi-region KMS replica, broker behind ALB, recording volume replicated).
- **Backups + tested restore** (RDS automated backups + quarterly restore exercise documented in `docs/`).
- **Break-glass TOTP** (ADR-018 commit).
- **Continuous audit-chain verification** (sidecar or scheduled job + alert).
- **Pen test** before SOC 2 Type II window opens — this static review does not substitute.
- **Threat model** as a short appendix to `DECISIONS.md`.
- **Data-classification annex** for confidentiality.
- **Vendor inventory** — KMS, RDS, oauth2-proxy, asciinema, Entra ID. Document the SOC 2 / ISO posture of each.
- **Runbook**: incident response, break-glass procedure, audit-chain-break response, asciinema server outage.

---

## 9. Notes on verification

The findings above are derived from reading the codebase at the commit listed in the header. Any future code changes invalidate specific line references; re-run a delta review on each significant PR (the `gosec` lint and `govulncheck` are not a substitute).

**Suggested cadence:** repeat this review at every quarter and every change to:
- Anything in `internal/auth/`, `internal/proxy/{server,authz,dbauth,dbauthz,dial}.go`, `internal/ca/`, `internal/signer/`, `internal/secrets/`, `internal/store/audit.go`, `internal/api/auth_*.go`.
- Any new migration in `internal/store/migrations/`.
- Any change to `cmd/broker/main.go`, `cmd/api/main.go`, or `internal/config/config.go`.
- Any change to `.github/workflows/`, `go.mod`, `Makefile`, `.golangci.yml`.

---

*End of security-review.md*
