# Management-plane authentication setup (ADR-008 Phase A)

This describes how to deploy the broker's management plane (the JSON API and the
React admin UI) behind NGINX with Entra ID (OIDC) single sign-on, plus the
break-glass local admin used when Entra is unreachable.

> Phase A covers the **management plane only**. SSH-side browser SSO/MFA
> (cert-via-helper) is Phase B and is not part of this document.

## Trust model (read this first)

The broker API does **not** perform OIDC itself. An OIDC reverse proxy
(`oauth2-proxy`) authenticates the admin against Entra and injects their
identity as request headers. The API trusts those headers **only** because of
three invariants — if any one is missing, identity can be forged:

1. **The API binds to loopback only** (`SSHBROKER_API_ADDR=127.0.0.1:8081`). It
   must be unreachable except through NGINX/oauth2-proxy on the same host.
2. **The proxy strips client-supplied identity headers** before setting its own,
   so a client cannot send `X-Auth-Request-Email` directly.
3. **The proxy sends a shared secret** (`X-Proxy-Auth`) that the API verifies
   (`SSHBROKER_PROXY_SECRET`). With no secret configured, the API trusts no OIDC
   headers at all (break-glass and — if explicitly enabled — bearer only).

## Roles

Identity → role is driven by Entra group membership via
`SSHBROKER_OIDC_GROUP_ROLES` (e.g. `sg-broker-admins:admin,sg-broker-audit:auditor`).
Built-in roles:

- `admin` — all permissions.
- `auditor` — all read permissions plus exports; no mutations.

Effective permissions are the union over the admin's mapped groups. An
authenticated user whose groups map to no role can sign in but can do nothing
(every action returns 403) — map at least one group to a role.

## Broker API environment

```sh
SSHBROKER_API_ADDR=127.0.0.1:8081          # loopback ONLY
SSHBROKER_DATABASE_URL=postgres://…
SSHBROKER_API_TOKEN=…                       # still required at startup; unused unless bearer is enabled
SSHBROKER_RECORDING_DIR=/var/lib/sshbroker/recordings

# OIDC header trust
SSHBROKER_PROXY_SECRET=<long-random-shared-with-oauth2-proxy>
SSHBROKER_OIDC_GROUP_ROLES=sg-broker-admins:admin,sg-broker-audit:auditor
# Header names default to the oauth2-proxy conventions below; override if needed:
# SSHBROKER_OIDC_EMAIL_HEADER=X-Auth-Request-Email
# SSHBROKER_OIDC_GROUPS_HEADER=X-Auth-Request-Groups
# SSHBROKER_PROXY_SECRET_HEADER=X-Proxy-Auth

# Break-glass session lifetimes
SSHBROKER_ADMIN_SESSION_ABSOLUTE=12h
SSHBROKER_ADMIN_SESSION_IDLE=1h

# The static bearer token is RETIRED by default. Only set this during cutover or
# a documented emergency, and unset it afterward:
# SSHBROKER_ALLOW_BEARER_TOKEN=1
```

## Provisioning the break-glass admin

```sh
broker admin set-local-admin -username breakglass -generate
# prints a strong password once — store it in your secret manager
```

The break-glass login is a broker-native form that **bypasses** oauth2-proxy
(NGINX `/api/v1/auth/local/*` and the UI are reachable without OIDC), so it
still works when Entra is down. It is password-only today; argon2id-hashed,
rate-limited, and every attempt is audited (`auth.login` / `auth.login.failed`).
Add a second factor as a hardening follow-up.

## oauth2-proxy (Entra / OIDC)

```ini
# /etc/oauth2-proxy/oauth2-proxy.cfg
provider                 = "oidc"
oidc_issuer_url          = "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
client_id                = "<APP_CLIENT_ID>"
client_secret            = "<APP_CLIENT_SECRET>"
redirect_url             = "https://broker.example.com/oauth2/callback"
email_domains            = ["*"]
cookie_secret            = "<32-byte-base64>"
cookie_secure            = true

# Expose identity to the upstream as headers.
set_xauthrequest         = true     # sets X-Auth-Request-Email, -User, -Groups
pass_access_token        = false
pass_authorization_header = false

# Request the groups claim from Entra (configure a groups claim on the app
# registration; for many groups use Graph/OBO — out of scope here).
scope                    = "openid email profile groups"

upstreams                = ["http://127.0.0.1:8081"]

# CRITICAL: inject the shared secret the broker verifies, and ensure the broker
# only ever sees proxy-set identity headers (NGINX strips client ones below).
```

To inject the shared secret, run oauth2-proxy behind NGINX (below) and have
NGINX add `X-Proxy-Auth`, or set it via oauth2-proxy's `--set-xauthrequest`
upstream with an injected header. The example below injects it at NGINX so the
secret lives in one place.

## NGINX

```nginx
server {
    listen 443 ssl;
    server_name broker.example.com;
    # ssl_certificate ... ;

    # Defense in depth: never let a client send identity/secret headers upstream.
    proxy_set_header X-Auth-Request-Email "";
    proxy_set_header X-Auth-Request-Groups "";
    proxy_set_header X-Proxy-Auth "";

    # --- Break-glass: bypasses OIDC so it works when Entra is down ---
    # The local login endpoints and the SPA are reachable without oauth2-proxy.
    location /api/v1/auth/local/ {
        proxy_set_header X-Proxy-Auth "<SAME_SECRET_AS_SSHBROKER_PROXY_SECRET>";
        proxy_pass http://127.0.0.1:8081;
    }

    # --- SSO-protected management API ---
    location /api/ {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        # Map oauth2-proxy's auth_request response headers onto the upstream.
        auth_request_set $email  $upstream_http_x_auth_request_email;
        auth_request_set $groups $upstream_http_x_auth_request_groups;
        proxy_set_header X-Auth-Request-Email  $email;
        proxy_set_header X-Auth-Request-Groups $groups;
        proxy_set_header X-Proxy-Auth "<SAME_SECRET_AS_SSHBROKER_PROXY_SECRET>";

        proxy_pass http://127.0.0.1:8081;
    }

    # oauth2-proxy endpoints (/oauth2/start, /callback, /auth, /sign_in).
    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host             $host;
        proxy_set_header X-Real-IP        $remote_addr;
        proxy_set_header X-Scheme         $scheme;
        proxy_set_header X-Auth-Request-Redirect $request_uri;
    }

    # The SPA (static files). The UI calls /api/v1/auth/whoami on load to decide
    # whether to show the app or the sign-in screen.
    location / {
        root /var/www/sshbroker-ui;
        try_files $uri /index.html;
    }
}
```

Notes:
- The asciinema server (ADR-011) lives on this same host; give it its own
  `location` and (recommended) the same `auth_request` protection so recordings
  aren't world-readable. The UI opens recording paths against this origin.
- The SPA's "Sign in with SSO" button points at `/oauth2/start?rd=/`; the
  break-glass form posts to `/api/v1/auth/local/login`.
- Cookies are `Secure` by default. For a local HTTP dev box only, set
  `SSHBROKER_ADMIN_COOKIE_INSECURE=1` so the session cookie works over HTTP.

## Verifying

1. **SSO:** browse to the UI → redirected to Entra → back to the app; the header
   shows your email and source `oidc`. An `auditor` sees read-only views (no
   create/edit/delete/terminate controls); an `admin` sees everything.
2. **Break-glass:** on the sign-in screen, use the local admin; the header shows
   `break-glass:<user>` / source `break-glass`.
3. **Header-forgery is rejected:** `curl` the API directly on loopback with a
   spoofed `X-Auth-Request-Email` but no `X-Proxy-Auth` → 401.
4. **Audit:** mutations appear in the audit log with your real identity as actor;
   `auth.login` is recorded on sign-in.
