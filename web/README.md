# sshbroker admin UI

A standalone Vite + React single-page app for the broker's management API
(`cmd/api`). It is built and served independently of the Go binaries.

## Auth (current)

For now the UI authenticates to the API with the static bearer token
(`SSHBROKER_API_TOKEN`). On first load it prompts for the token, validates it
against the API, and keeps it in `sessionStorage` for the tab session. A real
login flow (and MFA) replaces this later; nothing else in the UI changes when
it does, since all calls go through `src/api.js`.

## Develop

The API runs as a separate process. Start it (from the repo root):

```sh
export SSHBROKER_DATABASE_URL=postgres://...   # same DB as the broker
export SSHBROKER_API_TOKEN=$(openssl rand -hex 32)
export SSHBROKER_API_ADDR=:8081
go run ./cmd/api
```

Then run the UI dev server (it proxies `/api` and `/healthz` to the API, so the
browser sees one origin and there is no CORS):

```sh
cd web
npm install
npm run dev                         # http://localhost:5173
# point the proxy elsewhere with: SSHBROKER_API_URL=http://host:8081 npm run dev
```

Open the app, paste the API token, and you're in.

## Build for production

```sh
cd web
npm install
npm run build                       # outputs static files to web/dist/
```

Serve `web/dist/` behind your ingress and route `/api` (and `/healthz`) to the
management API on the same origin. Terminate TLS at the ingress.

## Views

Users (create, add keys, enable/disable) · Servers (register) · Groups (user &
server groups, membership) · Grants (group/user → server/group, with capability
and TTL composition) · Sessions (recent) · Audit (recent entries + chain
verification).
