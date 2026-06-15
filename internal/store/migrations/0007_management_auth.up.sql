-- ADR-008/020: management-plane authentication.
-- local_admins: break-glass operators (used when Entra is unreachable). OIDC
-- admins are NOT stored here — their identity comes from the reverse proxy.
-- admin_sessions: server-side opaque sessions for the break-glass login only.

CREATE TABLE local_admins (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,                       -- argon2id PHC string
    role          text NOT NULL DEFAULT 'admin',
    status        account_status NOT NULL DEFAULT 'active',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TRIGGER local_admins_updated BEFORE UPDATE ON local_admins
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE admin_sessions (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash     bytea NOT NULL UNIQUE,              -- sha-256 of the cookie token
    local_admin_id uuid NOT NULL REFERENCES local_admins(id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,               -- absolute lifetime
    revoked_at     timestamptz
);

CREATE INDEX admin_sessions_admin_idx ON admin_sessions(local_admin_id);
