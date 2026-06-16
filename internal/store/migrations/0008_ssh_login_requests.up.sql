-- ADR-021: browser SSO/MFA for SSH via device-authorization-style correlation.
-- The SSH broker process creates a pending request and waits; the API process
-- (behind oauth2-proxy) marks it approved with the resolved Entra identity.
CREATE TYPE ssh_login_status AS ENUM ('pending', 'approved', 'denied', 'consumed');

CREATE TABLE ssh_login_requests (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash        bytea NOT NULL UNIQUE,          -- sha-256 of the one-time code
    source_ip        text NOT NULL DEFAULT '',
    requested_target text NOT NULL DEFAULT '',       -- the SSH username, e.g. alice+web01
    status           ssh_login_status NOT NULL DEFAULT 'pending',
    entra_subject    text,                            -- set on approval
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    approved_at      timestamptz,
    consumed_at      timestamptz
);

-- Sweep helper: find expired/finished rows for periodic cleanup.
CREATE INDEX ssh_login_requests_expiry_idx ON ssh_login_requests (expires_at);
