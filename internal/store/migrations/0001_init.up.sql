-- 0001_init.up.sql
-- Initial schema for the SSH Access Broker (Phase 0).
-- Mirrors the entities in DECISIONS.md (ADR-010, ADR-011, ADR-012, ADR-015).

BEGIN;

-- gen_random_uuid() is built into PostgreSQL 13+. The extension is harmless
-- there and provides the function on older servers.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enumerations ------------------------------------------------------------
CREATE TYPE account_status   AS ENUM ('active', 'disabled');
CREATE TYPE user_source      AS ENUM ('local', 'entra');
CREATE TYPE access_mode      AS ENUM ('cert', 'jit_key', 'stored_cred');
CREATE TYPE subject_type     AS ENUM ('user', 'user_group', 'service_account');
CREATE TYPE target_type      AS ENUM ('server', 'server_group');
CREATE TYPE recording_policy AS ENUM ('metadata', 'full');
CREATE TYPE channel_type     AS ENUM ('shell', 'exec', 'sftp', 'port_forward');

-- updated_at helper -------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Users -------------------------------------------------------------------
CREATE TABLE users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username       text NOT NULL UNIQUE,
  email          text UNIQUE,
  source         user_source NOT NULL DEFAULT 'local',
  entra_oid      text UNIQUE,                 -- set when SSO-linked (authn only)
  status         account_status NOT NULL DEFAULT 'active',
  is_break_glass boolean NOT NULL DEFAULT false,
  mfa_secret     bytea,                       -- TOTP secret (app-encrypted)
  mfa_enrolled   boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER users_updated BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Service accounts (automation identities, ADR-013) -----------------------
CREATE TABLE service_accounts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  status      account_status NOT NULL DEFAULT 'active',
  public_key  text NOT NULL,                  -- authorized_keys line for broker authn
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER service_accounts_updated BEFORE UPDATE ON service_accounts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- User groups -------------------------------------------------------------
CREATE TABLE user_groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER user_groups_updated BEFORE UPDATE ON user_groups
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE user_group_members (
  user_group_id uuid NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  added_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_group_id, user_id)
);

-- Servers -----------------------------------------------------------------
CREATE TABLE servers (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname             text NOT NULL,
  address              text NOT NULL,
  port                 integer NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
  host_key_fingerprint text,                  -- pinned SHA256 host-key fp
  access_mode          access_mode NOT NULL DEFAULT 'cert',
  allowed_principals   text[] NOT NULL DEFAULT '{}',
  secret_ref           text,                  -- secrets.Store ref for legacy modes
  recording_override   recording_policy,      -- overrides grant policy when set
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (address, port),
  -- legacy modes require a brokered credential reference
  CONSTRAINT servers_legacy_secret_ck
    CHECK (access_mode = 'cert' OR secret_ref IS NOT NULL)
);
CREATE TRIGGER servers_updated BEFORE UPDATE ON servers
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Server groups -----------------------------------------------------------
CREATE TABLE server_groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER server_groups_updated BEFORE UPDATE ON server_groups
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE server_group_members (
  server_group_id uuid NOT NULL REFERENCES server_groups(id) ON DELETE CASCADE,
  server_id       uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  added_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (server_group_id, server_id)
);

-- Grants ------------------------------------------------------------------
-- subject_id / target_id are polymorphic (point at users/user_groups/
-- service_accounts and servers/server_groups respectively). Referential
-- integrity for these is enforced at the application layer.
CREATE TABLE grants (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type       subject_type NOT NULL,
  subject_id         uuid NOT NULL,
  target_type        target_type NOT NULL,
  target_id          uuid NOT NULL,
  principals         text[] NOT NULL DEFAULT '{}',
  max_ttl            interval NOT NULL DEFAULT '5 minutes',
  allow_shell        boolean NOT NULL DEFAULT true,
  allow_exec         boolean NOT NULL DEFAULT true,
  allow_sftp         boolean NOT NULL DEFAULT false,
  allow_port_forward boolean NOT NULL DEFAULT false,
  recording          recording_policy NOT NULL DEFAULT 'metadata',
  review_by          date,                    -- SOC 2 recertification (ADR-017)
  created_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER grants_updated BEFORE UPDATE ON grants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX grants_subject_idx ON grants (subject_type, subject_id);
CREATE INDEX grants_target_idx  ON grants (target_type, target_id);
CREATE INDEX grants_review_idx  ON grants (review_by) WHERE review_by IS NOT NULL;

-- Sessions ----------------------------------------------------------------
CREATE TABLE sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type    subject_type NOT NULL,
  subject_id      uuid NOT NULL,
  subject_label   text NOT NULL,              -- denormalized for audit readability
  server_id       uuid REFERENCES servers(id) ON DELETE SET NULL,
  server_label    text NOT NULL,
  login_principal text NOT NULL,
  access_mode     access_mode NOT NULL,
  grant_id        uuid REFERENCES grants(id) ON DELETE SET NULL,
  source_ip       inet,
  cert_serial     bigint,                     -- mode 'cert' only
  recording       recording_policy NOT NULL DEFAULT 'metadata',
  recording_ref   text,                       -- ref to recording when 'full'
  started_at      timestamptz NOT NULL DEFAULT now(),
  ended_at        timestamptz,
  bytes_in        bigint NOT NULL DEFAULT 0,
  bytes_out       bigint NOT NULL DEFAULT 0,
  exit_status     integer
);
CREATE INDEX sessions_subject_idx ON sessions (subject_type, subject_id);
CREATE INDEX sessions_server_idx  ON sessions (server_id);
CREATE INDEX sessions_started_idx ON sessions (started_at DESC);

CREATE TABLE session_channels (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id   uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  channel_type channel_type NOT NULL,
  opened_at    timestamptz NOT NULL DEFAULT now(),
  closed_at    timestamptz,
  detail       jsonb NOT NULL DEFAULT '{}'    -- e.g. exec command, forward target
);
CREATE INDEX session_channels_session_idx ON session_channels (session_id);

-- SFTP/SCP file-transfer manifest (ADR-011 / ADR-014)
CREATE TABLE session_file_transfers (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  direction  text NOT NULL CHECK (direction IN ('upload', 'download')),
  path       text NOT NULL,
  size_bytes bigint NOT NULL DEFAULT 0,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_file_transfers_session_idx ON session_file_transfers (session_id);

-- Audit log (append-only, hash-chained, ADR-015) --------------------------
CREATE TABLE audit_log (
  seq         bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text NOT NULL,                  -- username / service account / 'system'
  event_type  text NOT NULL,                  -- e.g. 'auth.success', 'grant.create'
  target      text,                           -- affected entity
  detail      jsonb NOT NULL DEFAULT '{}',
  prev_hash   bytea,                          -- hash of previous record
  record_hash bytea NOT NULL                  -- hash over this record + prev_hash
);
CREATE INDEX audit_log_at_idx    ON audit_log (at);
CREATE INDEX audit_log_actor_idx ON audit_log (actor);
CREATE INDEX audit_log_event_idx ON audit_log (event_type);

-- Tamper-evidence: the audit log is append-only.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

COMMIT;
