-- 0003_user_public_keys.up.sql
-- Users authenticate to the broker by SSH key, and may have several keys.
BEGIN;

CREATE TABLE user_public_keys (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key text NOT NULL UNIQUE,        -- authorized_keys line: "<type> <base64>"
  comment    text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_public_keys_user_idx ON user_public_keys (user_id);

COMMIT;
