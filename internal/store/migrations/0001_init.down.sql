-- 0001_init.down.sql
-- Reverses 0001_init.up.sql.

BEGIN;

DROP TABLE IF EXISTS audit_log CASCADE;
DROP FUNCTION IF EXISTS audit_log_immutable();

DROP TABLE IF EXISTS session_file_transfers CASCADE;
DROP TABLE IF EXISTS session_channels CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;

DROP TABLE IF EXISTS grants CASCADE;

DROP TABLE IF EXISTS server_group_members CASCADE;
DROP TABLE IF EXISTS server_groups CASCADE;
DROP TABLE IF EXISTS servers CASCADE;

DROP TABLE IF EXISTS user_group_members CASCADE;
DROP TABLE IF EXISTS user_groups CASCADE;
DROP TABLE IF EXISTS service_accounts CASCADE;
DROP TABLE IF EXISTS users CASCADE;

DROP FUNCTION IF EXISTS set_updated_at();

DROP TYPE IF EXISTS channel_type;
DROP TYPE IF EXISTS recording_policy;
DROP TYPE IF EXISTS target_type;
DROP TYPE IF EXISTS subject_type;
DROP TYPE IF EXISTS access_mode;
DROP TYPE IF EXISTS user_source;
DROP TYPE IF EXISTS account_status;

COMMIT;
