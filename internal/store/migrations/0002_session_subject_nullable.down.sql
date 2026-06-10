-- 0002_session_subject_nullable.down.sql
BEGIN;
ALTER TABLE sessions ALTER COLUMN subject_id SET NOT NULL;
COMMIT;
