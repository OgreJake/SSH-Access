-- 0002_session_subject_nullable.up.sql
-- File-backed identities (Phase 2) have no UUID; the readable subject_label
-- carries identity until DB-backed auth (Phase 3) supplies real UUIDs.
BEGIN;
ALTER TABLE sessions ALTER COLUMN subject_id DROP NOT NULL;
COMMIT;
