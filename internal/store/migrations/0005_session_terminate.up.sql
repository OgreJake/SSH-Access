-- ADR-016: explicit session termination. A non-null terminate_requested marks
-- a session for the broker's revocation reaper to kill.
ALTER TABLE sessions ADD COLUMN terminate_requested timestamptz;
