-- ADR-011: store the asciinema-server playback URL produced after uploading the
-- session's .cast file. recording_ref keeps the local artifact name.
ALTER TABLE sessions ADD COLUMN recording_url text;
