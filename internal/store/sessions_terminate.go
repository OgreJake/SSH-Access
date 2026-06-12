package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RequestSessionTermination flags an active session for the broker's revocation
// reaper to kill on its next poll. Returns ErrNotFound if the session does not
// exist or has already ended.
func (s *Store) RequestSessionTermination(ctx context.Context, id string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET terminate_requested = now()
		 WHERE id = $1::uuid AND ended_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("request session termination: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetSessionRecordingURL stores the asciinema-server playback URL for a session
// after its .cast file has been uploaded (ADR-011).
func (s *Store) SetSessionRecordingURL(ctx context.Context, id, url string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET recording_url = $2 WHERE id = $1::uuid`, id, url)
	if err != nil {
		return fmt.Errorf("set recording url: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionRecordingRef returns the stored recording reference for a session
// (empty if it has none). Returns ErrNotFound if the session does not exist.
func (s *Store) SessionRecordingRef(ctx context.Context, id string) (string, error) {
	var ref string
	err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(recording_ref, '') FROM sessions WHERE id = $1::uuid`, id).Scan(&ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("session recording ref: %w", err)
	}
	return ref, nil
}

// SetSessionRecordingRef stores the recording reference (path/key) for a
// session once its full recording has been opened (ADR-011).
func (s *Store) SetSessionRecordingRef(ctx context.Context, id, ref string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET recording_ref = $2 WHERE id = $1::uuid`, id, ref)
	if err != nil {
		return fmt.Errorf("set recording ref: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionsToTerminate returns the subset of the given (still-active) session IDs
// that should be terminated: either explicitly flagged, or whose subject (user
// or service account) is now disabled (ADR-016). The broker passes the IDs of
// the sessions it is currently proxying and kills those returned.
func (s *Store) SessionsToTerminate(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	const q = `
		SELECT s.id::text
		FROM sessions s
		LEFT JOIN users u
		       ON s.subject_type = 'user' AND s.subject_id = u.id
		LEFT JOIN service_accounts sa
		       ON s.subject_type = 'service_account' AND s.subject_id = sa.id
		WHERE s.id = ANY($1::uuid[])
		  AND s.ended_at IS NULL
		  AND (
		        s.terminate_requested IS NOT NULL
		     OR u.status = 'disabled'
		     OR sa.status = 'disabled'
		      )`
	rows, err := s.Pool.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("sessions to terminate: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
