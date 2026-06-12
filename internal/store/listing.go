package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsConflict reports whether err is a Postgres unique-violation (23505), so the
// API can map duplicate usernames/keys/etc. to 409 Conflict.
func IsConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// SessionRow is a session summary for listings.
type SessionRow struct {
	ID           string
	StartedAt    time.Time
	EndedAt      *time.Time
	SubjectLabel string
	ServerLabel  string
	Login        string
	SourceIP     string
	CertSerial   *int64
	BytesIn      int64
	BytesOut     int64
	ExitStatus   *int
	Recording    string
	RecordingRef string
}

// ListRecentSessions returns the most recent sessions, newest first.
func (s *Store) ListRecentSessions(ctx context.Context, limit int) ([]SessionRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT id::text, started_at, ended_at, subject_label, server_label,
		        login_principal, COALESCE(host(source_ip), ''), cert_serial,
		        bytes_in, bytes_out, exit_status, recording::text, COALESCE(recording_ref, '')
		 FROM sessions ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.EndedAt, &r.SubjectLabel, &r.ServerLabel,
			&r.Login, &r.SourceIP, &r.CertSerial, &r.BytesIn, &r.BytesOut, &r.ExitStatus, &r.Recording, &r.RecordingRef); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditRow is one audit-log entry for listings.
type AuditRow struct {
	Seq       int64
	At        time.Time
	Actor     string
	EventType string
	Target    string
	Detail    json.RawMessage
}

// ListRecentAudit returns the most recent audit entries, newest first.
func (s *Store) ListRecentAudit(ctx context.Context, limit int) ([]AuditRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT seq, at, actor, event_type, COALESCE(target, ''), detail
		 FROM audit_log ORDER BY seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var detail []byte
		if err := rows.Scan(&r.Seq, &r.At, &r.Actor, &r.EventType, &r.Target, &detail); err != nil {
			return nil, err
		}
		r.Detail = json.RawMessage(detail)
		out = append(out, r)
	}
	return out, rows.Err()
}
