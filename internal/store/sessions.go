package store

import (
	"context"
	"fmt"
)

// SessionStart describes a brokered session to record (ADR-011). UUID fields
// are pointers because file-backed identities/targets (Phase 2) have none yet.
type SessionStart struct {
	SubjectType    string
	SubjectID      *string
	SubjectLabel   string
	ServerID       *string
	ServerLabel    string
	LoginPrincipal string
	AccessMode     string
	GrantID        *string
	SourceIP       string
	CertSerial     *int64
	Recording      string
}

// CreateSession inserts a new session row and returns its id.
func (s *Store) CreateSession(ctx context.Context, in SessionStart) (string, error) {
	if in.Recording == "" {
		in.Recording = "metadata"
	}
	var sourceIP any
	if in.SourceIP != "" {
		sourceIP = in.SourceIP
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO sessions
		  (subject_type, subject_id, subject_label, server_id, server_label,
		   login_principal, access_mode, grant_id, source_ip, cert_serial, recording)
		 VALUES
		  ($1::subject_type, $2::uuid, $3, $4::uuid, $5,
		   $6, $7::access_mode, $8::uuid, $9::inet, $10, $11::recording_policy)
		 RETURNING id`,
		in.SubjectType, in.SubjectID, in.SubjectLabel, in.ServerID, in.ServerLabel,
		in.LoginPrincipal, in.AccessMode, in.GrantID, sourceIP, in.CertSerial, in.Recording,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}
	return id, nil
}

// EndSession finalizes a session row with its outcome.
func (s *Store) EndSession(ctx context.Context, id string, bytesIn, bytesOut int64, exitStatus *int) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE sessions
		 SET ended_at = now(), bytes_in = $2, bytes_out = $3, exit_status = $4
		 WHERE id = $1`,
		id, bytesIn, bytesOut, exitStatus)
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}
