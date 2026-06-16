package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SSHLoginRequest is a pending/decided browser-SSO request for an SSH
// connection (ADR-021).
type SSHLoginRequest struct {
	ID              string
	SourceIP        string
	RequestedTarget string
	Status          string
	EntraSubject    string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// CreateSSHLoginRequest opens a pending login for a waiting SSH connection and
// returns its id. codeHash is the SHA-256 of the one-time code embedded in the
// approval URL.
func (s *Store) CreateSSHLoginRequest(ctx context.Context, codeHash []byte, sourceIP, requestedTarget string, expiresAt time.Time) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO ssh_login_requests (code_hash, source_ip, requested_target, expires_at)
		 VALUES ($1, $2, $3, $4) RETURNING id::text`,
		codeHash, sourceIP, requestedTarget, expiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create ssh login request: %w", err)
	}
	return id, nil
}

// LookupSSHLoginByCode returns a still-pending, unexpired request by code hash,
// for display on the approval page. Returns ErrNotFound otherwise.
func (s *Store) LookupSSHLoginByCode(ctx context.Context, codeHash []byte) (*SSHLoginRequest, error) {
	var r SSHLoginRequest
	var subject *string
	err := s.Pool.QueryRow(ctx,
		`SELECT id::text, source_ip, requested_target, status::text, entra_subject, created_at, expires_at
		 FROM ssh_login_requests
		 WHERE code_hash = $1 AND status = 'pending' AND expires_at > now()`, codeHash).
		Scan(&r.ID, &r.SourceIP, &r.RequestedTarget, &r.Status, &subject, &r.CreatedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup ssh login: %w", err)
	}
	if subject != nil {
		r.EntraSubject = *subject
	}
	return &r, nil
}

// decideSSHLogin transitions a pending, unexpired request to approved or denied,
// recording the resolved Entra subject. Returns ErrNotFound if no pending,
// unexpired request matches (already decided, consumed, or expired).
func (s *Store) decideSSHLogin(ctx context.Context, codeHash []byte, subject, status string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE ssh_login_requests
		 SET status = $3::ssh_login_status, entra_subject = $2, approved_at = now()
		 WHERE code_hash = $1 AND status = 'pending' AND expires_at > now()`,
		codeHash, subject, status)
	if err != nil {
		return fmt.Errorf("decide ssh login: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ApproveSSHLogin marks a pending request approved for the given identity.
func (s *Store) ApproveSSHLogin(ctx context.Context, codeHash []byte, subject string) error {
	return s.decideSSHLogin(ctx, codeHash, subject, "approved")
}

// DenySSHLogin marks a pending request denied.
func (s *Store) DenySSHLogin(ctx context.Context, codeHash []byte, subject string) error {
	return s.decideSSHLogin(ctx, codeHash, subject, "denied")
}

// PollSSHLogin returns the current status of a request by id (the SSH side
// waits on this). A pending request past its expiry reports "expired".
func (s *Store) PollSSHLogin(ctx context.Context, id string) (status, subject string, err error) {
	var sub *string
	var expiresAt time.Time
	err = s.Pool.QueryRow(ctx,
		`SELECT status::text, entra_subject, expires_at
		 FROM ssh_login_requests WHERE id = $1::uuid`, id).Scan(&status, &sub, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("poll ssh login: %w", err)
	}
	if status == "pending" && time.Now().After(expiresAt) {
		status = "expired"
	}
	if sub != nil {
		subject = *sub
	}
	return status, subject, nil
}

// ConsumeSSHLogin atomically consumes an approved request (single use) and
// returns the resolved Entra subject. Returns ErrNotFound if the request is not
// currently approved (already consumed, denied, expired, or unknown).
func (s *Store) ConsumeSSHLogin(ctx context.Context, id string) (string, error) {
	var subject *string
	err := s.Pool.QueryRow(ctx,
		`UPDATE ssh_login_requests
		 SET status = 'consumed', consumed_at = now()
		 WHERE id = $1::uuid AND status = 'approved' AND expires_at > now()
		 RETURNING entra_subject`, id).Scan(&subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("consume ssh login: %w", err)
	}
	if subject == nil {
		return "", nil
	}
	return *subject, nil
}

// DeleteExpiredSSHLogins removes finished or expired requests older than the
// cutoff, for periodic cleanup. Returns the number removed.
func (s *Store) DeleteExpiredSSHLogins(ctx context.Context, olderThan time.Time) (int64, error) {
	ct, err := s.Pool.Exec(ctx,
		`DELETE FROM ssh_login_requests
		 WHERE expires_at < $1 OR status IN ('consumed', 'denied')`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("delete expired ssh logins: %w", err)
	}
	return ct.RowsAffected(), nil
}
