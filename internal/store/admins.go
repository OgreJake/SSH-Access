package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LocalAdmin is a break-glass management operator.
type LocalAdmin struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	Status       string
	LastLoginAt  *time.Time
}

// UpsertLocalAdmin creates or updates a break-glass admin's password and role
// (idempotent by username), so operators can (re)provision via the CLI.
func (s *Store) UpsertLocalAdmin(ctx context.Context, username, passwordHash, role string) (string, error) {
	if role == "" {
		role = "admin"
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO local_admins (username, password_hash, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (username)
		 DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
		 RETURNING id::text`, username, passwordHash, role).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert local admin: %w", err)
	}
	return id, nil
}

// GetLocalAdminByUsername returns an active break-glass admin by username.
func (s *Store) GetLocalAdminByUsername(ctx context.Context, username string) (*LocalAdmin, error) {
	var a LocalAdmin
	err := s.Pool.QueryRow(ctx,
		`SELECT id::text, username, password_hash, role, status::text, last_login_at
		 FROM local_admins WHERE username = $1`, username).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &a.Role, &a.Status, &a.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get local admin: %w", err)
	}
	return &a, nil
}

// SetLocalAdminStatus enables/disables a break-glass admin.
func (s *Store) SetLocalAdminStatus(ctx context.Context, username, status string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE local_admins SET status = $2::account_status WHERE username = $1`, username, status)
	if err != nil {
		return fmt.Errorf("set local admin status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminSession is a live break-glass session resolved from a cookie token.
type AdminSession struct {
	ID        string
	AdminID   string
	Username  string
	Role      string
	ExpiresAt time.Time
}

// CreateAdminSession opens a break-glass session for an admin and records the
// login time. tokenHash is the SHA-256 of the cookie token.
func (s *Store) CreateAdminSession(ctx context.Context, adminID string, tokenHash []byte, expiresAt time.Time) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id string
	if err := tx.QueryRow(ctx,
		`INSERT INTO admin_sessions (token_hash, local_admin_id, expires_at)
		 VALUES ($1, $2::uuid, $3) RETURNING id::text`, tokenHash, adminID, expiresAt).Scan(&id); err != nil {
		return "", fmt.Errorf("create admin session: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE local_admins SET last_login_at = now() WHERE id = $1::uuid`, adminID); err != nil {
		return "", fmt.Errorf("update last login: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// LookupAdminSession resolves an active (non-expired, non-revoked, admin still
// active) session by token hash, sliding the idle window. idleTimeout <= 0
// disables the idle check. Returns ErrNotFound when no valid session matches.
func (s *Store) LookupAdminSession(ctx context.Context, tokenHash []byte, idleTimeout time.Duration) (*AdminSession, error) {
	var (
		sess     AdminSession
		lastSeen time.Time
	)
	err := s.Pool.QueryRow(ctx,
		`SELECT s.id::text, s.local_admin_id::text, a.username, a.role, s.expires_at, s.last_seen_at
		 FROM admin_sessions s
		 JOIN local_admins a ON a.id = s.local_admin_id
		 WHERE s.token_hash = $1
		   AND s.revoked_at IS NULL
		   AND s.expires_at > now()
		   AND a.status = 'active'`, tokenHash).
		Scan(&sess.ID, &sess.AdminID, &sess.Username, &sess.Role, &sess.ExpiresAt, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup admin session: %w", err)
	}
	if idleTimeout > 0 && time.Since(lastSeen) > idleTimeout {
		_, _ = s.Pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at = now() WHERE id = $1::uuid`, sess.ID)
		return nil, ErrNotFound
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE admin_sessions SET last_seen_at = now() WHERE id = $1::uuid`, sess.ID)
	return &sess, nil
}

// RevokeAdminSession revokes a session by token hash (logout). Idempotent.
func (s *Store) RevokeAdminSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE admin_sessions SET revoked_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash)
	if err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	return nil
}
