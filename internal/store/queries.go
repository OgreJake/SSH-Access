package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------- name → id lookups ----------

func (s *Store) UserIDByUsername(ctx context.Context, username string) (string, error) {
	return s.scanID(ctx, `SELECT id::text FROM users WHERE username = $1`, username)
}

func (s *Store) UserGroupIDByName(ctx context.Context, name string) (string, error) {
	return s.scanID(ctx, `SELECT id::text FROM user_groups WHERE name = $1`, name)
}

func (s *Store) ServerGroupIDByName(ctx context.Context, name string) (string, error) {
	return s.scanID(ctx, `SELECT id::text FROM server_groups WHERE name = $1`, name)
}

func (s *Store) scanID(ctx context.Context, q, arg string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, q, arg).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lookup: %w", err)
	}
	return id, nil
}

// ---------- list rows (for the admin CLI) ----------

type UserRow struct {
	ID       string
	Username string
	Email    string
	Source   string
	Status   string
	KeyCount int
}

func (s *Store) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT u.id::text, u.username, COALESCE(u.email,''), u.source::text, u.status::text,
		        (SELECT count(*) FROM user_public_keys k WHERE k.user_id = u.id)
		 FROM users u ORDER BY u.username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Source, &u.Status, &u.KeyCount); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type ServerRow struct {
	ID                string
	Hostname          string
	Address           string
	Port              int
	AccessMode        string
	AllowedPrincipals []string
}

func (s *Store) ListServers(ctx context.Context) ([]ServerRow, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id::text, hostname, address, port, access_mode::text, allowed_principals
		 FROM servers ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	defer rows.Close()
	var out []ServerRow
	for rows.Next() {
		var sv ServerRow
		if err := rows.Scan(&sv.ID, &sv.Hostname, &sv.Address, &sv.Port, &sv.AccessMode, &sv.AllowedPrincipals); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

type GrantRow struct {
	ID          string
	SubjectType string
	Subject     string // resolved label
	TargetType  string
	Target      string // resolved label
	Principals  []string
	MaxTTL      time.Duration
	Shell       bool
	Exec        bool
	SFTP        bool
	Recording   string
}

func (s *Store) ListGrants(ctx context.Context) ([]GrantRow, error) {
	const q = `
		SELECT g.id::text, g.subject_type::text,
		       COALESCE(u.username, ug.name, sa.name, '') AS subject_label,
		       g.target_type::text,
		       COALESCE(s.hostname, sg.name, '') AS target_label,
		       g.principals, EXTRACT(EPOCH FROM g.max_ttl)::bigint,
		       g.allow_shell, g.allow_exec, g.allow_sftp, g.recording::text
		FROM grants g
		LEFT JOIN users          u  ON g.subject_type = 'user'          AND g.subject_id = u.id
		LEFT JOIN user_groups    ug ON g.subject_type = 'user_group'    AND g.subject_id = ug.id
		LEFT JOIN service_accounts sa ON g.subject_type = 'service_account' AND g.subject_id = sa.id
		LEFT JOIN servers        s  ON g.target_type = 'server'         AND g.target_id = s.id
		LEFT JOIN server_groups  sg ON g.target_type = 'server_group'   AND g.target_id = sg.id
		ORDER BY subject_label, target_label`
	rows, err := s.Pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer rows.Close()
	var out []GrantRow
	for rows.Next() {
		var g GrantRow
		var secs int64
		if err := rows.Scan(&g.ID, &g.SubjectType, &g.Subject, &g.TargetType, &g.Target,
			&g.Principals, &secs, &g.Shell, &g.Exec, &g.SFTP, &g.Recording); err != nil {
			return nil, err
		}
		g.MaxTTL = time.Duration(secs) * time.Second
		out = append(out, g)
	}
	return out, rows.Err()
}
