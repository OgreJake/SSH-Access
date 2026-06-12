package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned by lookups that match no row.
var ErrNotFound = errors.New("store: record not found")

// ---------- Identities / key authentication ----------

// AuthnIdentity is the result of resolving an offered public key to a subject.
type AuthnIdentity struct {
	SubjectType string // "user" | "service_account"
	ID          string
	Label       string // username or service-account name
	Active      bool   // false if the account is disabled/suspended
}

// AuthnByKey resolves an authorized_keys line ("<type> <base64>") to a subject,
// searching user keys first, then service accounts. Returns ErrNotFound if the
// key is registered to neither.
func (s *Store) AuthnByKey(ctx context.Context, publicKeyLine string) (*AuthnIdentity, error) {
	const q = `
		SELECT 'user' AS subject_type, u.id::text, u.username, (u.status = 'active')
		FROM user_public_keys k JOIN users u ON u.id = k.user_id
		WHERE k.public_key = $1
		UNION ALL
		SELECT 'service_account', sa.id::text, sa.name, (sa.status = 'active')
		FROM service_accounts sa
		WHERE sa.public_key = $1
		LIMIT 1`
	var id AuthnIdentity
	err := s.Pool.QueryRow(ctx, q, publicKeyLine).
		Scan(&id.SubjectType, &id.ID, &id.Label, &id.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("authn by key: %w", err)
	}
	return &id, nil
}

// ---------- Users ----------

// CreateUser inserts a user and returns its id. email may be nil.
func (s *Store) CreateUser(ctx context.Context, username string, email *string, source, status string) (string, error) {
	if source == "" {
		source = "local"
	}
	if status == "" {
		status = "active"
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO users (username, email, source, status)
		 VALUES ($1, $2, $3::user_source, $4::account_status) RETURNING id`,
		username, email, source, status).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// AddUserKey registers a public key for a user and returns the key id.
func (s *Store) AddUserKey(ctx context.Context, userID, publicKeyLine, comment string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO user_public_keys (user_id, public_key, comment)
		 VALUES ($1::uuid, $2, $3) RETURNING id`,
		userID, publicKeyLine, comment).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("add user key: %w", err)
	}
	return id, nil
}

// SetUserStatus changes a user's account status (e.g. active → disabled).
func (s *Store) SetUserStatus(ctx context.Context, userID, status string) error {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE users SET status = $2::account_status WHERE id = $1::uuid`, userID, status)
	if err != nil {
		return fmt.Errorf("set user status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListGroupsForUser returns the user-group ids a user belongs to.
func (s *Store) ListGroupsForUser(ctx context.Context, userID string) ([]string, error) {
	return s.scanIDs(ctx,
		`SELECT user_group_id::text FROM user_group_members WHERE user_id = $1::uuid`, userID)
}

// ---------- Service accounts ----------

// CreateServiceAccount inserts a service account (authenticating by key).
func (s *Store) CreateServiceAccount(ctx context.Context, name, publicKeyLine, status string) (string, error) {
	if status == "" {
		status = "active"
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO service_accounts (name, public_key, status)
		 VALUES ($1, $2, $3::account_status) RETURNING id`,
		name, publicKeyLine, status).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create service account: %w", err)
	}
	return id, nil
}

// ---------- Groups ----------

func (s *Store) CreateUserGroup(ctx context.Context, name string) (string, error) {
	return s.insertNamed(ctx, `INSERT INTO user_groups (name) VALUES ($1) RETURNING id`, name, "user group")
}

func (s *Store) AddUserToGroup(ctx context.Context, groupID, userID string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO user_group_members (user_group_id, user_id) VALUES ($1::uuid, $2::uuid)
		 ON CONFLICT DO NOTHING`, groupID, userID)
	if err != nil {
		return fmt.Errorf("add user to group: %w", err)
	}
	return nil
}

func (s *Store) CreateServerGroup(ctx context.Context, name string) (string, error) {
	return s.insertNamed(ctx, `INSERT INTO server_groups (name) VALUES ($1) RETURNING id`, name, "server group")
}

func (s *Store) AddServerToGroup(ctx context.Context, groupID, serverID string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO server_group_members (server_group_id, server_id) VALUES ($1::uuid, $2::uuid)
		 ON CONFLICT DO NOTHING`, groupID, serverID)
	if err != nil {
		return fmt.Errorf("add server to group: %w", err)
	}
	return nil
}

// ListGroupsForServer returns the server-group ids a server belongs to.
func (s *Store) ListGroupsForServer(ctx context.Context, serverID string) ([]string, error) {
	return s.scanIDs(ctx,
		`SELECT server_group_id::text FROM server_group_members WHERE server_id = $1::uuid`, serverID)
}

// ---------- Servers ----------

// CreateServerInput describes a target host to register.
type CreateServerInput struct {
	Hostname           string // the alias used in login+host
	Address            string // host:port or host (port column carries the port)
	Port               int
	HostKeyFingerprint string
	AccessMode         string // "cert" (default) | "jit_key" | "stored_cred"
	AllowedPrincipals  []string
	SecretRef          *string
}

// Server is a resolved target.
type Server struct {
	ID                 string
	Hostname           string
	Address            string
	Port               int
	HostKeyFingerprint string
	AccessMode         string
	AllowedPrincipals  []string
	SecretRef          string
}

func (s *Store) CreateServer(ctx context.Context, in CreateServerInput) (string, error) {
	if in.AccessMode == "" {
		in.AccessMode = "cert"
	}
	if in.Port == 0 {
		in.Port = 22
	}
	if in.AllowedPrincipals == nil {
		in.AllowedPrincipals = []string{} // NOT NULL column; empty array, not NULL
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO servers
		  (hostname, address, port, host_key_fingerprint, access_mode, allowed_principals, secret_ref)
		 VALUES ($1, $2, $3, $4, $5::access_mode, $6::text[], $7)
		 RETURNING id`,
		in.Hostname, in.Address, in.Port, nullIfEmpty(in.HostKeyFingerprint),
		in.AccessMode, in.AllowedPrincipals, in.SecretRef).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create server: %w", err)
	}
	return id, nil
}

// GetServerByHostname resolves a target alias to a server.
func (s *Store) GetServerByHostname(ctx context.Context, hostname string) (*Server, error) {
	var srv Server
	err := s.Pool.QueryRow(ctx,
		`SELECT id::text, hostname, address, port,
		        COALESCE(host_key_fingerprint, ''), access_mode::text,
		        allowed_principals, COALESCE(secret_ref, '')
		 FROM servers WHERE hostname = $1`, hostname).
		Scan(&srv.ID, &srv.Hostname, &srv.Address, &srv.Port,
			&srv.HostKeyFingerprint, &srv.AccessMode, &srv.AllowedPrincipals, &srv.SecretRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	return &srv, nil
}

// ---------- Grants ----------

// CreateGrantInput describes an RBAC grant (subject → target, ADR-010/014).
type CreateGrantInput struct {
	SubjectType string // "user" | "user_group"
	SubjectID   string
	TargetType  string // "server" | "server_group"
	TargetID    string
	Principals  []string
	MaxTTL      time.Duration
	AllowShell  bool
	AllowExec   bool
	AllowSFTP   bool
	Recording   string // recording_policy enum
	ReviewBy    *time.Time
}

// Grant is a matched grant returned to the authorizer.
type Grant struct {
	ID         string
	Principals []string
	MaxTTL     time.Duration
	AllowShell bool
	AllowExec  bool
	AllowSFTP  bool
	Recording  string
}

func (s *Store) CreateGrant(ctx context.Context, in CreateGrantInput) (string, error) {
	if in.Recording == "" {
		in.Recording = "metadata"
	}
	secs := int(in.MaxTTL / time.Second)
	if secs <= 0 {
		secs = 300
	}
	var id string
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO grants
		  (subject_type, subject_id, target_type, target_id, principals, max_ttl,
		   allow_shell, allow_exec, allow_sftp, recording, review_by)
		 VALUES ($1::subject_type, $2::uuid, $3::target_type, $4::uuid,
		         $5::text[], make_interval(secs => $6::int),
		         $7, $8, $9, $10::recording_policy, $11)
		 RETURNING id`,
		in.SubjectType, in.SubjectID, in.TargetType, in.TargetID, in.Principals, secs,
		in.AllowShell, in.AllowExec, in.AllowSFTP, in.Recording, in.ReviewBy).
		Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create grant: %w", err)
	}
	return id, nil
}

// MatchingGrants returns every grant whose subject is the given subject or one
// of the user's groups AND whose target is the server or one of its groups.
// subjectType is "user" or "service_account"; userGroupIDs applies only to
// users (pass nil for service accounts). This is the core group-to-group RBAC
// resolution (ADR-010); decision composition lives in the authorizer.
func (s *Store) MatchingGrants(ctx context.Context, subjectType, subjectID string, userGroupIDs []string, serverID string, serverGroupIDs []string) ([]Grant, error) {
	const q = `
		SELECT id::text, principals, EXTRACT(EPOCH FROM max_ttl)::bigint,
		       allow_shell, allow_exec, allow_sftp, recording::text
		FROM grants
		WHERE (
		        (subject_type = $1::subject_type AND subject_id = $2::uuid)
		     OR (subject_type = 'user_group'     AND subject_id = ANY($3::uuid[]))
		      )
		  AND (
		        (target_type = 'server'       AND target_id = $4::uuid)
		     OR (target_type = 'server_group' AND target_id = ANY($5::uuid[]))
		      )`
	rows, err := s.Pool.Query(ctx, q, subjectType, subjectID, userGroupIDs, serverID, serverGroupIDs)
	if err != nil {
		return nil, fmt.Errorf("matching grants: %w", err)
	}
	defer rows.Close()

	var out []Grant
	for rows.Next() {
		var g Grant
		var secs int64
		if err := rows.Scan(&g.ID, &g.Principals, &secs,
			&g.AllowShell, &g.AllowExec, &g.AllowSFTP, &g.Recording); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		g.MaxTTL = time.Duration(secs) * time.Second
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---------- helpers ----------

func (s *Store) insertNamed(ctx context.Context, q, name, what string) (string, error) {
	var id string
	if err := s.Pool.QueryRow(ctx, q, name).Scan(&id); err != nil {
		return "", fmt.Errorf("create %s: %w", what, err)
	}
	return id, nil
}

func (s *Store) scanIDs(ctx context.Context, q string, arg any) ([]string, error) {
	rows, err := s.Pool.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("query ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
