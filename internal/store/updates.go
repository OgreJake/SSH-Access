package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// setBuilder accumulates "col=$N" fragments and their args for partial UPDATEs.
type setBuilder struct {
	sets []string
	args []any
}

// add appends a SET fragment. exprFmt must contain a single %d for the
// placeholder index, e.g. "username=$%d" or "source=$%d::user_source".
func (b *setBuilder) add(exprFmt string, val any) {
	b.args = append(b.args, val)
	b.sets = append(b.sets, fmt.Sprintf(exprFmt, len(b.args)))
}

func (s *Store) execUpdate(ctx context.Context, table string, b *setBuilder, id string) error {
	if len(b.sets) == 0 {
		return nil // nothing to change
	}
	b.args = append(b.args, id)
	q := fmt.Sprintf("UPDATE %s SET %s WHERE id=$%d::uuid", table, strings.Join(b.sets, ", "), len(b.args))
	ct, err := s.Pool.Exec(ctx, q, b.args...)
	if err != nil {
		return fmt.Errorf("update %s: %w", table, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- users ----------

// UpdateUserInput holds optional fields; only non-nil fields are updated.
type UpdateUserInput struct {
	Username *string
	Email    *string
	Source   *string
	Status   *string
}

func (s *Store) UpdateUser(ctx context.Context, id string, in UpdateUserInput) error {
	b := &setBuilder{}
	if in.Username != nil {
		b.add("username=$%d", *in.Username)
	}
	if in.Email != nil {
		b.add("email=$%d", nullIfEmpty(*in.Email))
	}
	if in.Source != nil {
		b.add("source=$%d::user_source", *in.Source)
	}
	if in.Status != nil {
		b.add("status=$%d::account_status", *in.Status)
	}
	return s.execUpdate(ctx, "users", b, id)
}

// ---------- servers ----------

// UpdateServerInput holds optional fields; only non-nil fields are updated.
type UpdateServerInput struct {
	Hostname           *string
	Address            *string
	Port               *int
	HostKeyFingerprint *string
	AccessMode         *string
	AllowedPrincipals  *[]string
}

func (s *Store) UpdateServer(ctx context.Context, id string, in UpdateServerInput) error {
	b := &setBuilder{}
	if in.Hostname != nil {
		b.add("hostname=$%d", *in.Hostname)
	}
	if in.Address != nil {
		b.add("address=$%d", *in.Address)
	}
	if in.Port != nil {
		b.add("port=$%d", *in.Port)
	}
	if in.HostKeyFingerprint != nil {
		b.add("host_key_fingerprint=$%d", nullIfEmpty(*in.HostKeyFingerprint))
	}
	if in.AccessMode != nil {
		b.add("access_mode=$%d::access_mode", *in.AccessMode)
	}
	if in.AllowedPrincipals != nil {
		b.add("allowed_principals=$%d::text[]", *in.AllowedPrincipals)
	}
	return s.execUpdate(ctx, "servers", b, id)
}

// ---------- grants ----------

// UpdateGrantInput holds optional mutable fields (subject/target are fixed; to
// change those, delete and recreate the grant).
type UpdateGrantInput struct {
	Principals       *[]string
	MaxTTL           *time.Duration
	AllowShell       *bool
	AllowExec        *bool
	AllowSFTP        *bool
	AllowPortForward *bool
	Recording        *string
}

func (s *Store) UpdateGrant(ctx context.Context, id string, in UpdateGrantInput) error {
	b := &setBuilder{}
	if in.Principals != nil {
		b.add("principals=$%d::text[]", *in.Principals)
	}
	if in.MaxTTL != nil {
		secs := int(*in.MaxTTL / time.Second)
		if secs <= 0 {
			secs = 300
		}
		b.add("max_ttl=make_interval(secs => $%d::int)", secs)
	}
	if in.AllowShell != nil {
		b.add("allow_shell=$%d", *in.AllowShell)
	}
	if in.AllowExec != nil {
		b.add("allow_exec=$%d", *in.AllowExec)
	}
	if in.AllowSFTP != nil {
		b.add("allow_sftp=$%d", *in.AllowSFTP)
	}
	if in.AllowPortForward != nil {
		b.add("allow_port_forward=$%d", *in.AllowPortForward)
	}
	if in.Recording != nil {
		b.add("recording=$%d::recording_policy", *in.Recording)
	}
	return s.execUpdate(ctx, "grants", b, id)
}

// DeleteGrant removes a grant by id.
func (s *Store) DeleteGrant(ctx context.Context, id string) error {
	ct, err := s.Pool.Exec(ctx, "DELETE FROM grants WHERE id=$1::uuid", id)
	if err != nil {
		return fmt.Errorf("delete grant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes a user and its dependent rows. FK cascades drop the
// user's public keys and group memberships; this also removes grants that
// name the user directly as subject (the polymorphic grants table has no FK).
// Recorded sessions are preserved (sessions.subject_id has no FK and retains
// the subject label for the audit trail).
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.deleteWithDirectGrants(ctx, "users", "subject_type='user' AND subject_id=$1::uuid", id)
}

// DeleteServer removes a server and its dependent rows. FK cascades drop its
// server-group memberships and SET NULL on recorded sessions (the session row
// and its server label are preserved); this also removes grants that name the
// server directly as target.
func (s *Store) DeleteServer(ctx context.Context, id string) error {
	return s.deleteWithDirectGrants(ctx, "servers", "target_type='server' AND target_id=$1::uuid", id)
}

func (s *Store) deleteWithDirectGrants(ctx context.Context, table, grantWhere, id string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "DELETE FROM grants WHERE "+grantWhere, id); err != nil {
		return fmt.Errorf("delete dependent grants: %w", err)
	}
	ct, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE id=$1::uuid", table), id)
	if err != nil {
		return fmt.Errorf("delete %s: %w", table, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ---------- audit export ----------

// AllAudit returns the full audit log oldest-first (for reporting/export),
// capped defensively. The hash chain is verified separately.
func (s *Store) AllAudit(ctx context.Context, max int) ([]AuditRow, error) {
	if max <= 0 || max > 100000 {
		max = 100000
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT seq, at, actor, event_type, COALESCE(target, ''), detail
		 FROM audit_log ORDER BY seq ASC LIMIT $1`, max)
	if err != nil {
		return nil, fmt.Errorf("export audit: %w", err)
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var detail []byte
		if err := rows.Scan(&r.Seq, &r.At, &r.Actor, &r.EventType, &r.Target, &detail); err != nil {
			return nil, err
		}
		r.Detail = detail
		out = append(out, r)
	}
	return out, rows.Err()
}
