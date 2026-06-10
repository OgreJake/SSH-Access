package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/jackc/pgx/v5"
)

// auditLockKey serializes audit appends so the hash chain never forks, even
// across multiple broker instances sharing one database.
const auditLockKey int64 = 0x55D1710A

// AuditEvent is one entry to append to the tamper-evident log (ADR-015).
type AuditEvent struct {
	Actor     string
	EventType string
	Target    string
	Detail    map[string]string
}

// AppendAudit appends an entry, chaining it to the previous record's hash.
// The whole operation runs under an advisory lock in a single transaction so
// concurrent appends serialize and the chain stays linear.
func (s *Store) AppendAudit(ctx context.Context, ev AuditEvent) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLockKey); err != nil {
		return fmt.Errorf("audit lock: %w", err)
	}

	var prev []byte
	err = tx.QueryRow(ctx, "SELECT record_hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read chain head: %w", err)
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	detail := ev.Detail
	if detail == nil {
		detail = map[string]string{}
	}
	detailJSON, err := json.Marshal(detail) // map keys are emitted sorted
	if err != nil {
		return fmt.Errorf("marshal detail: %w", err)
	}
	rec := computeRecordHash(prev, at, ev.Actor, ev.EventType, ev.Target, detailJSON)

	_, err = tx.Exec(ctx,
		`INSERT INTO audit_log (at, actor, event_type, target, detail, prev_hash, record_hash)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
		at, ev.Actor, ev.EventType, ev.Target, string(detailJSON), prev, rec)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return tx.Commit(ctx)
}

// VerifyAuditChain walks the log oldest-first and recomputes every hash,
// returning the number of verified records or an error identifying the first
// broken/tampered link.
func (s *Store) VerifyAuditChain(ctx context.Context) (int, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT at, actor, event_type, COALESCE(target,''), detail, prev_hash, record_hash
		 FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()

	var prev []byte
	n := 0
	for rows.Next() {
		var (
			at                   time.Time
			actor, etype, tgt    string
			detail, pHash, rHash []byte
		)
		if err := rows.Scan(&at, &actor, &etype, &tgt, &detail, &pHash, &rHash); err != nil {
			return n, fmt.Errorf("scan: %w", err)
		}
		if !bytes.Equal(pHash, prev) {
			return n, fmt.Errorf("broken chain at record %d: prev_hash does not match prior record", n+1)
		}
		canon, err := canonicalDetail(detail)
		if err != nil {
			return n, fmt.Errorf("record %d: %w", n+1, err)
		}
		want := computeRecordHash(pHash, at.UTC().Truncate(time.Microsecond), actor, etype, tgt, canon)
		if !bytes.Equal(want, rHash) {
			return n, fmt.Errorf("tampered record %d: recomputed hash does not match stored hash", n+1)
		}
		prev = rHash
		n++
	}
	return n, rows.Err()
}

// computeRecordHash hashes the record fields with the previous hash using a
// length-prefixed encoding so no field boundary is ambiguous.
func computeRecordHash(prev []byte, at time.Time, actor, eventType, target string, detailJSON []byte) []byte {
	h := sha256.New()
	writeField(h, prev)
	writeField(h, []byte(at.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)))
	writeField(h, []byte(actor))
	writeField(h, []byte(eventType))
	writeField(h, []byte(target))
	writeField(h, detailJSON)
	return h.Sum(nil)
}

func writeField(h hash.Hash, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

// canonicalDetail re-serializes stored jsonb to the same canonical form used
// when hashing (sorted keys), so verification is independent of how Postgres
// stores the object.
func canonicalDetail(stored []byte) ([]byte, error) {
	m := map[string]string{}
	if len(stored) > 0 {
		if err := json.Unmarshal(stored, &m); err != nil {
			return nil, fmt.Errorf("decode detail: %w", err)
		}
	}
	return json.Marshal(m)
}
