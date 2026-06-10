package proxy

import "context"

// SessionRecord describes a brokered session at the moment it starts.
type SessionRecord struct {
	SubjectType  string
	SubjectLabel string
	Host         string // target alias / server label
	Address      string
	Login        string
	AccessMode   string
	SourceIP     string
	CertSerial   uint64
}

// SessionOutcome summarizes a session at close.
type SessionOutcome struct {
	BytesIn    int64
	BytesOut   int64
	ExitStatus *int
}

// Event is a one-off audit event (e.g. an authorization denial).
type Event struct {
	Actor  string
	Type   string
	Target string
	Detail map[string]string
}

// Auditor records session lifecycle and audit events. The store-backed
// implementation writes session rows and the hash-chained audit log; tests and
// un-wired deployments use NopAuditor.
type Auditor interface {
	StartSession(ctx context.Context, r SessionRecord) (sessionID string, err error)
	EndSession(ctx context.Context, sessionID string, o SessionOutcome) error
	RecordEvent(ctx context.Context, e Event)
}

type nopAuditor struct{}

func (nopAuditor) StartSession(context.Context, SessionRecord) (string, error) { return "", nil }
func (nopAuditor) EndSession(context.Context, string, SessionOutcome) error    { return nil }
func (nopAuditor) RecordEvent(context.Context, Event)                          {}

// NopAuditor discards all audit calls.
var NopAuditor Auditor = nopAuditor{}
