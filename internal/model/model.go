// Package model defines the broker's domain types. They mirror the database
// schema (see internal/store/migrations). CRUD/repository methods arrive in
// Phase 3; Phase 0 only establishes the shapes.
package model

import "time"

// Enumerations (mirror the Postgres ENUM types).

type AccountStatus string

const (
	AccountActive   AccountStatus = "active"
	AccountDisabled AccountStatus = "disabled"
)

type UserSource string

const (
	SourceLocal UserSource = "local"
	SourceEntra UserSource = "entra"
)

// AccessMode selects how the broker authenticates onward to a target (ADR-012).
type AccessMode string

const (
	ModeCert       AccessMode = "cert"        // A: short-lived SSH cert
	ModeJITKey     AccessMode = "jit_key"     // B1: ephemeral key injected/removed
	ModeStoredCred AccessMode = "stored_cred" // B2: long-lived brokered credential
)

type SubjectType string

const (
	SubjectUser           SubjectType = "user"
	SubjectUserGroup      SubjectType = "user_group"
	SubjectServiceAccount SubjectType = "service_account"
)

type TargetType string

const (
	TargetServer      TargetType = "server"
	TargetServerGroup TargetType = "server_group"
)

type RecordingPolicy string

const (
	RecordMetadata RecordingPolicy = "metadata"
	RecordFull     RecordingPolicy = "full"
)

type ChannelType string

const (
	ChannelShell       ChannelType = "shell"
	ChannelExec        ChannelType = "exec"
	ChannelSFTP        ChannelType = "sftp"
	ChannelPortForward ChannelType = "port_forward"
)

// Entities.

type User struct {
	ID           string
	Username     string
	Email        string
	Source       UserSource
	EntraOID     string
	Status       AccountStatus
	IsBreakGlass bool
	MFAEnrolled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ServiceAccount struct {
	ID          string
	Name        string
	Description string
	Status      AccountStatus
	PublicKey   string // authorized_keys line used to authenticate to the broker
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserGroup struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Server struct {
	ID                 string
	Hostname           string
	Address            string
	Port               int
	HostKeyFingerprint string
	AccessMode         AccessMode
	AllowedPrincipals  []string
	SecretRef          string // secrets.Store ref for legacy modes (B1/B2)
	RecordingOverride  *RecordingPolicy
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type ServerGroup struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Grant authorizes a subject to reach a target (ADR-010).
type Grant struct {
	ID               string
	SubjectType      SubjectType
	SubjectID        string
	TargetType       TargetType
	TargetID         string
	Principals       []string
	MaxTTL           time.Duration
	AllowShell       bool
	AllowExec        bool
	AllowSFTP        bool
	AllowPortForward bool
	Recording        RecordingPolicy
	ReviewBy         *time.Time // SOC 2 recertification (ADR-017)
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Session records one brokered connection (ADR-011).
type Session struct {
	ID             string
	SubjectType    SubjectType
	SubjectID      string
	SubjectLabel   string
	ServerID       string
	ServerLabel    string
	LoginPrincipal string
	AccessMode     AccessMode
	GrantID        string
	SourceIP       string
	CertSerial     *uint64
	Recording      RecordingPolicy
	RecordingRef   string
	StartedAt      time.Time
	EndedAt        *time.Time
	BytesIn        int64
	BytesOut       int64
	ExitStatus     *int
}

// AuditEntry is one append-only, hash-chained audit record (ADR-015).
type AuditEntry struct {
	Seq        int64
	At         time.Time
	Actor      string
	EventType  string
	Target     string
	Detail     map[string]any
	PrevHash   []byte
	RecordHash []byte
}
