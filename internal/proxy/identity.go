// Package proxy implements the broker's SSH front door. The broker terminates
// the user's SSH connection (it is an SSH server), authenticates the principal,
// and — in later slices — re-originates a fresh connection to the target using
// a freshly minted certificate, proxying channel data between the two
// (ADR-002). Terminating rather than tunnelling is what lets the broker mint
// per-session certs, enforce capabilities, and record sessions.
//
// This slice (Phase 2a) covers listening and public-key authentication.
package proxy

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/model"
)

// ErrUnauthorized is returned by an Authenticator when a principal cannot be
// identified or is not allowed to connect. The proxy never reports the precise
// reason to the client.
var ErrUnauthorized = errors.New("proxy: unauthorized")

// Identity is an authenticated principal (a user or a service account). The
// human/automation is identified by its key; the SSH username field is left
// to carry the target specification, resolved in a later slice.
type Identity struct {
	Subject model.SubjectType
	ID      string
	Label   string // username / service-account name, for audit
}

// Authenticator resolves an offered public key to an Identity. The DB-backed
// implementation arrives in Phase 3; MemoryAuthenticator is the dev backend.
type Authenticator interface {
	AuthenticatePublicKey(key ssh.PublicKey) (*Identity, error)
}

// BrowserLogin drives the device-authorization-style SSH browser SSO/MFA flow
// (ADR-021). It is implemented over the store + config by the broker, keeping
// the proxy decoupled from both. When set, the front door offers
// keyboard-interactive in addition to publickey; human users with no registered
// key fall through to this browser flow.
type BrowserLogin interface {
	// Begin creates a pending login for the waiting connection and returns its
	// id plus the approval URL to display to the user.
	Begin(ctx context.Context, sourceIP, requestedTarget string) (id, approvalURL string, err error)
	// Poll reports the current status: "pending", "approved", "denied", or
	// "expired"; when approved it also returns the resolved Entra subject.
	Poll(ctx context.Context, id string) (status, subject string, err error)
	// Consume atomically claims an approved login (single use), returning the subject.
	Consume(ctx context.Context, id string) (subject string, err error)
	// Resolve maps an authenticated Entra subject to a broker Identity
	// (JIT-provisioning per config). Returns ErrUnauthorized when the subject is
	// unknown and JIT is disabled, or the user is not active.
	Resolve(ctx context.Context, subject string) (*Identity, error)
}

func subjectType(s string) model.SubjectType { return model.SubjectType(s) }
