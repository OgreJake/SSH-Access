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

func subjectType(s string) model.SubjectType { return model.SubjectType(s) }
