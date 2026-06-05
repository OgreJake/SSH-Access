// Package secrets defines the credential store used for legacy targets
// (Mode B in ADR-012) and bootstrap secrets, plus its development backend.
//
// The dev backend (FileStore) encrypts secrets with a local AES-256-GCM key.
// Production uses AWS KMS envelope encryption behind this same interface so
// plaintext credentials never sit on disk and every decrypt is logged to
// CloudTrail (ADR-009).
package secrets

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Get/Delete when no secret exists for the ref.
var ErrNotFound = errors.New("secrets: not found")

// Store holds named secrets. Refs are opaque, caller-defined keys (for
// example "server/<id>/credential"). Implementations must keep secrets
// encrypted at rest.
type Store interface {
	// Get returns the plaintext secret for ref, or ErrNotFound.
	Get(ctx context.Context, ref string) ([]byte, error)
	// Put stores (or replaces) the secret for ref.
	Put(ctx context.Context, ref string, secret []byte) error
	// Delete removes the secret for ref. Deleting a missing ref returns nil.
	Delete(ctx context.Context, ref string) error
	// List returns all refs with the given prefix (empty prefix = all).
	List(ctx context.Context, prefix string) ([]string, error)
}
