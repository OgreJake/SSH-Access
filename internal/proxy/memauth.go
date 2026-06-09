package proxy

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/model"
)

// MemoryAuthenticator authenticates against an in-memory set of public keys.
// It is the development backend; production authentication is DB-backed
// (Phase 3) behind the same Authenticator interface.
type MemoryAuthenticator struct {
	mu    sync.RWMutex
	byKey map[string]Identity // key: marshaled public key bytes
}

var _ Authenticator = (*MemoryAuthenticator)(nil)

// NewMemoryAuthenticator returns an empty authenticator.
func NewMemoryAuthenticator() *MemoryAuthenticator {
	return &MemoryAuthenticator{byKey: make(map[string]Identity)}
}

// Add registers (or replaces) the identity for a public key.
func (m *MemoryAuthenticator) Add(key ssh.PublicKey, id Identity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byKey[string(key.Marshal())] = id
}

// Len reports how many keys are registered.
func (m *MemoryAuthenticator) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byKey)
}

// AuthenticatePublicKey looks up the offered key.
func (m *MemoryAuthenticator) AuthenticatePublicKey(key ssh.PublicKey) (*Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byKey[string(key.Marshal())]
	if !ok {
		return nil, ErrUnauthorized
	}
	return &id, nil
}

// LoadAuthorizedUsers builds a MemoryAuthenticator from an authorized_keys-
// format file. Each entry's comment field is taken as the username; entries
// without a comment are rejected so an unnamed key can never authenticate.
func LoadAuthorizedUsers(path string) (*MemoryAuthenticator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized users %q: %w", path, err)
	}
	auth := NewMemoryAuthenticator()
	rest := data
	for len(rest) > 0 {
		key, comment, _, remaining, perr := ssh.ParseAuthorizedKey(rest)
		if perr != nil {
			// No more parseable keys.
			break
		}
		rest = remaining
		if comment == "" {
			return nil, fmt.Errorf("authorized user entry is missing a username (comment)")
		}
		auth.Add(key, Identity{
			Subject: model.SubjectUser,
			ID:      comment,
			Label:   comment,
		})
	}
	return auth, nil
}
