package proxy

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/model"
)

// ResolvedIdentity is what a KeyLookup returns for an offered key. Active is
// false when the account exists but is disabled.
type ResolvedIdentity struct {
	Subject model.SubjectType
	ID      string
	Label   string
	Active  bool
}

// KeyLookup resolves an authorized_keys line to an identity. A nil identity
// with a nil error means the key is registered to no one.
type KeyLookup interface {
	AuthnByKey(ctx context.Context, publicKeyLine string) (*ResolvedIdentity, error)
}

// AuthorizedKeyLine renders a public key as the canonical authorized_keys line
// ("<type> <base64>", no comment) used as the lookup key in the database.
// Seeding (admin CLI) and authentication MUST use this same form.
func AuthorizedKeyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// DBAuthenticator authenticates offered public keys against a database-backed
// KeyLookup. It fails closed: any lookup error, unknown key, or disabled
// account results in ErrUnauthorized, and the precise reason is never sent to
// the client (it is logged for operators).
type DBAuthenticator struct {
	lookup  KeyLookup
	timeout time.Duration
	logger  *slog.Logger
}

var _ Authenticator = (*DBAuthenticator)(nil)

// NewDBAuthenticator constructs a DBAuthenticator.
func NewDBAuthenticator(lookup KeyLookup, logger *slog.Logger) *DBAuthenticator {
	if logger == nil {
		logger = slog.Default()
	}
	return &DBAuthenticator{lookup: lookup, timeout: 5 * time.Second, logger: logger}
}

// AuthenticatePublicKey resolves the offered key to an active identity.
func (a *DBAuthenticator) AuthenticatePublicKey(key ssh.PublicKey) (*Identity, error) {
	line := AuthorizedKeyLine(key)
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	id, err := a.lookup.AuthnByKey(ctx, line)
	if err != nil {
		// Fail closed on infrastructure errors rather than risking an
		// unauthenticated connection.
		a.logger.Error("authentication lookup failed", "err", err.Error())
		return nil, ErrUnauthorized
	}
	if id == nil {
		return nil, ErrUnauthorized
	}
	if !id.Active {
		a.logger.Info("rejected disabled account", "subject_type", string(id.Subject), "subject", id.Label)
		return nil, ErrUnauthorized
	}
	return &Identity{Subject: id.Subject, ID: id.ID, Label: id.Label}, nil
}
