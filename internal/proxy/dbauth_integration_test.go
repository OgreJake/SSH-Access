package proxy

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/yourorg/sshbroker/internal/model"
	"github.com/yourorg/sshbroker/internal/store"
)

// storeLookup adapts *store.Store to KeyLookup for this test (mirrors the
// adapter wired in cmd/broker).
type storeLookup struct{ st *store.Store }

func (l storeLookup) AuthnByKey(ctx context.Context, line string) (*ResolvedIdentity, error) {
	id, err := l.st.AuthnByKey(ctx, line)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ResolvedIdentity{
		Subject: model.SubjectType(id.SubjectType),
		ID:      id.ID,
		Label:   id.Label,
		Active:  id.Active,
	}, nil
}

// TestDBAuthenticatorAgainstStore exercises the full path: a real key is stored
// via AuthorizedKeyLine, then an offered ssh.PublicKey is resolved through the
// database and the DBAuthenticator, including the disabled-account path.
func TestDBAuthenticatorAgainstStore(t *testing.T) {
	dsn := os.Getenv("SSHBROKER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SSHBROKER_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx,
		"TRUNCATE users, user_public_keys, service_accounts RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	uid, err := st.CreateUser(ctx, "alice", nil, "local", "active")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, userPub := genUserKey(t)
	if _, err := st.AddUserKey(ctx, uid, AuthorizedKeyLine(userPub), "laptop"); err != nil {
		t.Fatalf("add key: %v", err)
	}

	auth := NewDBAuthenticator(storeLookup{st: st}, discardLogger())

	id, err := auth.AuthenticatePublicKey(userPub)
	if err != nil {
		t.Fatalf("expected authentication success, got %v", err)
	}
	if id.Subject != model.SubjectUser || id.Label != "alice" || id.ID != uid {
		t.Fatalf("unexpected identity: %+v", id)
	}

	// Disable the account; the same key must now be refused.
	if err := st.SetUserStatus(ctx, uid, "disabled"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := auth.AuthenticatePublicKey(userPub); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled account should be ErrUnauthorized, got %v", err)
	}
}
