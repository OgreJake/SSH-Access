package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/yourorg/sshbroker/internal/model"
)

type fakeLookup struct {
	byLine map[string]*ResolvedIdentity
	err    error
}

func (f fakeLookup) AuthnByKey(_ context.Context, line string) (*ResolvedIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byLine[line], nil // nil when absent → "not found"
}

func TestDBAuthenticatorActiveUser(t *testing.T) {
	_, userPub := genUserKey(t)
	line := AuthorizedKeyLine(userPub)
	auth := NewDBAuthenticator(fakeLookup{byLine: map[string]*ResolvedIdentity{
		line: {Subject: model.SubjectUser, ID: "uuid-1", Label: "alice", Active: true},
	}}, discardLogger())

	id, err := auth.AuthenticatePublicKey(userPub)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.Subject != model.SubjectUser || id.ID != "uuid-1" || id.Label != "alice" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestDBAuthenticatorDisabledRejected(t *testing.T) {
	_, userPub := genUserKey(t)
	line := AuthorizedKeyLine(userPub)
	auth := NewDBAuthenticator(fakeLookup{byLine: map[string]*ResolvedIdentity{
		line: {Subject: model.SubjectUser, ID: "uuid-1", Label: "alice", Active: false},
	}}, discardLogger())

	if _, err := auth.AuthenticatePublicKey(userPub); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled account should be ErrUnauthorized, got %v", err)
	}
}

func TestDBAuthenticatorUnknownKeyRejected(t *testing.T) {
	_, userPub := genUserKey(t)
	auth := NewDBAuthenticator(fakeLookup{byLine: map[string]*ResolvedIdentity{}}, discardLogger())
	if _, err := auth.AuthenticatePublicKey(userPub); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown key should be ErrUnauthorized, got %v", err)
	}
}

func TestDBAuthenticatorFailsClosedOnError(t *testing.T) {
	_, userPub := genUserKey(t)
	auth := NewDBAuthenticator(fakeLookup{err: errors.New("db down")}, discardLogger())
	if _, err := auth.AuthenticatePublicKey(userPub); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("lookup error should fail closed to ErrUnauthorized, got %v", err)
	}
}

func TestDBAuthenticatorServiceAccount(t *testing.T) {
	_, userPub := genUserKey(t)
	line := AuthorizedKeyLine(userPub)
	auth := NewDBAuthenticator(fakeLookup{byLine: map[string]*ResolvedIdentity{
		line: {Subject: model.SubjectServiceAccount, ID: "sa-1", Label: "ci-bot", Active: true},
	}}, discardLogger())

	id, err := auth.AuthenticatePublicKey(userPub)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.Subject != model.SubjectServiceAccount || id.Label != "ci-bot" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}
