package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yourorg/sshbroker/internal/model"
)

type fakeAuthzBackend struct {
	server       *ResolvedServer
	serverErr    error
	userGroups   []string
	serverGroups []string
	grants       []ResolvedGrant
	grantsErr    error
	lastSubject  string // captures subjectType passed to MatchingGrants
}

func (f *fakeAuthzBackend) ServerByHostname(_ context.Context, _ string) (*ResolvedServer, error) {
	return f.server, f.serverErr
}
func (f *fakeAuthzBackend) GroupsForUser(_ context.Context, _ string) ([]string, error) {
	return f.userGroups, nil
}
func (f *fakeAuthzBackend) GroupsForServer(_ context.Context, _ string) ([]string, error) {
	return f.serverGroups, nil
}
func (f *fakeAuthzBackend) MatchingGrants(_ context.Context, subjectType, _ string, _ []string, _ string, _ []string) ([]ResolvedGrant, error) {
	f.lastSubject = subjectType
	return f.grants, f.grantsErr
}

func userIdentity() Identity {
	return Identity{Subject: model.SubjectUser, ID: "u1", Label: "alice"}
}

func TestDBAuthorizerComposesUnionAndMaxTTL(t *testing.T) {
	be := &fakeAuthzBackend{
		server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22},
		grants: []ResolvedGrant{
			{Principals: []string{"deploy"}, MaxTTL: 2 * time.Minute, AllowExec: true},
			{Principals: []string{"deploy"}, MaxTTL: 10 * time.Minute, AllowShell: true, AllowSFTP: true},
			{Principals: []string{"other"}, MaxTTL: time.Hour, AllowPortForward: true}, // not for "deploy"
		},
	}
	a := NewDBAuthorizer(be, discardLogger())
	d, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "deploy", Host: "web01"})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if d.Address != "10.0.0.5:22" {
		t.Fatalf("address: %s", d.Address)
	}
	if len(d.Principals) != 1 || d.Principals[0] != "deploy" {
		t.Fatalf("principals: %v", d.Principals)
	}
	// Union across the two grants that permit "deploy": exec + shell + sftp,
	// but NOT port-forward (that grant was for a different login).
	if !d.AllowExec || !d.AllowShell || !d.AllowSFTP {
		t.Fatalf("expected exec+shell+sftp union, got %+v", d)
	}
	if d.CertPermissions.PortForwarding {
		t.Fatal("port-forward should not be granted (only an unrelated login had it)")
	}
	if !d.CertPermissions.PTY {
		t.Fatal("PTY should follow AllowShell")
	}
	// Longest permitted TTL among matching grants.
	if d.TTL != 10*time.Minute {
		t.Fatalf("expected max TTL 10m, got %s", d.TTL)
	}
}

func TestDBAuthorizerUnknownHost(t *testing.T) {
	be := &fakeAuthzBackend{server: nil} // not found
	a := NewDBAuthorizer(be, discardLogger())
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "deploy", Host: "ghost"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected ErrTargetUnauthorized, got %v", err)
	}
}

func TestDBAuthorizerNoGrant(t *testing.T) {
	be := &fakeAuthzBackend{server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22}}
	a := NewDBAuthorizer(be, discardLogger())
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "deploy", Host: "web01"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected ErrTargetUnauthorized, got %v", err)
	}
}

func TestDBAuthorizerLoginNotPermitted(t *testing.T) {
	be := &fakeAuthzBackend{
		server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22},
		grants: []ResolvedGrant{{Principals: []string{"deploy"}, MaxTTL: time.Minute, AllowExec: true}},
	}
	a := NewDBAuthorizer(be, discardLogger())
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "root", Host: "web01"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected ErrTargetUnauthorized for disallowed login, got %v", err)
	}
}

func TestDBAuthorizerServerAllowlist(t *testing.T) {
	be := &fakeAuthzBackend{
		server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22, AllowedPrincipals: []string{"ec2-user"}},
		grants: []ResolvedGrant{{Principals: []string{"deploy"}, MaxTTL: time.Minute, AllowExec: true}},
	}
	a := NewDBAuthorizer(be, discardLogger())
	// "deploy" is granted but not in the server allowlist → denied.
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "deploy", Host: "web01"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("server allowlist should deny, got %v", err)
	}
}

func TestDBAuthorizerFailsClosed(t *testing.T) {
	be := &fakeAuthzBackend{
		server:    &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22},
		grantsErr: errors.New("db down"),
	}
	a := NewDBAuthorizer(be, discardLogger())
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{Login: "deploy", Host: "web01"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("backend error should fail closed, got %v", err)
	}
}

func TestDBAuthorizerServiceAccountSubjectType(t *testing.T) {
	be := &fakeAuthzBackend{
		server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22},
		grants: []ResolvedGrant{{Principals: []string{"deploy"}, MaxTTL: time.Minute, AllowExec: true}},
	}
	a := NewDBAuthorizer(be, discardLogger())
	sa := Identity{Subject: model.SubjectServiceAccount, ID: "sa1", Label: "ci-bot"}
	if _, err := a.Authorize(context.Background(), sa, TargetSpec{Login: "deploy", Host: "web01"}); err != nil {
		t.Fatalf("authorize SA: %v", err)
	}
	if be.lastSubject != "service_account" {
		t.Fatalf("expected subject type service_account passed to MatchingGrants, got %q", be.lastSubject)
	}
}
