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
	d, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "web01"})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if d.Address != "10.0.0.5:22" {
		t.Fatalf("address: %s", d.Address)
	}
	if len(d.Principals) != 1 || d.Principals[0] != "deploy" {
		t.Fatalf("principals: %v", d.Principals)
	}
	if d.Login != "deploy" {
		t.Fatalf("expected resolved Login deploy, got %q", d.Login)
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
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "ghost"})
	if !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected ErrTargetUnauthorized, got %v", err)
	}
}

func TestDBAuthorizerNoGrant(t *testing.T) {
	be := &fakeAuthzBackend{server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22}}
	a := NewDBAuthorizer(be, discardLogger())
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "web01"})
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
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "root", Host: "web01"})
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
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "web01"})
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
	_, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "web01"})
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
	if _, err := a.Authorize(context.Background(), sa, TargetSpec{RequestedLogin: "deploy", Host: "web01"}); err != nil {
		t.Fatalf("authorize SA: %v", err)
	}
	if be.lastSubject != "service_account" {
		t.Fatalf("expected subject type service_account passed to MatchingGrants, got %q", be.lastSubject)
	}
}

func TestParseTargetForms(t *testing.T) {
	cases := []struct {
		in      string
		login   string
		host    string
		wantErr bool
	}{
		{"ec2-user+web01", "ec2-user", "web01", false},
		{"alice+web01", "alice", "web01", false},
		{"web01", "", "web01", false},  // bare host → derive
		{"+web01", "", "web01", false}, // explicit derive
		{"ec2-user+", "", "", true},    // missing host
		{"", "", "", true},
	}
	for _, c := range cases {
		spec, err := ParseTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if spec.RequestedLogin != c.login || spec.Host != c.host {
			t.Errorf("%q: got {%q,%q}, want {%q,%q}", c.in, spec.RequestedLogin, spec.Host, c.login, c.host)
		}
	}
}

// derivBackend: one grant permitting the given principals, optional server allowlist.
func derivBackend(principals, allowlist []string) *fakeAuthzBackend {
	return &fakeAuthzBackend{
		server: &ResolvedServer{ID: "s1", Address: "10.0.0.5", Port: 22, AllowedPrincipals: allowlist},
		grants: []ResolvedGrant{{Principals: principals, MaxTTL: time.Minute, AllowExec: true, AllowShell: true}},
	}
}

func TestDBAuthorizerDerivesSinglePrincipal(t *testing.T) {
	a := NewDBAuthorizer(derivBackend([]string{"ec2-user"}, []string{"ec2-user"}), discardLogger())
	// All three "derive" forms resolve to the single permitted account.
	for _, req := range []string{"", "me", "alice"} {
		d, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: req, Host: "web01"})
		if err != nil {
			t.Fatalf("req %q: %v", req, err)
		}
		if d.Login != "ec2-user" || len(d.Principals) != 1 || d.Principals[0] != "ec2-user" {
			t.Fatalf("req %q: expected resolved ec2-user, got %+v", req, d)
		}
	}
}

func TestDBAuthorizerExplicitStillWorks(t *testing.T) {
	a := NewDBAuthorizer(derivBackend([]string{"ec2-user"}, []string{"ec2-user"}), discardLogger())
	d, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "ec2-user", Host: "web01"})
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if d.Login != "ec2-user" {
		t.Fatalf("explicit: got %q", d.Login)
	}
}

func TestDBAuthorizerAmbiguousDerivationRejected(t *testing.T) {
	a := NewDBAuthorizer(derivBackend([]string{"ec2-user", "deploy"}, nil), discardLogger())
	// Bare/self forms are ambiguous with two usable accounts → reject.
	for _, req := range []string{"", "me", "alice"} {
		if _, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: req, Host: "web01"}); !errors.Is(err, ErrTargetUnauthorized) {
			t.Fatalf("req %q: expected ambiguity rejection, got %v", req, err)
		}
	}
	// But explicitly naming one of them works.
	d, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "deploy", Host: "web01"})
	if err != nil || d.Login != "deploy" {
		t.Fatalf("explicit deploy: d=%+v err=%v", d, err)
	}
}

func TestDBAuthorizerDeriveNoUsableAccount(t *testing.T) {
	// Grant permits deploy, but the server only allows ec2-user → no usable account.
	a := NewDBAuthorizer(derivBackend([]string{"deploy"}, []string{"ec2-user"}), discardLogger())
	if _, err := a.Authorize(context.Background(), userIdentity(), TargetSpec{RequestedLogin: "", Host: "web01"}); !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected denial when no usable account, got %v", err)
	}
}
