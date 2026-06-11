package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/yourorg/sshbroker/internal/model"
	"github.com/yourorg/sshbroker/internal/store"
)

// storeAuthz adapts *store.Store to AuthzBackend for this test (mirrors the
// adapter wired in cmd/broker).
type storeAuthz struct{ st *store.Store }

func (b storeAuthz) ServerByHostname(ctx context.Context, hostname string) (*ResolvedServer, error) {
	srv, err := b.st.GetServerByHostname(ctx, hostname)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ResolvedServer{ID: srv.ID, Address: srv.Address, Port: srv.Port,
		HostKeyFingerprint: srv.HostKeyFingerprint, AllowedPrincipals: srv.AllowedPrincipals}, nil
}
func (b storeAuthz) GroupsForUser(ctx context.Context, userID string) ([]string, error) {
	return b.st.ListGroupsForUser(ctx, userID)
}
func (b storeAuthz) GroupsForServer(ctx context.Context, serverID string) ([]string, error) {
	return b.st.ListGroupsForServer(ctx, serverID)
}
func (b storeAuthz) MatchingGrants(ctx context.Context, st, sid string, ug []string, srv string, sg []string) ([]ResolvedGrant, error) {
	gs, err := b.st.MatchingGrants(ctx, st, sid, ug, srv, sg)
	if err != nil {
		return nil, err
	}
	out := make([]ResolvedGrant, len(gs))
	for i, g := range gs {
		out[i] = ResolvedGrant{Principals: g.Principals, MaxTTL: g.MaxTTL,
			AllowShell: g.AllowShell, AllowExec: g.AllowExec, AllowSFTP: g.AllowSFTP, AllowPortForward: g.AllowPortForward}
	}
	return out, nil
}

func TestDBAuthorizerAgainstStore(t *testing.T) {
	dsn := os.Getenv("SSHBROKER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SSHBROKER_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	stx, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(stx.Close)
	if _, err := stx.Pool.Exec(ctx,
		`TRUNCATE grants, user_group_members, server_group_members,
		          user_groups, server_groups, servers, users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// alice ∈ deployers ; web01 ∈ web-tier ; two grants deployers→web-tier
	// both permitting "deploy": exec@2m and shell+sftp@10m.
	alice, _ := stx.CreateUser(ctx, "alice", nil, "local", "active")
	deployers, _ := stx.CreateUserGroup(ctx, "deployers")
	_ = stx.AddUserToGroup(ctx, deployers, alice)
	srvID, _ := stx.CreateServer(ctx, store.CreateServerInput{
		Hostname: "web01", Address: "10.0.0.5", Port: 22, HostKeyFingerprint: "SHA256:xyz",
		AllowedPrincipals: []string{"deploy", "ec2-user"},
	})
	webTier, _ := stx.CreateServerGroup(ctx, "web-tier")
	_ = stx.AddServerToGroup(ctx, webTier, srvID)
	if _, err := stx.CreateGrant(ctx, store.CreateGrantInput{
		SubjectType: "user_group", SubjectID: deployers, TargetType: "server_group", TargetID: webTier,
		Principals: []string{"deploy"}, MaxTTL: 2 * time.Minute, AllowExec: true,
	}); err != nil {
		t.Fatalf("grant1: %v", err)
	}
	if _, err := stx.CreateGrant(ctx, store.CreateGrantInput{
		SubjectType: "user_group", SubjectID: deployers, TargetType: "server_group", TargetID: webTier,
		Principals: []string{"deploy"}, MaxTTL: 10 * time.Minute, AllowShell: true, AllowSFTP: true,
	}); err != nil {
		t.Fatalf("grant2: %v", err)
	}

	a := NewDBAuthorizer(storeAuthz{st: stx}, discardLogger())
	id := Identity{Subject: model.SubjectUser, ID: alice, Label: "alice"}

	d, err := a.Authorize(ctx, id, TargetSpec{RequestedLogin: "deploy", Host: "web01"})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if d.Address != "10.0.0.5:22" || d.HostKeyFingerprint != "SHA256:xyz" {
		t.Fatalf("unexpected dial info: %+v", d)
	}
	if !d.AllowExec || !d.AllowShell || !d.AllowSFTP {
		t.Fatalf("expected union exec+shell+sftp, got %+v", d)
	}
	if d.TTL != 10*time.Minute {
		t.Fatalf("expected max TTL 10m, got %s", d.TTL)
	}

	// ADR-019: bare host and self-reference derive the single permitted account.
	for _, req := range []string{"", "me", "alice"} {
		dd, err := a.Authorize(ctx, id, TargetSpec{RequestedLogin: req, Host: "web01"})
		if err != nil {
			t.Fatalf("derive %q: %v", req, err)
		}
		if dd.Login != "deploy" || len(dd.Principals) != 1 || dd.Principals[0] != "deploy" {
			t.Fatalf("derive %q: expected resolved deploy, got %+v", req, dd)
		}
	}

	// A login no grant permits is denied.
	if _, err := a.Authorize(ctx, id, TargetSpec{RequestedLogin: "root", Host: "web01"}); !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected denial for root, got %v", err)
	}
	// Unknown host is denied.
	if _, err := a.Authorize(ctx, id, TargetSpec{RequestedLogin: "deploy", Host: "ghost"}); !errors.Is(err, ErrTargetUnauthorized) {
		t.Fatalf("expected denial for unknown host, got %v", err)
	}
}

// TestBrokeredDerivationEndToEnd proves ADR-019 through the whole broker: a
// user connects as "alice+web01" (self-reference), the broker derives the
// single permitted account (ec2-user), dials the real target as that account,
// and the session is attributed to alice.
func TestBrokeredDerivationEndToEnd(t *testing.T) {
	dsn := os.Getenv("SSHBROKER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SSHBROKER_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	stx, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(stx.Close)
	if _, err := stx.Pool.Exec(ctx,
		`TRUNCATE grants, user_group_members, server_group_members, user_groups,
		          server_groups, user_public_keys, service_accounts, servers, users
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)

	userSigner, userPub := genUserKey(t)
	uid, _ := stx.CreateUser(ctx, "alice", nil, "local", "active")
	if _, err := stx.AddUserKey(ctx, uid, AuthorizedKeyLine(userPub), "laptop"); err != nil {
		t.Fatalf("add key: %v", err)
	}
	sid, err := stx.CreateServer(ctx, store.CreateServerInput{
		Hostname: "web01", Address: host, Port: port, HostKeyFingerprint: targetFP,
		AllowedPrincipals: []string{"ec2-user"},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if _, err := stx.CreateGrant(ctx, store.CreateGrantInput{
		SubjectType: "user", SubjectID: uid, TargetType: "server", TargetID: sid,
		Principals: []string{"ec2-user"}, MaxTTL: 5 * time.Minute, AllowShell: true, AllowExec: true,
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	authn := NewDBAuthenticator(storeLookup{st: stx}, discardLogger())
	authz := NewDBAuthorizer(storeAuthz{st: stx}, discardLogger())
	rec := &recordingAuditor{}
	srv, brokerAddr := startBrokerWithAuditor(t, authn, authz, iss, rec)

	// Connect addressing ourselves; the broker derives ec2-user.
	client := dialBroker(t, srv, brokerAddr, "alice+web01", userSigner)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sess.Output("whoami"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	_ = sess.Close()

	if s, _ := rec.counts(); s != 1 {
		t.Fatalf("expected 1 StartSession, got %d", s)
	}
	got := rec.started[0]
	if got.SubjectLabel != "alice" {
		t.Fatalf("session should be attributed to alice, got %q", got.SubjectLabel)
	}
	if got.Login != "ec2-user" {
		t.Fatalf("expected derived account ec2-user, got %q", got.Login)
	}
	_ = client.Close()
}
