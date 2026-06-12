package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func strptr(s string) *string { return &s }

func TestUserKeyAuthn(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	uid, err := st.CreateUser(ctx, "alice", strptr("alice@example.com"), "local", "active")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	const key1 = "ssh-ed25519 AAAAaliceKEY1"
	const key2 = "ssh-ed25519 AAAAaliceKEY2"
	if _, err := st.AddUserKey(ctx, uid, key1, "laptop"); err != nil {
		t.Fatalf("add key1: %v", err)
	}
	if _, err := st.AddUserKey(ctx, uid, key2, "desktop"); err != nil {
		t.Fatalf("add key2: %v", err)
	}

	// Both of a user's keys resolve to the same active identity.
	for _, k := range []string{key1, key2} {
		id, err := st.AuthnByKey(ctx, k)
		if err != nil {
			t.Fatalf("authn %q: %v", k, err)
		}
		if id.SubjectType != "user" || id.Label != "alice" || !id.Active {
			t.Fatalf("unexpected identity for %q: %+v", k, id)
		}
		if id.ID != uid {
			t.Fatalf("expected id %s, got %s", uid, id.ID)
		}
	}

	// Disabling the user flips Active to false (auth layer will refuse).
	if err := st.SetUserStatus(ctx, uid, "disabled"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	id, err := st.AuthnByKey(ctx, key1)
	if err != nil {
		t.Fatalf("authn after disable: %v", err)
	}
	if id.Active {
		t.Fatal("disabled user should report Active=false")
	}

	// Service-account key resolves to a service_account subject.
	if _, err := st.CreateServiceAccount(ctx, "ci-bot", "ssh-ed25519 AAAAbotKEY", "active"); err != nil {
		t.Fatalf("create SA: %v", err)
	}
	said, err := st.AuthnByKey(ctx, "ssh-ed25519 AAAAbotKEY")
	if err != nil {
		t.Fatalf("authn SA: %v", err)
	}
	if said.SubjectType != "service_account" || said.Label != "ci-bot" || !said.Active {
		t.Fatalf("unexpected SA identity: %+v", said)
	}

	// Unknown key → ErrNotFound.
	if _, err := st.AuthnByKey(ctx, "ssh-ed25519 AAAAnope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown key, got %v", err)
	}
}

func TestRBACResolution(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// alice ∈ deployers ; mttest-00 ∈ web-tier ; grant: deployers → web-tier.
	alice, _ := st.CreateUser(ctx, "alice", nil, "local", "active")
	bob, _ := st.CreateUser(ctx, "bob", nil, "local", "active")
	deployers, _ := st.CreateUserGroup(ctx, "deployers")
	if err := st.AddUserToGroup(ctx, deployers, alice); err != nil {
		t.Fatalf("add member: %v", err)
	}

	srvID, err := st.CreateServer(ctx, CreateServerInput{
		Hostname:           "mttest-00",
		Address:            "172.16.65.207",
		Port:               22,
		HostKeyFingerprint: "SHA256:abc",
		AllowedPrincipals:  []string{"ec2-user", "deploy"},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	webTier, _ := st.CreateServerGroup(ctx, "web-tier")
	if err := st.AddServerToGroup(ctx, webTier, srvID); err != nil {
		t.Fatalf("add server to group: %v", err)
	}

	if _, err := st.CreateGrant(ctx, CreateGrantInput{
		SubjectType: "user_group", SubjectID: deployers,
		TargetType: "server_group", TargetID: webTier,
		Principals: []string{"ec2-user"}, MaxTTL: 5 * time.Minute,
		AllowShell: true, AllowExec: true, Recording: "metadata",
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	// Resolve the way the authorizer will: alice's groups, the server by alias,
	// the server's groups, then matching grants.
	server, err := st.GetServerByHostname(ctx, "mttest-00")
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	if server.Address != "172.16.65.207" || server.Port != 22 {
		t.Fatalf("unexpected server: %+v", server)
	}

	aliceGroups, _ := st.ListGroupsForUser(ctx, alice)
	serverGroups, _ := st.ListGroupsForServer(ctx, server.ID)

	grants, err := st.MatchingGrants(ctx, "user", alice, aliceGroups, server.ID, serverGroups)
	if err != nil {
		t.Fatalf("matching grants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("alice should match 1 grant via group→group, got %d", len(grants))
	}
	g := grants[0]
	if len(g.Principals) != 1 || g.Principals[0] != "ec2-user" {
		t.Fatalf("unexpected principals: %v", g.Principals)
	}
	if g.MaxTTL != 5*time.Minute {
		t.Fatalf("expected 5m TTL, got %s", g.MaxTTL)
	}
	if !g.AllowShell || !g.AllowExec || g.AllowSFTP {
		t.Fatalf("unexpected capabilities: %+v", g)
	}

	// bob is in no group → no matching grants.
	bobGroups, _ := st.ListGroupsForUser(ctx, bob)
	bobGrants, err := st.MatchingGrants(ctx, "user", bob, bobGroups, server.ID, serverGroups)
	if err != nil {
		t.Fatalf("matching grants (bob): %v", err)
	}
	if len(bobGrants) != 0 {
		t.Fatalf("bob should match no grants, got %d", len(bobGrants))
	}

	// A direct user→server grant also resolves (no groups needed).
	if _, err := st.CreateGrant(ctx, CreateGrantInput{
		SubjectType: "user", SubjectID: bob,
		TargetType: "server", TargetID: server.ID,
		Principals: []string{"ec2-user"}, MaxTTL: time.Minute, AllowExec: true,
	}); err != nil {
		t.Fatalf("create direct grant: %v", err)
	}
	bobGrants, _ = st.MatchingGrants(ctx, "user", bob, bobGroups, server.ID, serverGroups)
	if len(bobGrants) != 1 {
		t.Fatalf("bob should now match 1 direct grant, got %d", len(bobGrants))
	}
}
