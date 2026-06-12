package store

import (
	"context"
	"testing"
)

func TestSessionsToTerminate(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// alice (active) and bob (will be disabled), each with a live session.
	alice, err := st.CreateUser(ctx, "alice", nil, "local", "active")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := st.CreateUser(ctx, "bob", nil, "local", "active")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	aliceSess, err := st.CreateSession(ctx, SessionStart{
		SubjectType: "user", SubjectID: &alice, SubjectLabel: "alice", ServerLabel: "web01",
		LoginPrincipal: "ec2-user", AccessMode: "cert", SourceIP: "10.0.0.1", Recording: "metadata",
	})
	if err != nil {
		t.Fatalf("alice session: %v", err)
	}
	bobSess, err := st.CreateSession(ctx, SessionStart{
		SubjectType: "user", SubjectID: &bob, SubjectLabel: "bob", ServerLabel: "web01",
		LoginPrincipal: "ec2-user", AccessMode: "cert", SourceIP: "10.0.0.2", Recording: "metadata",
	})
	if err != nil {
		t.Fatalf("bob session: %v", err)
	}

	ids := []string{aliceSess, bobSess}

	// Nothing flagged, both active → none to terminate.
	if doomed, err := st.SessionsToTerminate(ctx, ids); err != nil || len(doomed) != 0 {
		t.Fatalf("expected none, got %v (err %v)", doomed, err)
	}

	// Explicitly flag alice's session.
	if err := st.RequestSessionTermination(ctx, aliceSess); err != nil {
		t.Fatalf("request termination: %v", err)
	}
	doomed, err := st.SessionsToTerminate(ctx, ids)
	if err != nil {
		t.Fatalf("to-terminate: %v", err)
	}
	if len(doomed) != 1 || doomed[0] != aliceSess {
		t.Fatalf("expected alice flagged, got %v", doomed)
	}

	// Disable bob → his live session also becomes terminable.
	if err := st.SetUserStatus(ctx, bob, "disabled"); err != nil {
		t.Fatalf("disable bob: %v", err)
	}
	doomed, err = st.SessionsToTerminate(ctx, ids)
	if err != nil {
		t.Fatalf("to-terminate 2: %v", err)
	}
	if len(doomed) != 2 {
		t.Fatalf("expected both terminable, got %v", doomed)
	}

	// Ending a session removes it from consideration even if flagged.
	if err := st.EndSession(ctx, aliceSess, 0, 0, nil); err != nil {
		t.Fatalf("end alice: %v", err)
	}
	doomed, err = st.SessionsToTerminate(ctx, ids)
	if err != nil {
		t.Fatalf("to-terminate 3: %v", err)
	}
	if len(doomed) != 1 || doomed[0] != bobSess {
		t.Fatalf("expected only bob after alice ended, got %v", doomed)
	}

	// Requesting termination of an already-ended session is ErrNotFound.
	if err := st.RequestSessionTermination(ctx, aliceSess); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for ended session, got %v", err)
	}
}
