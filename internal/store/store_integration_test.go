package store

import (
	"context"
	"os"
	"testing"
)

// integration tests run only when SSHBROKER_TEST_DATABASE_URL points at a
// Postgres database with the migrations applied.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SSHBROKER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SSHBROKER_TEST_DATABASE_URL to run store integration tests")
	}
	st, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)
	// Clean slate (TRUNCATE does not fire the append-only row trigger).
	_, err = st.Pool.Exec(context.Background(),
		`TRUNCATE audit_log, sessions, grants,
		          user_group_members, server_group_members,
		          user_groups, server_groups,
		          user_public_keys, service_accounts, servers, users
		 RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return st
}

func TestAuditChainAppendAndVerify(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := st.AppendAudit(ctx, AuditEvent{
			Actor: "alice", EventType: "session.start", Target: "web01",
			Detail: map[string]string{"login": "deploy", "n": string(rune('0' + i))},
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	n, err := st.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d records, want 5", n)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.AppendAudit(ctx, AuditEvent{Actor: "a", EventType: "e", Target: "t"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	// The DB trigger must block UPDATE and DELETE.
	if _, err := st.Pool.Exec(ctx, "UPDATE audit_log SET actor='x'"); err == nil {
		t.Fatal("UPDATE on audit_log should be rejected by the trigger")
	}
	if _, err := st.Pool.Exec(ctx, "DELETE FROM audit_log"); err == nil {
		t.Fatal("DELETE on audit_log should be rejected by the trigger")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(ctx, AuditEvent{Actor: "a", EventType: "e", Target: "t",
			Detail: map[string]string{"i": string(rune('0' + i))}}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if _, err := st.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}

	// Tamper: disable the append-only trigger (requires table owner) and
	// rewrite a record's detail. Verification must then fail.
	if _, err := st.Pool.Exec(ctx, "ALTER TABLE audit_log DISABLE TRIGGER USER"); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	defer st.Pool.Exec(ctx, "ALTER TABLE audit_log ENABLE TRIGGER USER")

	if _, err := st.Pool.Exec(ctx,
		`UPDATE audit_log SET detail = '{"i":"tampered"}'::jsonb WHERE seq = (SELECT min(seq) FROM audit_log)`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := st.VerifyAuditChain(ctx); err == nil {
		t.Fatal("verification should detect the tampered record")
	}
}

func TestSessionLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	serial := int64(42)
	id, err := st.CreateSession(ctx, SessionStart{
		SubjectType:    "user",
		SubjectLabel:   "alice",
		ServerLabel:    "web01",
		LoginPrincipal: "deploy",
		AccessMode:     "cert",
		SourceIP:       "10.0.0.9",
		CertSerial:     &serial,
		Recording:      "metadata",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if id == "" {
		t.Fatal("expected a session id")
	}

	exit := 0
	if err := st.EndSession(ctx, id, 1234, 5678, &exit); err != nil {
		t.Fatalf("end session: %v", err)
	}

	var (
		bytesIn, bytesOut int64
		ended             bool
	)
	err = st.Pool.QueryRow(ctx,
		"SELECT bytes_in, bytes_out, ended_at IS NOT NULL FROM sessions WHERE id=$1", id).
		Scan(&bytesIn, &bytesOut, &ended)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if bytesIn != 1234 || bytesOut != 5678 || !ended {
		t.Fatalf("session not finalized correctly: in=%d out=%d ended=%v", bytesIn, bytesOut, ended)
	}
}
