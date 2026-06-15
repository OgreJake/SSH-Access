package store

import (
	"context"
	"testing"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
)

func TestLocalAdminAndSessions(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hash, err := auth.HashPassword("break-glass-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id, err := st.UpsertLocalAdmin(ctx, "root", hash, "admin")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Upsert is idempotent by username (re-provision).
	id2, err := st.UpsertLocalAdmin(ctx, "root", hash, "admin")
	if err != nil || id2 != id {
		t.Fatalf("re-upsert should keep same id: %s vs %s (err %v)", id, id2, err)
	}

	admin, err := st.GetLocalAdminByUsername(ctx, "root")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ok, _ := auth.VerifyPassword(admin.PasswordHash, "break-glass-secret"); !ok {
		t.Fatal("stored hash should verify")
	}

	// Open a session and resolve it by token hash.
	token, tokenHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if _, err := st.CreateAdminSession(ctx, admin.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess, err := st.LookupAdminSession(ctx, auth.HashSessionToken(token), time.Hour)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if sess.Username != "root" || sess.Role != "admin" {
		t.Fatalf("unexpected session: %+v", sess)
	}

	// last_login_at recorded.
	admin, _ = st.GetLocalAdminByUsername(ctx, "root")
	if admin.LastLoginAt == nil {
		t.Fatal("last_login_at should be set after session creation")
	}

	// Revocation (logout) invalidates the session.
	if err := st.RevokeAdminSession(ctx, auth.HashSessionToken(token)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.LookupAdminSession(ctx, auth.HashSessionToken(token), time.Hour); err != ErrNotFound {
		t.Fatalf("revoked session should be ErrNotFound, got %v", err)
	}

	// Disabled admin → no valid session even with a fresh token.
	tok2, th2, _ := auth.NewSessionToken()
	if _, err := st.CreateAdminSession(ctx, admin.ID, th2, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session 2: %v", err)
	}
	if err := st.SetLocalAdminStatus(ctx, "root", "disabled"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := st.LookupAdminSession(ctx, auth.HashSessionToken(tok2), time.Hour); err != ErrNotFound {
		t.Fatalf("disabled admin session should be ErrNotFound, got %v", err)
	}

	// Expired session is rejected.
	st.SetLocalAdminStatus(ctx, "root", "active")
	tok3, th3, _ := auth.NewSessionToken()
	if _, err := st.CreateAdminSession(ctx, admin.ID, th3, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	if _, err := st.LookupAdminSession(ctx, auth.HashSessionToken(tok3), time.Hour); err != ErrNotFound {
		t.Fatalf("expired session should be ErrNotFound, got %v", err)
	}
}
