package store

import (
	"context"
	"testing"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
)

func TestSSHLoginRequestLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	code, hash, err := auth.NewLoginCode()
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	id, err := st.CreateSSHLoginRequest(ctx, hash, "10.0.0.5", "alice+web01", time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Approval page can look it up by code and see the details.
	req, err := st.LookupSSHLoginByCode(ctx, auth.HashLoginCode(code))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if req.SourceIP != "10.0.0.5" || req.RequestedTarget != "alice+web01" || req.Status != "pending" {
		t.Fatalf("unexpected request: %+v", req)
	}

	// Pending → SSH side sees pending.
	if status, _, _ := st.PollSSHLogin(ctx, id); status != "pending" {
		t.Fatalf("expected pending, got %q", status)
	}

	// Approve binds the identity; SSH side then sees approved.
	if err := st.ApproveSSHLogin(ctx, auth.HashLoginCode(code), "alice@contoso.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	status, subject, _ := st.PollSSHLogin(ctx, id)
	if status != "approved" || subject != "alice@contoso.com" {
		t.Fatalf("expected approved/alice, got %q/%q", status, subject)
	}

	// A second approval attempt fails (no longer pending) — single decision.
	if err := st.ApproveSSHLogin(ctx, auth.HashLoginCode(code), "evil@x.com"); err != ErrNotFound {
		t.Fatalf("re-approve should be ErrNotFound, got %v", err)
	}
	// Lookup-by-code now fails too (not pending).
	if _, err := st.LookupSSHLoginByCode(ctx, auth.HashLoginCode(code)); err != ErrNotFound {
		t.Fatalf("lookup of decided request should be ErrNotFound, got %v", err)
	}

	// Consume once → subject; consume again → ErrNotFound (single use).
	sub, err := st.ConsumeSSHLogin(ctx, id)
	if err != nil || sub != "alice@contoso.com" {
		t.Fatalf("consume: sub=%q err=%v", sub, err)
	}
	if _, err := st.ConsumeSSHLogin(ctx, id); err != ErrNotFound {
		t.Fatalf("second consume should be ErrNotFound, got %v", err)
	}
	if status, _, _ := st.PollSSHLogin(ctx, id); status != "consumed" {
		t.Fatalf("expected consumed, got %q", status)
	}
}

func TestSSHLoginExpiryAndDeny(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Expired pending request: poll reports expired, approve fails.
	c1, h1, _ := auth.NewLoginCode()
	id1, err := st.CreateSSHLoginRequest(ctx, h1, "10.0.0.9", "bob+db01", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("create expired: %v", err)
	}
	if status, _, _ := st.PollSSHLogin(ctx, id1); status != "expired" {
		t.Fatalf("expected expired, got %q", status)
	}
	if err := st.ApproveSSHLogin(ctx, auth.HashLoginCode(c1), "bob@x.com"); err != ErrNotFound {
		t.Fatalf("approving expired should be ErrNotFound, got %v", err)
	}

	// Deny path.
	c2, h2, _ := auth.NewLoginCode()
	id2, _ := st.CreateSSHLoginRequest(ctx, h2, "10.0.0.10", "carol+web02", time.Now().Add(time.Minute))
	if err := st.DenySSHLogin(ctx, auth.HashLoginCode(c2), "carol@x.com"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if status, _, _ := st.PollSSHLogin(ctx, id2); status != "denied" {
		t.Fatalf("expected denied, got %q", status)
	}
	if _, err := st.ConsumeSSHLogin(ctx, id2); err != ErrNotFound {
		t.Fatalf("consuming denied should be ErrNotFound, got %v", err)
	}

	// Unknown id.
	if _, _, err := st.PollSSHLogin(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrNotFound {
		t.Fatalf("unknown id poll should be ErrNotFound, got %v", err)
	}
}
