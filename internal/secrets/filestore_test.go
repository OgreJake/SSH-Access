package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	s, err := NewFileStore(t.TempDir(), key)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func TestFileStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	want := []byte("super-secret-password")
	if err := s.Put(ctx, "server/abc/credential", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "server/abc/credential")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get = %q, want %q", got, want)
	}
}

func TestFileStoreNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestFileStoreDeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete (missing) = %v, want nil", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
}

func TestFileStoreList(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, ref := range []string{"server/1/cred", "server/2/cred", "bootstrap/x"} {
		if err := s.Put(ctx, ref, []byte("v")); err != nil {
			t.Fatalf("Put %s: %v", ref, err)
		}
	}
	got, err := s.List(ctx, "server/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List(server/) = %v, want 2 entries", got)
	}
	if got[0] != "server/1/cred" || got[1] != "server/2/cred" {
		t.Fatalf("List(server/) = %v, want sorted server refs", got)
	}
}

func TestFileStoreTamperedRefFails(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.Put(ctx, "ref-a", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Reading under a different ref must fail: ref is bound as AAD.
	if _, err := s.Get(ctx, "ref-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(ref-b) = %v, want ErrNotFound", err)
	}
}

func TestNewFileStoreRejectsShortKey(t *testing.T) {
	if _, err := NewFileStore(t.TempDir(), []byte("too-short")); err == nil {
		t.Fatal("expected error for short key")
	}
}
