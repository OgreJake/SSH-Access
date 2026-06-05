package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileStore is the development secret backend. Each secret is encrypted with
// AES-256-GCM under a single master key and written to its own file. The file
// name is the base64url encoding of the ref, which keeps it filesystem-safe
// and reversible (so List can recover refs). Dev only — production uses KMS
// envelope encryption (ADR-009).
type FileStore struct {
	dir  string
	aead cipher.AEAD
}

// compile-time interface check.
var _ Store = (*FileStore)(nil)

// NewFileStore creates a FileStore rooted at dir, encrypting with a 32-byte
// (AES-256) master key. The directory is created if missing.
func NewFileStore(dir string, masterKey []byte) (*FileStore, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create secret dir: %w", err)
	}
	return &FileStore{dir: dir, aead: aead}, nil
}

func (s *FileStore) path(ref string) string {
	name := base64.RawURLEncoding.EncodeToString([]byte(ref))
	return filepath.Join(s.dir, name)
}

// Put encrypts and writes the secret for ref.
func (s *FileStore) Put(_ context.Context, ref string, secret []byte) error {
	if ref == "" {
		return fmt.Errorf("empty ref")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}
	// Bind the ciphertext to the ref via additional authenticated data so a
	// secret cannot be silently moved between refs.
	sealed := s.aead.Seal(nonce, nonce, secret, []byte(ref))
	if err := os.WriteFile(s.path(ref), sealed, 0o600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

// Get reads and decrypts the secret for ref.
func (s *FileStore) Get(_ context.Context, ref string) ([]byte, error) {
	data, err := os.ReadFile(s.path(ref))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	ns := s.aead.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:ns], data[ns:]
	plain, err := s.aead.Open(nil, nonce, ct, []byte(ref))
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return plain, nil
}

// Delete removes the secret for ref; a missing ref is not an error.
func (s *FileStore) Delete(_ context.Context, ref string) error {
	err := os.Remove(s.path(ref))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// List returns all refs with the given prefix, sorted.
func (s *FileStore) List(_ context.Context, prefix string) ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	var refs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(e.Name())
		if err != nil {
			continue // not one of ours
		}
		ref := string(raw)
		if strings.HasPrefix(ref, prefix) {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs, nil
}
