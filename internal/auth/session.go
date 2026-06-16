package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// SessionCookieName is the cookie that carries the break-glass session token.
const SessionCookieName = "sshbroker_admin_session"

// NewSessionToken returns a fresh opaque token (for the cookie) and its SHA-256
// hash (for storage). Only the hash is persisted, so a database read cannot
// recover live session tokens.
func NewSessionToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

// HashSessionToken returns the storage hash for a presented token.
func HashSessionToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// NewLoginCode returns a fresh opaque one-time SSH-login code (embedded in the
// approval URL) and its SHA-256 storage hash (ADR-021). Like session tokens,
// only the hash is persisted.
func NewLoginCode() (code string, hash []byte, err error) {
	return NewSessionToken()
}

// HashLoginCode returns the storage hash for a presented SSH-login code.
func HashLoginCode(code string) []byte {
	return HashSessionToken(code)
}
