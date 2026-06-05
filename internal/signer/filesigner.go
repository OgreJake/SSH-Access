package signer

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// FileAuthority is the development CA backend. It loads a private key from
// disk and signs in-process. Do NOT use in production — use the KMS backend,
// which keeps the private key inside KMS (ADR-006).
type FileAuthority struct {
	ca ssh.Signer
}

// compile-time interface check.
var _ Authority = (*FileAuthority)(nil)

// NewFileAuthority loads a CA private key from keyPath. If passphrase is
// non-empty the key is decrypted with it. Supported formats include OpenSSH
// and PEM (PKCS#8 / SEC1). For parity with the production KMS key, generate
// an ECDSA P-256 key (see `make gen-ca`).
func NewFileAuthority(keyPath, passphrase string) (*FileAuthority, error) {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %q: %w", keyPath, err)
	}

	var s ssh.Signer
	if passphrase != "" {
		s, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	} else {
		s, err = ssh.ParsePrivateKey(pem)
	}
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &FileAuthority{ca: s}, nil
}

// PublicKey returns the CA public key.
func (a *FileAuthority) PublicKey() ssh.PublicKey { return a.ca.PublicKey() }

// SignCertificate signs cert in place using the loaded CA key.
func (a *FileAuthority) SignCertificate(_ context.Context, cert *ssh.Certificate) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	if err := cert.SignCert(rand.Reader, a.ca); err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}
	return nil
}

// AuthorizedKey returns the CA public key as an authorized_keys / known CA
// line, suitable for a target's TrustedUserCAKeys file.
func (a *FileAuthority) AuthorizedKey() string {
	return string(ssh.MarshalAuthorizedKey(a.ca.PublicKey()))
}
