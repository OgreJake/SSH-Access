// Package signer defines the SSH certificate-authority abstraction and its
// development backend.
//
// The CA signing key is the system's most sensitive secret. The Authority
// interface lets the rest of the broker mint certificates without knowing
// where the key lives. The dev backend (FileAuthority) loads a private key
// from disk; the production backend delegates signing to AWS KMS so the
// private key never leaves KMS (ADR-006). Both satisfy this same interface.
package signer

import (
	"context"

	"golang.org/x/crypto/ssh"
)

// Authority signs SSH user certificates on behalf of the broker.
type Authority interface {
	// PublicKey returns the CA public key, for distribution to targets'
	// sshd TrustedUserCAKeys.
	PublicKey() ssh.PublicKey

	// SignCertificate signs cert in place, populating its SignatureKey and
	// Signature. The caller is responsible for setting all other fields
	// (Key, Serial, KeyId, ValidPrincipals, ValidAfter/ValidBefore,
	// CriticalOptions, Extensions) before calling.
	SignCertificate(ctx context.Context, cert *ssh.Certificate) error
}
