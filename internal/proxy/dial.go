package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/ca"
)

// connectTarget mints a short-lived certificate for a per-session ephemeral
// key and uses it to authenticate to the target as the resolved login. The
// user's own key never touches the target leg — the broker is the client.
func (s *Server) connectTarget(ctx context.Context, id Identity, spec TargetSpec, d *Decision) (*ssh.Client, error) {
	// Ephemeral keypair, used only for this target connection.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, fmt.Errorf("ephemeral signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ephemeral public key: %w", err)
	}

	keyID := fmt.Sprintf("u=%s;host=%s;login=%s", id.Label, spec.Host, spec.Login)
	cert, err := s.issuer.Issue(ctx, ca.IssueParams{
		UserPublicKey: sshPub,
		Principals:    d.Principals,
		TTL:           d.TTL,
		SourceAddress: s.brokerSourceAddr,
		KeyID:         keyID,
		Permissions:   d.CertPermissions,
	})
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, ephSigner)
	if err != nil {
		return nil, fmt.Errorf("cert signer: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            spec.Login,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: hostKeyCallback(d.HostKeyFingerprint, s.logger),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", d.Address, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("dial target %s: %w", d.Address, err)
	}
	return client, nil
}

// hostKeyCallback enforces a pinned target host key when one is configured. An
// empty fingerprint accepts any key with a warning — a dev convenience only;
// the DB-backed path (Phase 3) requires a pinned key.
func hostKeyCallback(fingerprint string, logger *slog.Logger) ssh.HostKeyCallback {
	if fingerprint == "" {
		return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			logger.Warn("target host key not pinned; accepting (dev only)",
				"host", hostname, "fingerprint", ssh.FingerprintSHA256(key))
			return nil
		}
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if got != fingerprint {
			return fmt.Errorf("target host key mismatch: got %s, expected %s", got, fingerprint)
		}
		return nil
	}
}
