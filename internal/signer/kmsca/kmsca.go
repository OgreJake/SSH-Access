// Package kmsca implements signer.Authority backed by an AWS KMS asymmetric
// key (ADR-006). The CA private key is generated inside KMS and never leaves
// it: to sign a certificate the broker sends KMS the certificate's digest and
// KMS returns the signature. On EC2 the broker authenticates to KMS with its
// IAM instance role (no static credentials), and every signing call is logged
// to CloudTrail — useful SOC 2 evidence.
//
// The integration is small because of one fact: golang.org/x/crypto/ssh asks a
// crypto.Signer for an ASN.1-DER ECDSA signature over a SHA-256 digest and
// re-encodes it into SSH wire format itself. KMS's ECDSA_SHA_256 signing
// returns exactly that DER form, so a thin crypto.Signer over KMS, wrapped by
// ssh.NewSignerFromSigner, satisfies the same Authority interface as the dev
// file backend with no signature surgery.
package kmsca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/signer"
)

// kmsClient is the subset of the KMS API this package uses. *kms.Client
// satisfies it; tests inject a fake.
type kmsClient interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// Authority signs SSH certificates using a KMS asymmetric key.
type Authority struct {
	client      kmsClient
	keyID       string
	pub         *ecdsa.PublicKey
	sshPub      ssh.PublicKey
	signTimeout time.Duration
}

var _ signer.Authority = (*Authority)(nil)

type options struct {
	region      string
	signTimeout time.Duration
	client      kmsClient // test injection
}

// Option configures the Authority.
type Option func(*options)

// WithRegion sets the AWS region explicitly. If unset, the region is taken
// from the environment / instance metadata as usual.
func WithRegion(r string) Option { return func(o *options) { o.region = r } }

// WithSignTimeout bounds each KMS Sign call (default 5s).
func WithSignTimeout(d time.Duration) Option { return func(o *options) { o.signTimeout = d } }

// withClient injects a KMS client (testing only).
func withClient(c kmsClient) Option { return func(o *options) { o.client = c } }

// New constructs an Authority for the given KMS key ID (key id, ARN, or alias).
// It fetches and validates the public key up front, which also fail-fast
// verifies that the broker's credentials can reach the key.
func New(ctx context.Context, keyID string, opts ...Option) (*Authority, error) {
	if keyID == "" {
		return nil, fmt.Errorf("kms key id is required")
	}
	o := options{signTimeout: 5 * time.Second}
	for _, f := range opts {
		f(&o)
	}

	client := o.client
	if client == nil {
		var loadOpts []func(*config.LoadOptions) error
		if o.region != "" {
			loadOpts = append(loadOpts, config.WithRegion(o.region))
		}
		cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		client = kms.NewFromConfig(cfg)
	}

	a := &Authority{client: client, keyID: keyID, signTimeout: o.signTimeout}
	if err := a.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Authority) loadPublicKey(ctx context.Context) error {
	out, err := a.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &a.keyID})
	if err != nil {
		return fmt.Errorf("kms get public key: %w", err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return fmt.Errorf("kms key usage is %q, want SIGN_VERIFY", out.KeyUsage)
	}
	if out.KeySpec != types.KeySpecEccNistP256 {
		return fmt.Errorf("kms key spec is %q, want ECC_NIST_P256", out.KeySpec)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return fmt.Errorf("parse kms public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("kms public key is %T, want *ecdsa.PublicKey", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("kms key is not on the P-256 curve")
	}
	sshPub, err := ssh.NewPublicKey(ecPub)
	if err != nil {
		return fmt.Errorf("convert to ssh public key: %w", err)
	}
	a.pub = ecPub
	a.sshPub = sshPub
	return nil
}

// PublicKey returns the CA public key (for targets' TrustedUserCAKeys).
func (a *Authority) PublicKey() ssh.PublicKey { return a.sshPub }

// SignCertificate signs cert in place via KMS.
func (a *Authority) SignCertificate(ctx context.Context, cert *ssh.Certificate) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	cs := &cryptoSigner{
		client:  a.client,
		keyID:   a.keyID,
		pub:     a.pub,
		ctx:     ctx,
		timeout: a.signTimeout,
	}
	s, err := ssh.NewSignerFromSigner(cs)
	if err != nil {
		return fmt.Errorf("wrap kms signer: %w", err)
	}
	if err := cert.SignCert(rand.Reader, s); err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}
	return nil
}

// cryptoSigner adapts a single KMS Sign call to crypto.Signer. A fresh one is
// built per certificate so each carries its own request context — no shared
// mutable state, fully concurrent.
type cryptoSigner struct {
	client  kmsClient
	keyID   string
	pub     *ecdsa.PublicKey
	ctx     context.Context
	timeout time.Duration
}

func (s *cryptoSigner) Public() crypto.PublicKey { return s.pub }

func (s *cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unexpected hash %v, want SHA-256 (P-256 key)", opts.HashFunc())
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	// out.Signature is an ASN.1-DER ECDSA signature; ssh re-encodes it.
	return out.Signature, nil
}
