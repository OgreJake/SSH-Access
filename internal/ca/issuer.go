// Package ca mints short-lived, tightly-constrained SSH user certificates.
//
// The issuer is the policy layer on top of signer.Authority: the Authority
// holds the key and performs the raw signature (dev file key, or AWS KMS in
// production); the Issuer decides what a certificate is allowed to contain —
// lifetime, principals, source-address pin, capabilities, and the audit key
// ID (ADR-007). Keeping policy here means the same constraints apply no matter
// which signing backend is in use.
package ca

import (
	"context"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/signer"
)

// SSH user-certificate extension names (presence grants the capability).
const (
	extPTY             = "permit-pty"
	extPortForwarding  = "permit-port-forwarding"
	extAgentForwarding = "permit-agent-forwarding"
	extX11Forwarding   = "permit-X11-forwarding"

	optSourceAddress = "source-address"
)

// Permissions are the capability flags for a certificate, derived from the
// grant. Anything not enabled is omitted, so the certificate is least-
// privilege by default: with no flags set the holder can still run commands
// and use SFTP, but cannot open an interactive PTY or forward anything.
type Permissions struct {
	PTY             bool
	PortForwarding  bool
	AgentForwarding bool
	X11Forwarding   bool
}

// IssueParams describes one certificate request.
type IssueParams struct {
	// UserPublicKey is the key the certificate is bound to (required).
	UserPublicKey ssh.PublicKey
	// Principals are the target logins this certificate authorizes. Must be
	// non-empty — an empty list would make the certificate valid for ANY
	// user, so the issuer rejects it.
	Principals []string
	// TTL is the requested lifetime; it is clamped to the issuer's max TTL.
	// A non-positive value means "use the max".
	TTL time.Duration
	// SourceAddress, if non-empty, pins the certificate to a source address
	// or comma-separated CIDR list. In production this is the broker's egress
	// address so a leaked certificate is unusable away from the broker.
	SourceAddress string
	// KeyID is recorded in the certificate and surfaces in the target's sshd
	// logs; encode requester/grant/request here for audit correlation
	// (required).
	KeyID string
	// Permissions are the capability flags for this certificate.
	Permissions Permissions
}

// Issuer mints constrained SSH user certificates.
type Issuer struct {
	authority signer.Authority
	serials   SerialAllocator

	maxTTL    time.Duration
	clockSkew time.Duration
	now       func() time.Time
}

// Option configures an Issuer.
type Option func(*Issuer)

// WithClock overrides the time source (used in tests).
func WithClock(now func() time.Time) Option { return func(i *Issuer) { i.now = now } }

// WithClockSkew sets the tolerance subtracted from ValidAfter to absorb minor
// clock differences between the broker and targets.
func WithClockSkew(d time.Duration) Option { return func(i *Issuer) { i.clockSkew = d } }

// NewIssuer creates an Issuer. maxTTL is the hard cap on every certificate's
// lifetime.
func NewIssuer(authority signer.Authority, serials SerialAllocator, maxTTL time.Duration, opts ...Option) (*Issuer, error) {
	if authority == nil {
		return nil, fmt.Errorf("nil authority")
	}
	if serials == nil {
		return nil, fmt.Errorf("nil serial allocator")
	}
	if maxTTL <= 0 {
		return nil, fmt.Errorf("maxTTL must be positive")
	}
	i := &Issuer{
		authority: authority,
		serials:   serials,
		maxTTL:    maxTTL,
		clockSkew: time.Minute,
		now:       time.Now,
	}
	for _, o := range opts {
		o(i)
	}
	if i.clockSkew < 0 {
		return nil, fmt.Errorf("clock skew must not be negative")
	}
	return i, nil
}

// CAPublicKey returns the authority's public key, for distribution to targets'
// TrustedUserCAKeys.
func (i *Issuer) CAPublicKey() ssh.PublicKey { return i.authority.PublicKey() }

// Issue validates params, builds a least-privilege certificate, and signs it.
func (i *Issuer) Issue(ctx context.Context, p IssueParams) (*ssh.Certificate, error) {
	if p.UserPublicKey == nil {
		return nil, fmt.Errorf("nil user public key")
	}
	principals := dedupeNonEmpty(p.Principals)
	if len(principals) == 0 {
		return nil, fmt.Errorf("at least one principal is required")
	}
	if p.KeyID == "" {
		return nil, fmt.Errorf("KeyID is required for audit")
	}

	ttl := p.TTL
	if ttl <= 0 || ttl > i.maxTTL {
		ttl = i.maxTTL
	}

	serial, err := i.serials.Next(ctx)
	if err != nil {
		return nil, fmt.Errorf("allocate serial: %w", err)
	}

	now := i.now()
	validAfter := now.Add(-i.clockSkew)
	validBefore := now.Add(ttl)

	criticalOptions := map[string]string{}
	if p.SourceAddress != "" {
		criticalOptions[optSourceAddress] = p.SourceAddress
	}

	extensions := map[string]string{}
	if p.Permissions.PTY {
		extensions[extPTY] = ""
	}
	if p.Permissions.PortForwarding {
		extensions[extPortForwarding] = ""
	}
	if p.Permissions.AgentForwarding {
		extensions[extAgentForwarding] = ""
	}
	if p.Permissions.X11Forwarding {
		extensions[extX11Forwarding] = ""
	}

	cert := &ssh.Certificate{
		Key:             p.UserPublicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           p.KeyID,
		ValidPrincipals: principals,
		ValidAfter:      unixSeconds(validAfter),
		ValidBefore:     unixSeconds(validBefore),
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}

	if err := i.authority.SignCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return cert, nil
}

// dedupeNonEmpty removes empty and duplicate entries and sorts the result.
func dedupeNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// unixSeconds converts a time to the uint64 seconds used by SSH certificates,
// clamping pre-epoch values to zero.
func unixSeconds(t time.Time) uint64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}
