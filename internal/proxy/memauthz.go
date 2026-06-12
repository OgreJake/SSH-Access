package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/yourorg/sshbroker/internal/ca"
)

// MemoryAuthorizer is the development Authorizer, backed by a static policy
// loaded from JSON. Production authorization is DB-backed (Phase 3) behind the
// same interface.
type MemoryAuthorizer struct {
	targets map[string]targetPolicy // keyed by host alias
}

type targetPolicy struct {
	Address string        `json:"address"`
	HostKey string        `json:"host_key"`
	Grants  []grantPolicy `json:"grants"`
}

type grantPolicy struct {
	Subject     string   `json:"subject"`    // username (matches Identity.Label)
	Principals  []string `json:"principals"` // logins this grant permits
	MaxTTL      string   `json:"max_ttl"`    // duration string, e.g. "5m"
	Shell       bool     `json:"shell"`
	Exec        bool     `json:"exec"`
	SFTP        bool     `json:"sftp"`
	PortForward bool     `json:"port_forward"`
}

type policyFile struct {
	Targets []struct {
		Name string `json:"name"`
		targetPolicy
	} `json:"targets"`
}

var _ Authorizer = (*MemoryAuthorizer)(nil)

// NewMemoryAuthorizer returns an authorizer that denies everything.
func NewMemoryAuthorizer() *MemoryAuthorizer {
	return &MemoryAuthorizer{targets: make(map[string]targetPolicy)}
}

// LoadTargets builds a MemoryAuthorizer from a JSON policy file.
func LoadTargets(path string) (*MemoryAuthorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets %q: %w", path, err)
	}
	var pf policyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse targets %q: %w", path, err)
	}
	a := NewMemoryAuthorizer()
	for _, t := range pf.Targets {
		if t.Name == "" || t.Address == "" {
			return nil, fmt.Errorf("target entry missing name or address")
		}
		a.targets[t.Name] = t.targetPolicy
	}
	return a, nil
}

// Authorize resolves the target and finds a grant for the identity that
// permits the requested login. The file backend is explicit-only: it does not
// derive accounts (ADR-019 derivation is DB-backed), so an account must be
// given as account+host. Denials carry a server-side reason (the client still
// sees only a generic message).
func (a *MemoryAuthorizer) Authorize(_ context.Context, id Identity, target TargetSpec) (*Decision, error) {
	tp, ok := a.targets[target.Host]
	if !ok {
		return nil, fmt.Errorf("%w: host %q not found in policy", ErrTargetUnauthorized, target.Host)
	}
	if target.RequestedLogin == "" {
		return nil, fmt.Errorf("%w: file backend requires an explicit account (account%shost)", ErrTargetUnauthorized, targetSeparator)
	}
	login := target.RequestedLogin
	var permitted []string
	subjectHasGrant := false
	for _, g := range tp.Grants {
		if g.Subject != id.Label {
			continue
		}
		subjectHasGrant = true
		permitted = append(permitted, g.Principals...)
		if !slices.Contains(g.Principals, login) {
			continue
		}
		ttl, err := parseTTL(g.MaxTTL)
		if err != nil {
			return nil, fmt.Errorf("grant for %q has invalid max_ttl: %w", id.Label, err)
		}
		return &Decision{
			Address:            tp.Address,
			HostKeyFingerprint: tp.HostKey,
			Login:              login,
			Principals:         []string{login},
			TTL:                ttl,
			Recording:          "metadata", // file backend does not configure full recording
			CertPermissions: ca.Permissions{
				PTY:            g.Shell, // interactive shells need a PTY
				PortForwarding: g.PortForward,
			},
			AllowShell: g.Shell,
			AllowExec:  g.Exec,
			AllowSFTP:  g.SFTP,
		}, nil
	}
	if subjectHasGrant {
		return nil, fmt.Errorf("%w: subject %q has no grant permitting login %q on %q (permitted logins: %v)",
			ErrTargetUnauthorized, id.Label, login, target.Host, permitted)
	}
	return nil, fmt.Errorf("%w: no grant for subject %q on host %q", ErrTargetUnauthorized, id.Label, target.Host)
}

func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil // 0 → issuer clamps to its max
	}
	return time.ParseDuration(s)
}
