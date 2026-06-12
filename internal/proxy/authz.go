package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/sshbroker/internal/ca"
)

// ErrTargetUnauthorized is returned when an identity may not reach the
// requested target as the requested login. The client is never told which of
// the two (target unknown vs. not granted) was the cause.
var ErrTargetUnauthorized = errors.New("proxy: target not authorized")

// targetSeparator splits the SSH username into <token><sep><host>, e.g.
// "ec2-user+web01" or "alice+web01".
const targetSeparator = "+"

// TargetSpec is the parsed SSH username. RequestedLogin is the token left of
// the separator: it may name a target account explicitly, be the user's own
// name or "me" (derive), or be empty (bare host → derive). The authorizer
// resolves it to the effective target account (ADR-019).
type TargetSpec struct {
	RequestedLogin string
	Host           string
}

// ParseTarget parses the SSH username. Accepted forms:
//
//	account+host   explicit target account, e.g. "ec2-user+web01"
//	host           bare host; the broker derives the account from the grant
//	+host          explicit "derive" (empty requested login)
func ParseTarget(user string) (TargetSpec, error) {
	if user == "" {
		return TargetSpec{}, fmt.Errorf("empty target host")
	}
	login, host, ok := strings.Cut(user, targetSeparator)
	if !ok {
		return TargetSpec{RequestedLogin: "", Host: user}, nil // bare host
	}
	if host == "" {
		return TargetSpec{}, fmt.Errorf("expected username of the form account%shost or host", targetSeparator)
	}
	return TargetSpec{RequestedLogin: login, Host: host}, nil
}

// Decision is the result of authorizing a connection: where to dial, how to
// verify the target, the resolved target account, and what the minted
// certificate and session may do.
type Decision struct {
	Address            string        // host:port to dial
	HostKeyFingerprint string        // SHA256:... to verify; empty = dev accept-and-log
	Login              string        // resolved target OS account (ADR-019)
	Principals         []string      // principals placed in the certificate
	TTL                time.Duration // certificate lifetime (0 = issuer max)
	CertPermissions    ca.Permissions
	Recording          string // session recording policy: "metadata" | "full" (ADR-011)

	// Broker-side channel gating (ADR-014). Cert extensions cover what the
	// target permits; these let the broker refuse capabilities per grant.
	AllowShell bool
	AllowExec  bool
	AllowSFTP  bool
}

// Authorizer decides whether an identity may reach a target and with what
// privileges. The DB-backed implementation (computing this from users,
// groups, servers, and grants) arrives in Phase 3; MemoryAuthorizer is the
// dev backend.
type Authorizer interface {
	Authorize(ctx context.Context, id Identity, target TargetSpec) (*Decision, error)
}
