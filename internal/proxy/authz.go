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

// targetSeparator splits the SSH username into <login><sep><host>, e.g.
// "deploy+web01" → login "deploy", host "web01".
const targetSeparator = "+"

// TargetSpec is the parsed SSH username: the login to use on the target and
// the target host alias to resolve.
type TargetSpec struct {
	Login string
	Host  string
}

// ParseTarget parses an SSH username of the form "<login>+<host>".
func ParseTarget(user string) (TargetSpec, error) {
	login, host, ok := strings.Cut(user, targetSeparator)
	if !ok || login == "" || host == "" {
		return TargetSpec{}, fmt.Errorf("expected username of the form login%shost (e.g. deploy%sweb01)", targetSeparator, targetSeparator)
	}
	return TargetSpec{Login: login, Host: host}, nil
}

// Decision is the result of authorizing a connection: where to dial, how to
// verify the target, and what the minted certificate and session may do.
type Decision struct {
	Address            string        // host:port to dial
	HostKeyFingerprint string        // SHA256:... to verify; empty = dev accept-and-log
	Principals         []string      // principals placed in the certificate
	TTL                time.Duration // certificate lifetime (0 = issuer max)
	CertPermissions    ca.Permissions

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
