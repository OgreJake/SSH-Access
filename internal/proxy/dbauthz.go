package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/yourorg/sshbroker/internal/model"
)

// ResolvedServer is a target resolved from the database.
type ResolvedServer struct {
	ID                 string
	Address            string
	Port               int
	HostKeyFingerprint string
	AllowedPrincipals  []string // optional server-level login allowlist
}

// ResolvedGrant is one RBAC grant applicable to a (subject, target) pair.
type ResolvedGrant struct {
	Principals       []string
	MaxTTL           time.Duration
	AllowShell       bool
	AllowExec        bool
	AllowSFTP        bool
	AllowPortForward bool
}

// AuthzBackend supplies the data the authorizer composes a Decision from. A nil
// server with a nil error means the host alias is unknown.
type AuthzBackend interface {
	ServerByHostname(ctx context.Context, hostname string) (*ResolvedServer, error)
	GroupsForUser(ctx context.Context, userID string) ([]string, error)
	GroupsForServer(ctx context.Context, serverID string) ([]string, error)
	MatchingGrants(ctx context.Context, subjectType, subjectID string, userGroupIDs []string, serverID string, serverGroupIDs []string) ([]ResolvedGrant, error)
}

// DBAuthorizer authorizes against database-backed RBAC (ADR-010/014). When
// several grants match, capabilities are the union and the TTL is the longest
// permitted — every matching grant is an explicit allow. It fails closed:
// backend errors deny with a generic ErrTargetUnauthorized.
type DBAuthorizer struct {
	backend AuthzBackend
	timeout time.Duration
	logger  *slog.Logger
}

var _ Authorizer = (*DBAuthorizer)(nil)

// NewDBAuthorizer constructs a DBAuthorizer.
func NewDBAuthorizer(backend AuthzBackend, logger *slog.Logger) *DBAuthorizer {
	if logger == nil {
		logger = slog.Default()
	}
	return &DBAuthorizer{backend: backend, timeout: 5 * time.Second, logger: logger}
}

func (a *DBAuthorizer) Authorize(ctx context.Context, id Identity, target TargetSpec) (*Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	server, err := a.backend.ServerByHostname(ctx, target.Host)
	if err != nil {
		a.logger.Error("authz: resolve server failed", "host", target.Host, "err", err.Error())
		return nil, ErrTargetUnauthorized
	}
	if server == nil {
		return nil, fmt.Errorf("%w: host %q not found", ErrTargetUnauthorized, target.Host)
	}

	// Subject set: a user contributes its groups; a service account stands alone.
	var userGroups []string
	if id.Subject == model.SubjectUser {
		if userGroups, err = a.backend.GroupsForUser(ctx, id.ID); err != nil {
			a.logger.Error("authz: groups for user failed", "subject", id.Label, "err", err.Error())
			return nil, ErrTargetUnauthorized
		}
	}
	serverGroups, err := a.backend.GroupsForServer(ctx, server.ID)
	if err != nil {
		a.logger.Error("authz: groups for server failed", "host", target.Host, "err", err.Error())
		return nil, ErrTargetUnauthorized
	}

	grants, err := a.backend.MatchingGrants(ctx, string(id.Subject), id.ID, userGroups, server.ID, serverGroups)
	if err != nil {
		a.logger.Error("authz: matching grants failed", "subject", id.Label, "host", target.Host, "err", err.Error())
		return nil, ErrTargetUnauthorized
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("%w: no grant for subject %q on host %q", ErrTargetUnauthorized, id.Label, target.Host)
	}

	// Defense in depth: if the server enumerates allowed logins, the requested
	// login must be among them regardless of grants.
	if len(server.AllowedPrincipals) > 0 && !slices.Contains(server.AllowedPrincipals, target.Login) {
		return nil, fmt.Errorf("%w: login %q not permitted on host %q (server allowlist)",
			ErrTargetUnauthorized, target.Login, target.Host)
	}

	// Keep grants that permit the requested login; collect the rest for the
	// (server-side only) denial reason.
	var matched []ResolvedGrant
	var permitted []string
	for _, g := range grants {
		permitted = append(permitted, g.Principals...)
		if slices.Contains(g.Principals, target.Login) {
			matched = append(matched, g)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: subject %q has grants on %q but none permit login %q (permitted: %v)",
			ErrTargetUnauthorized, id.Label, target.Host, target.Login, dedup(permitted))
	}

	// Compose: union of capabilities, longest permitted TTL.
	d := &Decision{
		Address:            net.JoinHostPort(server.Address, strconv.Itoa(serverPort(server.Port))),
		HostKeyFingerprint: server.HostKeyFingerprint,
		Principals:         []string{target.Login},
	}
	for _, g := range matched {
		if g.MaxTTL > d.TTL {
			d.TTL = g.MaxTTL
		}
		d.AllowShell = d.AllowShell || g.AllowShell
		d.AllowExec = d.AllowExec || g.AllowExec
		d.AllowSFTP = d.AllowSFTP || g.AllowSFTP
		d.CertPermissions.PortForwarding = d.CertPermissions.PortForwarding || g.AllowPortForward
	}
	d.CertPermissions.PTY = d.AllowShell // interactive shells need a PTY
	return d, nil
}

func serverPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
