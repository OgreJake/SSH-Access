package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
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

	// The principals this subject may use on this host: union of the matching
	// grants' principals, restricted to the server's allowlist where set.
	permitted := dedup(grantPrincipals(grants))
	usable := permitted
	if len(server.AllowedPrincipals) > 0 {
		usable = intersect(permitted, server.AllowedPrincipals)
	}

	// Resolve the effective target account (ADR-019).
	chosen, err := a.resolvePrincipal(id, target, usable)
	if err != nil {
		return nil, err
	}

	// Defense in depth: the resolved account must be in the server allowlist
	// where one is set (derivation already ensures this; explicit forms may not).
	if len(server.AllowedPrincipals) > 0 && !slices.Contains(server.AllowedPrincipals, chosen) {
		return nil, fmt.Errorf("%w: account %q not permitted on host %q (server allowlist)",
			ErrTargetUnauthorized, chosen, target.Host)
	}

	// Compose over the grants that actually permit the chosen account:
	// union of capabilities, longest permitted TTL.
	d := &Decision{
		Address:            net.JoinHostPort(server.Address, strconv.Itoa(serverPort(server.Port))),
		HostKeyFingerprint: server.HostKeyFingerprint,
		Login:              chosen,
		Principals:         []string{chosen},
	}
	for _, g := range grants {
		if !slices.Contains(g.Principals, chosen) {
			continue
		}
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

// resolvePrincipal turns the requested-login token into the effective target
// account, given the accounts usable by this subject on this host (ADR-019).
func (a *DBAuthorizer) resolvePrincipal(id Identity, target TargetSpec, usable []string) (string, error) {
	req := target.RequestedLogin

	// Explicit: the token names an account the subject may use — honor it
	// (backward compatible with account+host).
	if req != "" && slices.Contains(usable, req) {
		return req, nil
	}

	// Self-reference or bare host → derive from the usable accounts.
	if req == "" || req == "me" || req == id.Label {
		switch len(usable) {
		case 1:
			return usable[0], nil
		case 0:
			return "", fmt.Errorf("%w: subject %q has no usable account on host %q", ErrTargetUnauthorized, id.Label, target.Host)
		default:
			// Ambiguous: never guess. Tell the user how to disambiguate.
			return "", fmt.Errorf("%w: multiple accounts available on %q for %q (%s); connect as e.g. %q",
				ErrTargetUnauthorized, target.Host, id.Label, strings.Join(usable, ", "), usable[0]+"+"+target.Host)
		}
	}

	// A specific account was named but it is not one the subject may use.
	return "", fmt.Errorf("%w: subject %q may not use account %q on host %q (available: %s)",
		ErrTargetUnauthorized, id.Label, req, target.Host, strings.Join(usable, ", "))
}

func grantPrincipals(grants []ResolvedGrant) []string {
	var out []string
	for _, g := range grants {
		out = append(out, g.Principals...)
	}
	return out
}

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := set[x]; ok {
			out = append(out, x)
		}
	}
	return out
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
