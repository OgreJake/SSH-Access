// Package api exposes the broker's management plane (ADR-005) as a JSON HTTP
// API over the repository layer. It is deliberately separate from the SSH front
// door: different exposure and trust boundary.
//
// Authentication (ADR-008 Phase A) resolves a Principal per request from, in
// order: a break-glass session cookie, trusted Entra-OIDC headers injected by
// the reverse proxy (gated on a shared-secret header), or — transitionally —
// the static bearer token treated as a full admin. Authorization (ADR-020) is
// per-route permission checks via require()/requireAuth().
package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/store"
)

// AuthConfig configures management-plane authentication (ADR-008/020).
type AuthConfig struct {
	// OIDC trusted-header names (set by the reverse proxy).
	OIDCEmailHeader  string
	OIDCGroupsHeader string
	OIDCGroupsDelim  string
	// Proxy shared secret: OIDC headers are trusted only when this header
	// matches. Empty ProxySecret disables OIDC header trust entirely.
	ProxySecretHeader string
	ProxySecret       string
	// Entra group -> role mapping.
	GroupRoles auth.GroupRoleMapping
	// Break-glass session lifetimes.
	SessionAbsolute time.Duration
	SessionIdle     time.Duration
	// CookieSecure sets the Secure flag on the session cookie (disable only for
	// local HTTP dev).
	CookieSecure bool
	// AllowBearerToken keeps the static token working as a transitional full
	// admin (retired in A3).
	AllowBearerToken bool
}

// Server is the management API.
type Server struct {
	store              *store.Store
	logger             *slog.Logger
	token              string
	recordingDir       string
	reviewIntervalDays int
	authCfg            AuthConfig
	loginLimiter       *loginLimiter
}

// New constructs the API server. It fails closed: an empty token is rejected so
// the management plane can never start unauthenticated.
func New(st *store.Store, logger *slog.Logger, token string) (*Server, error) {
	if st == nil {
		return nil, errors.New("api: store is required")
	}
	if token == "" {
		return nil, errors.New("api: an API token is required (SSHBROKER_API_TOKEN)")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:              st,
		logger:             logger,
		token:              token,
		reviewIntervalDays: 90,
		authCfg: AuthConfig{
			OIDCEmailHeader:   "X-Auth-Request-Email",
			OIDCGroupsHeader:  "X-Auth-Request-Groups",
			OIDCGroupsDelim:   ",",
			ProxySecretHeader: "X-Proxy-Auth",
			GroupRoles:        auth.GroupRoleMapping{},
			SessionAbsolute:   12 * time.Hour,
			SessionIdle:       time.Hour,
			CookieSecure:      true,
			AllowBearerToken:  true, // transitional; A3 retires the bearer token
		},
		loginLimiter: newLoginLimiter(5, time.Minute),
	}, nil
}

// SetAuthConfig overrides the authentication configuration (cmd/api builds this
// from the environment). Zero-valued fields fall back to the New defaults.
func (s *Server) SetAuthConfig(c AuthConfig) {
	d := s.authCfg
	if c.OIDCEmailHeader != "" {
		d.OIDCEmailHeader = c.OIDCEmailHeader
	}
	if c.OIDCGroupsHeader != "" {
		d.OIDCGroupsHeader = c.OIDCGroupsHeader
	}
	if c.OIDCGroupsDelim != "" {
		d.OIDCGroupsDelim = c.OIDCGroupsDelim
	}
	if c.ProxySecretHeader != "" {
		d.ProxySecretHeader = c.ProxySecretHeader
	}
	d.ProxySecret = c.ProxySecret
	if c.GroupRoles != nil {
		d.GroupRoles = c.GroupRoles
	}
	if c.SessionAbsolute > 0 {
		d.SessionAbsolute = c.SessionAbsolute
	}
	if c.SessionIdle > 0 {
		d.SessionIdle = c.SessionIdle
	}
	d.CookieSecure = c.CookieSecure
	d.AllowBearerToken = c.AllowBearerToken
	s.authCfg = d
}

// SetReviewIntervalDays overrides the default grant recertification cadence
// (ADR-017). Values <= 0 are ignored.
func (s *Server) SetReviewIntervalDays(days int) {
	if days > 0 {
		s.reviewIntervalDays = days
	}
}

// SetRecordingDir enables session-recording downloads from the given directory
// (ADR-011). The API and broker are expected to share this filesystem path.
func (s *Server) SetRecordingDir(dir string) { s.recordingDir = dir }

// Handler builds the routed, middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.health)

	// Authentication endpoints (unauthenticated by design).
	mux.HandleFunc("POST /api/v1/auth/local/login", s.localLogin)
	mux.HandleFunc("POST /api/v1/auth/local/logout", s.localLogout)
	mux.HandleFunc("GET /api/v1/auth/whoami", s.requireAuth(s.whoami))

	mux.HandleFunc("GET /api/v1/users", s.require(auth.PermUsersRead, s.listUsers))
	mux.HandleFunc("POST /api/v1/users", s.require(auth.PermUsersWrite, s.createUser))
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.require(auth.PermUsersWrite, s.patchUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.require(auth.PermUsersWrite, s.deleteUser))
	mux.HandleFunc("POST /api/v1/users/{id}/keys", s.require(auth.PermUsersWrite, s.addUserKey))

	mux.HandleFunc("GET /api/v1/servers", s.require(auth.PermServersRead, s.listServers))
	mux.HandleFunc("POST /api/v1/servers", s.require(auth.PermServersWrite, s.createServer))
	mux.HandleFunc("PATCH /api/v1/servers/{id}", s.require(auth.PermServersWrite, s.patchServer))
	mux.HandleFunc("DELETE /api/v1/servers/{id}", s.require(auth.PermServersWrite, s.deleteServer))

	mux.HandleFunc("GET /api/v1/grants", s.require(auth.PermGrantsRead, s.listGrants))
	mux.HandleFunc("POST /api/v1/grants", s.require(auth.PermGrantsWrite, s.createGrant))
	mux.HandleFunc("PATCH /api/v1/grants/{id}", s.require(auth.PermGrantsWrite, s.patchGrant))
	mux.HandleFunc("DELETE /api/v1/grants/{id}", s.require(auth.PermGrantsWrite, s.deleteGrant))
	mux.HandleFunc("POST /api/v1/grants/{id}/recertify", s.require(auth.PermGrantsRecertify, s.recertifyGrant))

	mux.HandleFunc("POST /api/v1/user-groups", s.require(auth.PermGroupsWrite, s.createUserGroup))
	mux.HandleFunc("GET /api/v1/user-groups", s.require(auth.PermGroupsRead, s.listUserGroups))
	mux.HandleFunc("POST /api/v1/user-groups/{id}/members", s.require(auth.PermGroupsWrite, s.addUserGroupMember))
	mux.HandleFunc("POST /api/v1/server-groups", s.require(auth.PermGroupsWrite, s.createServerGroup))
	mux.HandleFunc("GET /api/v1/server-groups", s.require(auth.PermGroupsRead, s.listServerGroups))
	mux.HandleFunc("POST /api/v1/server-groups/{id}/members", s.require(auth.PermGroupsWrite, s.addServerGroupMember))

	mux.HandleFunc("GET /api/v1/sessions", s.require(auth.PermSessionsRead, s.listSessions))
	mux.HandleFunc("POST /api/v1/sessions/{id}/terminate", s.require(auth.PermSessionsTerminate, s.terminateSession))
	mux.HandleFunc("GET /api/v1/sessions/{id}/recording", s.require(auth.PermRecordingsRead, s.getRecording))
	mux.HandleFunc("GET /api/v1/audit", s.require(auth.PermAuditRead, s.listAudit))
	mux.HandleFunc("GET /api/v1/audit/export", s.require(auth.PermAuditRead, s.exportAudit))
	mux.HandleFunc("GET /api/v1/audit/verify", s.require(auth.PermAuditRead, s.verifyAudit))

	// SSH browser-SSO approval (ADR-021): any authenticated SSO user may approve
	// their own pending SSH login. Reached by the user's browser behind oauth2-proxy.
	mux.HandleFunc("GET /api/v1/ssh-login", s.requireAuth(s.sshLoginInfo))
	mux.HandleFunc("POST /api/v1/ssh-login/approve", s.requireAuth(s.sshLoginApprove))
	mux.HandleFunc("POST /api/v1/ssh-login/deny", s.requireAuth(s.sshLoginDeny))

	return s.recoverMW(s.resolvePrincipalMW(s.auditMW(mux)))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
