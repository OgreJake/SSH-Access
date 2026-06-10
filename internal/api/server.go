// Package api exposes the broker's management plane (ADR-005) as a JSON HTTP
// API over the repository layer. It is deliberately separate from the SSH front
// door: different exposure and trust boundary. Authentication is a static
// bearer token for now; browser/session auth (with MFA) lands in a later slice.
package api

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/yourorg/sshbroker/internal/store"
)

// Server is the management API.
type Server struct {
	store  *store.Store
	logger *slog.Logger
	token  string
}

// New constructs the API server. It fails closed: an empty token is rejected
// so the management plane can never start unauthenticated.
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
	return &Server{store: st, logger: logger, token: token}, nil
}

// Handler builds the routed, middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.health)

	mux.HandleFunc("GET /api/v1/users", s.listUsers)
	mux.HandleFunc("POST /api/v1/users", s.createUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.patchUser)
	mux.HandleFunc("POST /api/v1/users/{id}/keys", s.addUserKey)

	mux.HandleFunc("GET /api/v1/servers", s.listServers)
	mux.HandleFunc("POST /api/v1/servers", s.createServer)
	mux.HandleFunc("PATCH /api/v1/servers/{id}", s.patchServer)

	mux.HandleFunc("GET /api/v1/grants", s.listGrants)
	mux.HandleFunc("POST /api/v1/grants", s.createGrant)
	mux.HandleFunc("PATCH /api/v1/grants/{id}", s.patchGrant)
	mux.HandleFunc("DELETE /api/v1/grants/{id}", s.deleteGrant)

	mux.HandleFunc("POST /api/v1/user-groups", s.createUserGroup)
	mux.HandleFunc("GET /api/v1/user-groups", s.listUserGroups)
	mux.HandleFunc("POST /api/v1/user-groups/{id}/members", s.addUserGroupMember)
	mux.HandleFunc("POST /api/v1/server-groups", s.createServerGroup)
	mux.HandleFunc("GET /api/v1/server-groups", s.listServerGroups)
	mux.HandleFunc("POST /api/v1/server-groups/{id}/members", s.addServerGroupMember)

	mux.HandleFunc("GET /api/v1/sessions", s.listSessions)
	mux.HandleFunc("GET /api/v1/audit", s.listAudit)
	mux.HandleFunc("GET /api/v1/audit/export", s.exportAudit)
	mux.HandleFunc("GET /api/v1/audit/verify", s.verifyAudit)

	return s.middleware(mux)
}

// middleware applies panic recovery and bearer-token auth (everything except
// /healthz).
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic in handler", "method", r.Method, "path", r.URL.Path, "err", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		if r.URL.Path != "/healthz" && !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
