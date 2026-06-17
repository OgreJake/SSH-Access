package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/store"
)

type ctxKey int

const principalKey ctxKey = iota

func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

func principalFrom(ctx context.Context) (*auth.Principal, bool) {
	p, ok := ctx.Value(principalKey).(*auth.Principal)
	return p, ok && p != nil
}

// maxBodyBytes caps request bodies to bound memory use (CC7.1).
const maxBodyBytes = 1 << 20 // 1 MiB

// bodyLimitMW caps the size of every request body.
func (s *Server) bodyLimitMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// requireJSONMW requires application/json on state-changing methods. This blocks
// cross-site form/simple-request CSRF (an HTML form cannot set this content
// type, and a cross-origin fetch that does is stopped by the CORS preflight),
// as defense in depth alongside the session cookie's SameSite attribute (M-1).
func (s *Server) requireJSONMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			ct := r.Header.Get("Content-Type")
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			if strings.TrimSpace(ct) != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// recoverMW converts handler panics into 500s.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic in handler", "method", r.Method, "path", r.URL.Path, "err", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// resolvePrincipalMW resolves the caller's identity (if any) into the request
// context. It never rejects; route guards decide what authentication is needed.
func (s *Server) resolvePrincipalMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := s.resolvePrincipal(r); p != nil {
			r = r.WithContext(withPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// resolvePrincipal applies the identity sources in priority order.
func (s *Server) resolvePrincipal(r *http.Request) *auth.Principal {
	// 1. Break-glass session cookie.
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
		if sess, err := s.store.LookupAdminSession(r.Context(), auth.HashSessionToken(c.Value), s.authCfg.SessionIdle); err == nil {
			p := auth.NewPrincipal("break-glass:"+sess.Username, auth.SourceBreakGlass, []string{sess.Role})
			return &p
		}
	}
	// 2. Trusted OIDC headers from the reverse proxy (only if the shared secret
	//    matches — see ADR-008 header-trust boundary).
	if s.proxyTrusted(r) {
		email := strings.TrimSpace(r.Header.Get(s.authCfg.OIDCEmailHeader))
		if email != "" {
			groups := splitAndTrim(r.Header.Get(s.authCfg.OIDCGroupsHeader), s.authCfg.OIDCGroupsDelim)
			roles := s.authCfg.GroupRoles.RolesForGroups(groups)
			p := auth.NewPrincipal(email, auth.SourceOIDC, roles)
			return &p
		}
	}
	// 3. Transitional static bearer token → full admin.
	if s.authCfg.AllowBearerToken && s.bearerOK(r) {
		p := auth.NewPrincipal("bearer-token", auth.SourceBreakGlass, []string{auth.RoleAdmin})
		return &p
	}
	return nil
}

// proxyTrusted reports whether the request carries the configured proxy shared
// secret. With no secret configured, OIDC headers are never trusted.
func (s *Server) proxyTrusted(r *http.Request) bool {
	if s.authCfg.ProxySecret == "" {
		return false
	}
	got := r.Header.Get(s.authCfg.ProxySecretHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.authCfg.ProxySecret)) == 1
}

func (s *Server) bearerOK(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func splitAndTrim(s, delim string) []string {
	if s == "" {
		return nil
	}
	if delim == "" {
		delim = ","
	}
	parts := strings.Split(s, delim)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// require wraps a handler so it runs only for an authenticated principal holding
// the given permission (401 if unauthenticated, 403 if lacking the permission).
// Authenticated-but-forbidden attempts are written to the audit log (CC7.2);
// unauthenticated hits are logged operationally (they carry no identity and,
// behind the proxy, should be rare — auditing them would let anonymous traffic
// amplify DB writes).
func (s *Server) require(perm auth.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFrom(r.Context())
		if !ok {
			s.logger.Warn("unauthenticated request", "method", r.Method, "path", r.URL.Path, "source_ip", clientIP(r))
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErrorExtra(w, http.StatusUnauthorized, "unauthorized", map[string]any{"auth_url": s.authURL})
			return
		}
		if !p.Can(perm) {
			s.auditDenied(r, p.Subject, string(perm))
			writeError(w, http.StatusForbidden, "forbidden: requires "+string(perm))
			return
		}
		h(w, r)
	}
}

// requireAuth wraps a handler so it runs for any authenticated principal.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principalFrom(r.Context()); !ok {
			s.logger.Warn("unauthenticated request", "method", r.Method, "path", r.URL.Path, "source_ip", clientIP(r))
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErrorExtra(w, http.StatusUnauthorized, "unauthorized", map[string]any{"auth_url": s.authURL})
			return
		}
		h(w, r)
	}
}

// auditDenied records an authorization denial for a known principal (CC7.2).
func (s *Server) auditDenied(r *http.Request, actor, permission string) {
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{
		Actor:     actor,
		EventType: "access.denied",
		Target:    r.URL.Path,
		Detail: map[string]string{
			"reason":     "forbidden",
			"permission": permission,
			"method":     r.Method,
			"path":       r.URL.Path,
			"source_ip":  clientIP(r),
		},
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// auditMW records every successful management mutation with the real admin
// identity (ADR-020), giving blanket management-plane accountability. The
// /auth/* endpoints write their own, richer events and are skipped here.
func (s *Server) auditMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || strings.HasPrefix(r.URL.Path, "/api/v1/ssh-login") {
			next.ServeHTTP(w, r)
			return
		}
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		if sr.status < 200 || sr.status >= 300 {
			return
		}
		actor := "unknown"
		if p, ok := principalFrom(r.Context()); ok {
			actor = p.Subject
		}
		_ = s.store.AppendAudit(r.Context(), store.AuditEvent{
			Actor:     actor,
			EventType: "api." + strings.ToLower(r.Method),
			Target:    r.URL.Path,
			Detail: map[string]string{
				"method": r.Method,
				"path":   r.URL.Path,
				"status": strconv.Itoa(sr.status),
			},
		})
	})
}
