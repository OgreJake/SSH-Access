package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/store"
)

// dummyHash lets failed logins for unknown users spend roughly the same time as
// real verifications, reducing username-enumeration via timing.
var dummyHash, _ = auth.HashPassword("sshbroker-dummy-password-for-timing")

// loginLimiter is a simple fixed-window limiter keyed by username (and client
// IP) to slow brute-force attempts against the break-glass login.
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func (s *Server) localLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Username == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	key := in.Username + "|" + clientIP(r)
	if !s.loginLimiter.allow(key) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}

	fail := func() {
		_ = s.store.AppendAudit(r.Context(), store.AuditEvent{
			Actor: "break-glass:" + in.Username, EventType: "auth.login.failed",
			Target: "local", Detail: map[string]string{"source_ip": clientIP(r)},
		})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	}

	admin, err := s.store.GetLocalAdminByUsername(r.Context(), in.Username)
	if err != nil {
		_, _ = auth.VerifyPassword(dummyHash, in.Password) // constant-ish time
		fail()
		return
	}
	ok, _ := auth.VerifyPassword(admin.PasswordHash, in.Password)
	if !ok || admin.Status != "active" {
		fail()
		return
	}

	token, hash, err := auth.NewSessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	expires := time.Now().Add(s.authCfg.SessionAbsolute)
	if _, err := s.store.CreateAdminSession(r.Context(), admin.ID, hash, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.authCfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{
		Actor: "break-glass:" + admin.Username, EventType: "auth.login",
		Target: "local", Detail: map[string]string{"source_ip": clientIP(r)},
	})
	p := auth.NewPrincipal("break-glass:"+admin.Username, auth.SourceBreakGlass, []string{admin.Role})
	writeJSON(w, http.StatusOK, principalDTO(p))
}

func (s *Server) localLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
		_ = s.store.RevokeAdminSession(r.Context(), auth.HashSessionToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.authCfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, principalDTO(*p))
}

func principalDTO(p auth.Principal) map[string]any {
	return map[string]any{
		"subject":     p.Subject,
		"source":      string(p.Source),
		"roles":       p.Roles,
		"permissions": p.Permissions(),
	}
}

// clientIP returns the originating client IP. The API is reachable only via the
// loopback proxy, so the left-most X-Forwarded-For entry (the real client) is
// trusted; otherwise fall back to the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := indexLastColon(host); i >= 0 {
		host = host[:i]
	}
	return host
}

func indexLastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
