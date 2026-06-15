package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourorg/sshbroker/internal/auth"
)

// sessionCookieFrom extracts the session cookie value from a login response.
func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("no session cookie in response (status %d)", rec.Code)
	return ""
}

// doCookie issues a request authenticated by a break-glass session cookie.
func doCookie(t *testing.T, h http.Handler, method, path, cookie string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	return out
}

func TestBreakGlassLoginWhoamiLogout(t *testing.T) {
	srv, st := testAPIServer(t)
	srv.SetAuthConfig(AuthConfig{CookieSecure: false, AllowBearerToken: true})
	h := srv.Handler()

	hash, _ := auth.HashPassword("s3cret-pw")
	if _, err := st.UpsertLocalAdmin(context.Background(), "root", hash, "admin"); err != nil {
		t.Fatalf("provision admin: %v", err)
	}

	// Wrong password → 401, no cookie.
	if rec := do(t, h, "POST", "/api/v1/auth/local/login", "", map[string]any{"username": "root", "password": "nope"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d want 401", rec.Code)
	}

	// Correct password → 200 + cookie.
	rec := do(t, h, "POST", "/api/v1/auth/local/login", "", map[string]any{"username": "root", "password": "s3cret-pw"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d (%s)", rec.Code, rec.Body)
	}
	cookie := sessionCookieFrom(t, rec)

	// whoami via cookie shows admin identity + permissions.
	who := doCookie(t, h, "GET", "/api/v1/auth/whoami", cookie, nil)
	if who.Code != http.StatusOK {
		t.Fatalf("whoami: %d (%s)", who.Code, who.Body)
	}
	var id struct {
		Subject     string   `json:"subject"`
		Source      string   `json:"source"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	_ = json.Unmarshal(who.Body.Bytes(), &id)
	if id.Subject != "break-glass:root" || id.Source != "break-glass" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if len(id.Permissions) != len(auth.AllPermissions()) {
		t.Fatalf("admin should hold all %d permissions, got %d", len(auth.AllPermissions()), len(id.Permissions))
	}

	// Cookie authorizes a real mutation.
	if rec := doCookie(t, h, "POST", "/api/v1/user-groups", cookie, map[string]any{"name": "g1"}); rec.Code != http.StatusCreated {
		t.Fatalf("create via cookie: %d (%s)", rec.Code, rec.Body)
	}

	// Logout revokes the session; the cookie no longer authenticates.
	if rec := doCookie(t, h, "POST", "/api/v1/auth/local/logout", cookie, nil); rec.Code != http.StatusOK {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := doCookie(t, h, "GET", "/api/v1/auth/whoami", cookie, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("whoami after logout: got %d want 401", rec.Code)
	}

	// A bare request with no auth is rejected.
	if rec := do(t, h, "GET", "/api/v1/users", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth: got %d want 401", rec.Code)
	}
}

func TestOIDCHeaderTrustAndRBAC(t *testing.T) {
	srv, _ := testAPIServer(t)
	srv.SetAuthConfig(AuthConfig{
		ProxySecret:      "proxy-shared-secret",
		GroupRoles:       auth.ParseGroupRoleMapping("sg-admins:admin,sg-audit:auditor"),
		CookieSecure:     false,
		AllowBearerToken: true,
	})
	h := srv.Handler()

	withHeaders := func(method, path, secret, email, groups string, body any) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if secret != "" {
			req.Header.Set("X-Proxy-Auth", secret)
		}
		if email != "" {
			req.Header.Set("X-Auth-Request-Email", email)
		}
		if groups != "" {
			req.Header.Set("X-Auth-Request-Groups", groups)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Headers without the proxy secret are NOT trusted → 401.
	if rec := withHeaders("GET", "/api/v1/users", "", "eve@x.com", "sg-admins", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged headers (no secret): got %d want 401", rec.Code)
	}
	// Wrong secret → not trusted.
	if rec := withHeaders("GET", "/api/v1/users", "wrong", "eve@x.com", "sg-admins", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: got %d want 401", rec.Code)
	}

	// Admin group → can read and write.
	if rec := withHeaders("GET", "/api/v1/users", "proxy-shared-secret", "alice@x.com", "sg-admins", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin read: %d (%s)", rec.Code, rec.Body)
	}

	// Auditor group → can read, cannot write.
	if rec := withHeaders("GET", "/api/v1/grants", "proxy-shared-secret", "rob@x.com", "sg-audit", nil); rec.Code != http.StatusOK {
		t.Fatalf("auditor read: %d", rec.Code)
	}
	rec := withHeaders("POST", "/api/v1/user-groups", "proxy-shared-secret", "rob@x.com", "sg-audit", map[string]any{"name": "x"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor write: got %d want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "groups:write") {
		t.Fatalf("403 should name the missing permission, got %s", rec.Body)
	}

	// Authenticated but unmapped groups → no roles → no permissions → 403 on read.
	if rec := withHeaders("GET", "/api/v1/users", "proxy-shared-secret", "nobody@x.com", "sg-unmapped", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("unmapped user read: got %d want 403", rec.Code)
	}
}

func TestBearerTokenRetired(t *testing.T) {
	srv, _ := testAPIServer(t)
	srv.SetAuthConfig(AuthConfig{AllowBearerToken: false, CookieSecure: false})
	h := srv.Handler()
	// With bearer disabled and no other identity, the token must not authenticate.
	if rec := do(t, h, "GET", "/api/v1/users", testToken, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer should be rejected when disabled: got %d want 401", rec.Code)
	}
}

func TestManagementAuditTrail(t *testing.T) {
	h, st := testAPI(t)
	// A bearer-token mutation should be audited with the actor.
	createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "audited"})
	events, err := st.ListRecentAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.EventType == "api.post" && strings.Contains(string(e.Detail), "user-groups") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an api.post audit event for the mutation")
	}
}
