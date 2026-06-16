package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
)

func TestSSHLoginApprovalEndpoints(t *testing.T) {
	srv, st := testAPIServer(t)
	srv.SetAuthConfig(AuthConfig{
		ProxySecret:      "proxy-secret",
		GroupRoles:       auth.ParseGroupRoleMapping("sg-admins:admin"),
		CookieSecure:     false,
		AllowBearerToken: true,
	})
	h := srv.Handler()

	// oidc issues a request as an Entra user behind the proxy.
	oidc := func(method, path, email, body string) *httptest.ResponseRecorder {
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		var req *http.Request
		if rdr != nil {
			req = httptest.NewRequest(method, path, rdr)
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("X-Proxy-Auth", "proxy-secret")
		req.Header.Set("X-Auth-Request-Email", email)
		req.Header.Set("X-Auth-Request-Groups", "sg-admins")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// SSH side creates a pending request.
	code, hash, _ := auth.NewLoginCode()
	id, err := st.CreateSSHLoginRequest(context.Background(), hash, "10.1.2.3", "alice+web01", time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Info endpoint shows the connection details to the approver.
	rec := oidc("GET", "/api/v1/ssh-login?code="+code, "alice@contoso.com", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("info: %d (%s)", rec.Code, rec.Body)
	}
	var info struct {
		SourceIP        string `json:"source_ip"`
		RequestedTarget string `json:"requested_target"`
		Approver        string `json:"approver"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info.SourceIP != "10.1.2.3" || info.RequestedTarget != "alice+web01" || info.Approver != "alice@contoso.com" {
		t.Fatalf("unexpected info: %+v", info)
	}

	// Approve binds the Entra identity; the SSH side can then consume it.
	if rec := oidc("POST", "/api/v1/ssh-login/approve", "alice@contoso.com", `{"code":"`+code+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d (%s)", rec.Code, rec.Body)
	}
	if status, subject, _ := st.PollSSHLogin(context.Background(), id); status != "approved" || subject != "alice@contoso.com" {
		t.Fatalf("poll after approve: %q/%q", status, subject)
	}

	// An approval was audited with the real identity.
	events, _ := st.ListRecentAudit(context.Background(), 50)
	var audited bool
	for _, e := range events {
		if e.EventType == "ssh.login.approved" && e.Actor == "alice@contoso.com" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("expected ssh.login.approved audit event")
	}
}

func TestSSHLoginApprovalRejections(t *testing.T) {
	srv, st := testAPIServer(t)
	srv.SetAuthConfig(AuthConfig{
		ProxySecret:      "proxy-secret",
		GroupRoles:       auth.ParseGroupRoleMapping("sg-admins:admin"),
		CookieSecure:     false,
		AllowBearerToken: true,
	})
	h := srv.Handler()

	// Unauthenticated → 401.
	if rec := do(t, h, "GET", "/api/v1/ssh-login?code=whatever", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth info: %d want 401", rec.Code)
	}

	// Break-glass (bearer→admin) is authenticated but not an SSO identity → 403.
	code, hash, _ := auth.NewLoginCode()
	_, _ = st.CreateSSHLoginRequest(context.Background(), hash, "10.0.0.1", "x+y", time.Now().Add(time.Minute))
	if rec := do(t, h, "POST", "/api/v1/ssh-login/approve", testToken, map[string]any{"code": code}); rec.Code != http.StatusForbidden {
		t.Fatalf("break-glass approve: %d want 403", rec.Code)
	}

	// Unknown/expired code → 404 on info.
	oidcReq := httptest.NewRequest("GET", "/api/v1/ssh-login?code=nonexistent", nil)
	oidcReq.Header.Set("X-Proxy-Auth", "proxy-secret")
	oidcReq.Header.Set("X-Auth-Request-Email", "alice@contoso.com")
	oidcReq.Header.Set("X-Auth-Request-Groups", "sg-admins")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, oidcReq)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown code info: %d want 404", rec.Code)
	}
}
