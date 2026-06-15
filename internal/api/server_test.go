package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/store"
)

const testToken = "test-secret-token"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testAPI(t *testing.T) (http.Handler, *store.Store) {
	srv, st := testAPIServer(t)
	return srv.Handler(), st
}

func testAPIServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dsn := os.Getenv("SSHBROKER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SSHBROKER_TEST_DATABASE_URL to run API integration tests")
	}
	st, err := store.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(context.Background(),
		`TRUNCATE admin_sessions, local_admins, audit_log, sessions, grants,
		          user_group_members, server_group_members, user_groups, server_groups,
		          user_public_keys, service_accounts, servers, users
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	srv, err := New(st, discardLogger(), testToken)
	if err != nil {
		t.Fatalf("new api: %v", err)
	}
	return srv, st
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func genKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestAPIHealthNoAuth(t *testing.T) {
	h, _ := testAPI(t)
	rec := do(t, h, "GET", "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}

func TestAPIRequiresAuth(t *testing.T) {
	h, _ := testAPI(t)
	if rec := do(t, h, "GET", "/api/v1/users", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := do(t, h, "GET", "/api/v1/users", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
	if rec := do(t, h, "GET", "/api/v1/users", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("good token: status = %d, want 200", rec.Code)
	}
}

func TestAPIUserLifecycle(t *testing.T) {
	h, _ := testAPI(t)

	rec := do(t, h, "POST", "/api/v1/users", testToken, map[string]any{
		"username": "alice", "email": "alice@example.com",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d (%s)", rec.Code, rec.Body)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("expected user id")
	}

	// Duplicate username → 409.
	if rec := do(t, h, "POST", "/api/v1/users", testToken, map[string]any{"username": "alice"}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate user: %d, want 409", rec.Code)
	}

	// Add a key.
	if rec := do(t, h, "POST", "/api/v1/users/"+created.ID+"/keys", testToken, map[string]any{
		"public_key": genKeyLine(t), "comment": "laptop",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("add key: %d (%s)", rec.Code, rec.Body)
	}

	// Invalid key → 400.
	if rec := do(t, h, "POST", "/api/v1/users/"+created.ID+"/keys", testToken, map[string]any{
		"public_key": "not-a-key",
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad key: %d, want 400", rec.Code)
	}

	// Disable.
	if rec := do(t, h, "PATCH", "/api/v1/users/"+created.ID, testToken, map[string]any{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d", rec.Code)
	}

	// List shows alice, disabled, 1 key.
	rec = do(t, h, "GET", "/api/v1/users", testToken, nil)
	var users []userDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users) != 1 || users[0].Username != "alice" || users[0].Status != "disabled" || users[0].KeyCount != 1 {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestAPIGrantRoundTrip(t *testing.T) {
	h, _ := testAPI(t)

	// user + user group
	uid := createID(t, h, "POST", "/api/v1/users", map[string]any{"username": "alice"})
	ugid := createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "deployers"})
	if rec := do(t, h, "POST", "/api/v1/user-groups/"+ugid+"/members", testToken, map[string]any{"user_id": uid}); rec.Code != http.StatusOK {
		t.Fatalf("add member: %d", rec.Code)
	}
	// server + server group
	sid := createID(t, h, "POST", "/api/v1/servers", map[string]any{
		"hostname": "web01", "address": "10.0.0.5", "port": 22, "allowed_principals": []string{"deploy"},
	})
	sgid := createID(t, h, "POST", "/api/v1/server-groups", map[string]any{"name": "web-tier"})
	if rec := do(t, h, "POST", "/api/v1/server-groups/"+sgid+"/members", testToken, map[string]any{"server_id": sid}); rec.Code != http.StatusOK {
		t.Fatalf("add server to group: %d", rec.Code)
	}
	// grant group→group
	if rec := do(t, h, "POST", "/api/v1/grants", testToken, map[string]any{
		"subject_type": "user_group", "subject_id": ugid,
		"target_type": "server_group", "target_id": sgid,
		"principals": []string{"deploy"}, "max_ttl_seconds": 600, "exec": true, "shell": true,
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create grant: %d (%s)", rec.Code, rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/grants", testToken, nil)
	var grants []grantDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &grants)
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.Subject != "deployers" || g.Target != "web-tier" || g.MaxTTLSeconds != 600 || !g.Exec || !g.Shell {
		t.Fatalf("unexpected grant: %+v", g)
	}
}

func createID(t *testing.T, h http.Handler, method, path string, body any) string {
	t.Helper()
	rec := do(t, h, method, path, testToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%s %s: %d (%s)", method, path, rec.Code, rec.Body)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatalf("%s %s: no id in response", method, path)
	}
	return created.ID
}
