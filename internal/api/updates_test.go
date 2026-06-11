package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/yourorg/sshbroker/internal/store"
)

func testCtx() context.Context { return context.Background() }

func storeAuditEvent(i int) store.AuditEvent {
	return store.AuditEvent{
		Actor: "tester", EventType: "test.event", Target: "t",
		Detail: map[string]string{"i": strconv.Itoa(i)},
	}
}

func TestAPIUpdateUser(t *testing.T) {
	h, _ := testAPI(t)
	uid := createID(t, h, "POST", "/api/v1/users", map[string]any{"username": "alice", "email": "a@x.com"})

	// Edit email + status in one PATCH.
	if rec := do(t, h, "PATCH", "/api/v1/users/"+uid, testToken, map[string]any{
		"email": "alice@example.com", "status": "disabled",
	}); rec.Code != http.StatusOK {
		t.Fatalf("patch user: %d (%s)", rec.Code, rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/users", testToken, nil)
	var users []userDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users) != 1 || users[0].Email != "alice@example.com" || users[0].Status != "disabled" {
		t.Fatalf("user not updated: %+v", users)
	}

	// Unknown id → 404.
	if rec := do(t, h, "PATCH", "/api/v1/users/00000000-0000-0000-0000-000000000000", testToken,
		map[string]any{"status": "active"}); rec.Code != http.StatusNotFound {
		t.Fatalf("patch unknown user: %d, want 404", rec.Code)
	}
}

func TestAPIUpdateServer(t *testing.T) {
	h, _ := testAPI(t)
	sid := createID(t, h, "POST", "/api/v1/servers", map[string]any{
		"hostname": "web01", "address": "10.0.0.5", "port": 22, "allowed_principals": []string{"deploy"},
	})

	if rec := do(t, h, "PATCH", "/api/v1/servers/"+sid, testToken, map[string]any{
		"address": "10.0.0.99", "port": 2222, "allowed_principals": []string{"deploy", "ec2-user"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("patch server: %d (%s)", rec.Code, rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/servers", testToken, nil)
	var servers []serverDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &servers)
	if len(servers) != 1 || servers[0].Address != "10.0.0.99" || servers[0].Port != 2222 ||
		len(servers[0].AllowedPrincipals) != 2 {
		t.Fatalf("server not updated: %+v", servers)
	}
}

func TestAPIUpdateAndDeleteGrant(t *testing.T) {
	h, _ := testAPI(t)
	ugid := createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "deployers"})
	sgid := createID(t, h, "POST", "/api/v1/server-groups", map[string]any{"name": "web-tier"})
	gid := createID(t, h, "POST", "/api/v1/grants", map[string]any{
		"subject_type": "user_group", "subject_id": ugid,
		"target_type": "server_group", "target_id": sgid,
		"principals": []string{"deploy"}, "max_ttl_seconds": 300, "exec": true,
	})

	// Edit: widen principals, bump TTL, add shell, drop exec.
	if rec := do(t, h, "PATCH", "/api/v1/grants/"+gid, testToken, map[string]any{
		"principals": []string{"deploy", "ec2-user"}, "max_ttl_seconds": 900,
		"shell": true, "exec": false,
	}); rec.Code != http.StatusOK {
		t.Fatalf("patch grant: %d (%s)", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/grants", testToken, nil)
	var grants []grantDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &grants)
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.MaxTTLSeconds != 900 || !g.Shell || g.Exec || len(g.Principals) != 2 {
		t.Fatalf("grant not updated: %+v", g)
	}

	// Delete.
	if rec := do(t, h, "DELETE", "/api/v1/grants/"+gid, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete grant: %d", rec.Code)
	}
	rec = do(t, h, "GET", "/api/v1/grants", testToken, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &grants)
	if len(grants) != 0 {
		t.Fatalf("grant should be gone, got %d", len(grants))
	}

	// Delete again → 404.
	if rec := do(t, h, "DELETE", "/api/v1/grants/"+gid, testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing grant: %d, want 404", rec.Code)
	}
}

func TestAPIDeleteUser(t *testing.T) {
	h, st := testAPI(t)
	uid := createID(t, h, "POST", "/api/v1/users", map[string]any{"username": "alice"})
	if rec := do(t, h, "POST", "/api/v1/users/"+uid+"/keys", testToken, map[string]any{"public_key": genKeyLine(t)}); rec.Code != http.StatusCreated {
		t.Fatalf("add key: %d", rec.Code)
	}
	ugid := createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "deployers"})
	if rec := do(t, h, "POST", "/api/v1/user-groups/"+ugid+"/members", testToken, map[string]any{"user_id": uid}); rec.Code != http.StatusOK {
		t.Fatalf("add member: %d", rec.Code)
	}
	sid := createID(t, h, "POST", "/api/v1/servers", map[string]any{"hostname": "web01", "address": "10.0.0.5", "port": 22})
	// A direct user→server grant that should be cleaned up on delete.
	createID(t, h, "POST", "/api/v1/grants", map[string]any{
		"subject_type": "user", "subject_id": uid, "target_type": "server", "target_id": sid,
		"principals": []string{"deploy"}, "max_ttl_seconds": 300, "exec": true,
	})

	if rec := do(t, h, "DELETE", "/api/v1/users/"+uid, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete user: %d (%s)", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/users", testToken, nil)
	var users []userDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users) != 0 {
		t.Fatalf("user should be gone, got %d", len(users))
	}
	rec = do(t, h, "GET", "/api/v1/grants", testToken, nil)
	var grants []grantDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &grants)
	if len(grants) != 0 {
		t.Fatalf("direct grant should be cleaned up, got %d", len(grants))
	}
	var keyCount int
	_ = st.Pool.QueryRow(testCtx(), "SELECT count(*) FROM user_public_keys").Scan(&keyCount)
	if keyCount != 0 {
		t.Fatalf("keys should cascade, got %d", keyCount)
	}
	if rec := do(t, h, "DELETE", "/api/v1/users/"+uid, testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("re-delete: %d, want 404", rec.Code)
	}
}

func TestAPIDeleteServerPreservesSessions(t *testing.T) {
	h, st := testAPI(t)
	sid := createID(t, h, "POST", "/api/v1/servers", map[string]any{"hostname": "web01", "address": "10.0.0.5", "port": 22})

	if _, err := st.CreateSession(testCtx(), store.SessionStart{
		SubjectType: "user", SubjectLabel: "alice", ServerLabel: "web01",
		LoginPrincipal: "deploy", AccessMode: "cert", SourceIP: "10.0.0.9", Recording: "metadata",
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	ugid := createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "deployers"})
	createID(t, h, "POST", "/api/v1/grants", map[string]any{
		"subject_type": "user_group", "subject_id": ugid, "target_type": "server", "target_id": sid,
		"principals": []string{"deploy"}, "max_ttl_seconds": 300, "exec": true,
	})

	if rec := do(t, h, "DELETE", "/api/v1/servers/"+sid, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete server: %d (%s)", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/servers", testToken, nil)
	var servers []serverDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &servers)
	if len(servers) != 0 {
		t.Fatalf("server should be gone, got %d", len(servers))
	}
	rec = do(t, h, "GET", "/api/v1/grants", testToken, nil)
	var grants []grantDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &grants)
	if len(grants) != 0 {
		t.Fatalf("direct grant should be cleaned up, got %d", len(grants))
	}
	rec = do(t, h, "GET", "/api/v1/sessions", testToken, nil)
	var sessions []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &sessions)
	if len(sessions) != 1 || sessions[0]["server"] != "web01" {
		t.Fatalf("session should be preserved with its label, got %+v", sessions)
	}
}

func TestAPIAuditExport(t *testing.T) {
	h, st := testAPI(t)
	// Seed a couple of audit entries directly via the store.
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(testCtx(), storeAuditEvent(i)); err != nil {
			t.Fatalf("append audit: %v", err)
		}
	}
	rec := do(t, h, "GET", "/api/v1/audit/export", testToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Fatal("expected Content-Disposition attachment header")
	}
	var entries []auditDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &entries)
	if len(entries) != 3 {
		t.Fatalf("expected 3 exported entries, got %d", len(entries))
	}
	// Export is oldest-first (chain order).
	if entries[0].Seq > entries[2].Seq {
		t.Fatal("export should be oldest-first")
	}
}
