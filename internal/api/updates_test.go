package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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

func TestAPITerminateSession(t *testing.T) {
	h, st := testAPI(t)
	uid := createID(t, h, "POST", "/api/v1/users", map[string]any{"username": "alice"})
	sess, err := st.CreateSession(testCtx(), store.SessionStart{
		SubjectType: "user", SubjectID: &uid, SubjectLabel: "alice", ServerLabel: "web01",
		LoginPrincipal: "ec2-user", AccessMode: "cert", SourceIP: "10.0.0.1", Recording: "metadata",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if rec := do(t, h, "POST", "/api/v1/sessions/"+sess+"/terminate", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("terminate: %d (%s)", rec.Code, rec.Body)
	}
	doomed, err := st.SessionsToTerminate(testCtx(), []string{sess})
	if err != nil || len(doomed) != 1 || doomed[0] != sess {
		t.Fatalf("expected session flagged for termination, got %v (err %v)", doomed, err)
	}
	if rec := do(t, h, "POST", "/api/v1/sessions/00000000-0000-0000-0000-000000000000/terminate", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("terminate unknown: %d, want 404", rec.Code)
	}
}

func TestAPIGetRecording(t *testing.T) {
	h, st := testAPI(t)
	uid := createID(t, h, "POST", "/api/v1/users", map[string]any{"username": "alice"})
	sess, err := st.CreateSession(testCtx(), store.SessionStart{
		SubjectType: "user", SubjectID: &uid, SubjectLabel: "alice", ServerLabel: "web01",
		LoginPrincipal: "ec2-user", AccessMode: "cert", SourceIP: "10.0.0.1", Recording: "full",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// No recording ref yet → 404 (uses the shared handler, no dir configured).
	if rec := do(t, h, "GET", "/api/v1/sessions/"+sess+"/recording", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no-ref recording: %d, want 404", rec.Code)
	}

	// Now write a recording file and set the ref, with a recording-dir-enabled server.
	dir := t.TempDir()
	ref := sess + ".cast"
	if err := os.WriteFile(filepath.Join(dir, ref), []byte("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n"), 0o600); err != nil {
		t.Fatalf("write cast: %v", err)
	}
	if err := st.SetSessionRecordingRef(testCtx(), sess, ref); err != nil {
		t.Fatalf("set ref: %v", err)
	}
	srv, err := New(st, discardLogger(), testToken)
	if err != nil {
		t.Fatalf("new api: %v", err)
	}
	srv.SetRecordingDir(dir)
	h2 := srv.Handler()

	rec := do(t, h2, "GET", "/api/v1/sessions/"+sess+"/recording", testToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download recording: %d (%s)", rec.Code, rec.Body)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Fatal("expected attachment header")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"o","hello"`)) && !bytes.Contains(rec.Body.Bytes(), []byte("hello")) {
		t.Fatalf("recording body missing content: %s", rec.Body)
	}

	// Path traversal in the ref is neutralized (filepath.Base) → not found.
	if err := st.SetSessionRecordingRef(testCtx(), sess, "../../etc/passwd"); err != nil {
		t.Fatalf("set ref traversal: %v", err)
	}
	if rec := do(t, h2, "GET", "/api/v1/sessions/"+sess+"/recording", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("traversal ref should 404 (base=passwd not in dir), got %d", rec.Code)
	}
}

func TestAPIGrantReviewLifecycle(t *testing.T) {
	h, _ := testAPI(t)
	ugid := createID(t, h, "POST", "/api/v1/user-groups", map[string]any{"name": "deployers"})
	sgid := createID(t, h, "POST", "/api/v1/server-groups", map[string]any{"name": "web-tier"})

	// Create with an explicit overdue review date.
	gid := createID(t, h, "POST", "/api/v1/grants", map[string]any{
		"subject_type": "user_group", "subject_id": ugid,
		"target_type": "server_group", "target_id": sgid,
		"principals": []string{"deploy"}, "max_ttl_seconds": 300, "exec": true,
		"review_by": "2020-01-01",
	})
	getStatus := func() (string, *grantDTO) {
		rec := do(t, h, "GET", "/api/v1/grants", testToken, nil)
		var gs []grantDTO
		_ = json.Unmarshal(rec.Body.Bytes(), &gs)
		for i := range gs {
			if gs[i].ID == gid {
				return gs[i].ReviewStatus, &gs[i]
			}
		}
		return "", nil
	}
	if st, g := getStatus(); st != "overdue" || g.ReviewBy == nil {
		t.Fatalf("expected overdue with a date, got %q (%+v)", st, g)
	}

	// Recertify pushes it out to "ok".
	rec := do(t, h, "POST", "/api/v1/grants/"+gid+"/recertify", testToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("recertify: %d (%s)", rec.Code, rec.Body)
	}
	if st, _ := getStatus(); st != "ok" {
		t.Fatalf("after recertify expected ok, got %q", st)
	}

	// A grant created without a date defaults to a future review (status ok).
	gid2 := createID(t, h, "POST", "/api/v1/grants", map[string]any{
		"subject_type": "user_group", "subject_id": ugid,
		"target_type": "server_group", "target_id": sgid,
		"principals": []string{"ec2-user"}, "max_ttl_seconds": 300, "exec": true,
	})
	rec = do(t, h, "GET", "/api/v1/grants", testToken, nil)
	var gs []grantDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &gs)
	var found *grantDTO
	for i := range gs {
		if gs[i].ID == gid2 {
			found = &gs[i]
		}
	}
	if found == nil || found.ReviewBy == nil || found.ReviewStatus != "ok" {
		t.Fatalf("defaulted grant should have a future review date, got %+v", found)
	}

	// Recertify of an unknown grant → 404.
	if rec := do(t, h, "POST", "/api/v1/grants/00000000-0000-0000-0000-000000000000/recertify", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("recertify unknown: %d, want 404", rec.Code)
	}
}

func TestReviewStatus(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	mk := func(s string) *time.Time { d, _ := time.Parse("2006-01-02", s); return &d }
	cases := []struct {
		in   *time.Time
		want string
	}{
		{nil, "none"},
		{mk("2026-06-10"), "overdue"},
		{mk("2026-06-20"), "due_soon"},
		{mk("2026-09-20"), "ok"},
	}
	for _, c := range cases {
		if got := reviewStatus(c.in, now); got != c.want {
			t.Errorf("reviewStatus(%v) = %q, want %q", c.in, got, c.want)
		}
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
