package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword(hash, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("verify good password: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(hash, "wrong password")
	if err != nil || ok {
		t.Fatalf("verify wrong password should fail: ok=%v err=%v", ok, err)
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password should error")
	}
	if _, err := VerifyPassword("not-a-phc-string", "x"); err != ErrInvalidHash {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}
}

func TestRolePermissions(t *testing.T) {
	admin := NewPrincipal("a@x.com", SourceOIDC, []string{RoleAdmin})
	if !admin.Can(PermUsersWrite) || !admin.Can(PermAuditRead) || !admin.Can(PermSessionsTerminate) {
		t.Fatal("admin should hold all permissions")
	}

	auditor := NewPrincipal("r@x.com", SourceOIDC, []string{RoleAuditor})
	if !auditor.Can(PermAuditRead) || !auditor.Can(PermUsersRead) || !auditor.Can(PermGrantsRead) {
		t.Fatal("auditor should hold read permissions")
	}
	if auditor.Can(PermUsersWrite) || auditor.Can(PermGrantsWrite) || auditor.Can(PermSessionsTerminate) {
		t.Fatal("auditor must not hold any write/mutation permission")
	}

	// Multiple roles union; unknown roles contribute nothing.
	multi := NewPrincipal("m@x.com", SourceOIDC, []string{RoleAuditor, "nonexistent"})
	if multi.Can(PermUsersWrite) {
		t.Fatal("unknown role must not grant permissions")
	}
}

func TestGroupRoleMapping(t *testing.T) {
	m := ParseGroupRoleMapping("sg-admins:admin, sg-audit:auditor, sg-bogus:notarole, :admin")
	if len(m) != 2 {
		t.Fatalf("expected 2 valid mappings, got %d: %+v", len(m), m)
	}
	roles := m.RolesForGroups([]string{"sg-audit", "sg-admins", "sg-unmapped"})
	if len(roles) != 2 {
		t.Fatalf("expected admin+auditor, got %v", roles)
	}
	// De-dupes when multiple groups map to the same role.
	m2 := ParseGroupRoleMapping("g1:auditor,g2:auditor")
	if got := m2.RolesForGroups([]string{"g1", "g2"}); len(got) != 1 || got[0] != RoleAuditor {
		t.Fatalf("expected single auditor role, got %v", got)
	}
}
