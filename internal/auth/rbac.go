// Package auth implements management-plane authentication and authorization
// (ADR-008 Phase A, ADR-020): the permission/role model, Entra group→role
// mapping, argon2id password handling for break-glass admins, and opaque
// session token helpers.
package auth

import (
	"sort"
	"strings"
)

// Permission is a fine-grained management-plane capability. Routes require a
// permission; roles are bundles of permissions.
type Permission string

const (
	PermUsersRead         Permission = "users:read"
	PermUsersWrite        Permission = "users:write"
	PermServersRead       Permission = "servers:read"
	PermServersWrite      Permission = "servers:write"
	PermGroupsRead        Permission = "groups:read"
	PermGroupsWrite       Permission = "groups:write"
	PermGrantsRead        Permission = "grants:read"
	PermGrantsWrite       Permission = "grants:write"
	PermGrantsRecertify   Permission = "grants:recertify"
	PermSessionsRead      Permission = "sessions:read"
	PermSessionsTerminate Permission = "sessions:terminate"
	PermAuditRead         Permission = "audit:read"
	PermRecordingsRead    Permission = "recordings:read"
)

// AllPermissions is the full set (the admin role's bundle).
func AllPermissions() []Permission {
	return []Permission{
		PermUsersRead, PermUsersWrite, PermServersRead, PermServersWrite,
		PermGroupsRead, PermGroupsWrite, PermGrantsRead, PermGrantsWrite,
		PermGrantsRecertify, PermSessionsRead, PermSessionsTerminate,
		PermAuditRead, PermRecordingsRead,
	}
}

// readPermissions is every ":read" capability plus export-style reads (the
// auditor role's bundle: full visibility, no mutations).
func readPermissions() []Permission {
	var out []Permission
	for _, p := range AllPermissions() {
		if strings.HasSuffix(string(p), ":read") {
			out = append(out, p)
		}
	}
	return out
}

// Built-in role names.
const (
	RoleAdmin   = "admin"
	RoleAuditor = "auditor"
)

// builtinRoles maps a role name to its permission set.
var builtinRoles = map[string][]Permission{
	RoleAdmin:   AllPermissions(),
	RoleAuditor: readPermissions(),
}

// RoleExists reports whether a role name is a known built-in role.
func RoleExists(role string) bool {
	_, ok := builtinRoles[role]
	return ok
}

// PermissionsForRoles returns the union of permissions across the given roles.
// Unknown roles contribute nothing.
func PermissionsForRoles(roles ...string) map[Permission]bool {
	perms := make(map[Permission]bool)
	for _, r := range roles {
		for _, p := range builtinRoles[r] {
			perms[p] = true
		}
	}
	return perms
}

// Source identifies how a Principal authenticated.
type Source string

const (
	SourceOIDC       Source = "oidc"        // Entra via the reverse proxy
	SourceBreakGlass Source = "break-glass" // local admin login
)

// Principal is an authenticated management-plane caller.
type Principal struct {
	Subject string // Entra email, or "break-glass:<username>"
	Source  Source
	Roles   []string
	perms   map[Permission]bool
}

// NewPrincipal builds a Principal with permissions resolved from its roles.
func NewPrincipal(subject string, source Source, roles []string) Principal {
	sort.Strings(roles)
	return Principal{Subject: subject, Source: source, Roles: roles, perms: PermissionsForRoles(roles...)}
}

// Can reports whether the principal holds a permission.
func (p Principal) Can(perm Permission) bool { return p.perms[perm] }

// Permissions returns the principal's effective permissions, sorted.
func (p Principal) Permissions() []string {
	out := make([]string, 0, len(p.perms))
	for perm := range p.perms {
		out = append(out, string(perm))
	}
	sort.Strings(out)
	return out
}

// GroupRoleMapping maps Entra group identifiers to management roles. An admin's
// effective roles are the union over their group memberships (ADR-020).
type GroupRoleMapping map[string]string

// RolesForGroups resolves the roles granted by a set of Entra groups, de-duped.
func (m GroupRoleMapping) RolesForGroups(groups []string) []string {
	seen := make(map[string]bool)
	var roles []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if role, ok := m[g]; ok && !seen[role] {
			seen[role] = true
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

// ParseGroupRoleMapping parses "group1:role1,group2:role2" (e.g. from an env
// var) into a GroupRoleMapping. Entries with an unknown role are skipped.
func ParseGroupRoleMapping(s string) GroupRoleMapping {
	m := GroupRoleMapping{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		group, role, ok := strings.Cut(pair, ":")
		group, role = strings.TrimSpace(group), strings.TrimSpace(role)
		if !ok || group == "" || !RoleExists(role) {
			continue
		}
		m[group] = role
	}
	return m
}
