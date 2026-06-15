package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"

	"crypto/rand"
	"encoding/base64"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/config"
	"github.com/yourorg/sshbroker/internal/proxy"
	"github.com/yourorg/sshbroker/internal/store"
)

// runAdmin implements `broker admin <subcommand>`. It needs only
// SSHBROKER_DATABASE_URL (not the full broker config), so it can be run as a
// management tool independent of a running broker.
func runAdmin(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		adminUsage()
		return nil
	}
	dsn := os.Getenv("SSHBROKER_DATABASE_URL")
	if dsn == "" {
		return errors.New("SSHBROKER_DATABASE_URL is required")
	}
	ctx := context.Background()
	st, err := store.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "add-user":
		return cmdAddUser(ctx, st, rest)
	case "add-key":
		return cmdAddKey(ctx, st, rest)
	case "add-service-account":
		return cmdAddServiceAccount(ctx, st, rest)
	case "add-server":
		return cmdAddServer(ctx, st, rest)
	case "create-user-group":
		return cmdCreateGroup(ctx, st, rest, "user")
	case "create-server-group":
		return cmdCreateGroup(ctx, st, rest, "server")
	case "add-user-to-group":
		return cmdAddUserToGroup(ctx, st, rest)
	case "add-server-to-group":
		return cmdAddServerToGroup(ctx, st, rest)
	case "add-grant":
		return cmdAddGrant(ctx, st, rest)
	case "set-user-status":
		return cmdSetUserStatus(ctx, st, rest)
	case "list-users":
		return cmdListUsers(ctx, st, rest)
	case "list-servers":
		return cmdListServers(ctx, st, rest)
	case "list-grants":
		return cmdListGrants(ctx, st, rest)
	case "terminate-session":
		return cmdTerminateSession(ctx, st, rest)
	case "recertify-grant":
		return cmdRecertifyGrant(ctx, st, rest)
	case "set-local-admin":
		return cmdSetLocalAdmin(ctx, st, rest)
	default:
		adminUsage()
		return fmt.Errorf("unknown admin command %q", cmd)
	}
}

func adminUsage() {
	fmt.Fprint(os.Stderr, `usage: broker admin <command> [flags]

Identities:
  add-user             -username NAME [-email E] [-source local|entra] [-status active|disabled]
  add-key              -user NAME -key-file PATH | -key "ssh-... " [-comment C]
  add-service-account  -name NAME  -key-file PATH | -key "ssh-... " [-status active|disabled]
  set-user-status      -username NAME -status active|disabled

Targets:
  add-server           -hostname H -address A [-port 22] [-host-key-fp FP] [-principals a,b] [-access-mode cert]

Groups & RBAC:
  create-user-group    -name NAME
  create-server-group  -name NAME
  add-user-to-group    -user NAME -group NAME
  add-server-to-group  -server HOSTNAME -group NAME
  add-grant            (-subject-user NAME | -subject-group NAME)
                       (-server HOSTNAME | -server-group NAME)
                       -principals a,b [-ttl 5m] [-shell] [-exec] [-sftp]
                       [-recording metadata|full]

Inspect:
  list-users | list-servers | list-grants

All commands need SSHBROKER_DATABASE_URL.
`)
}

// ---------- identities ----------

func cmdAddUser(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-user", flag.ContinueOnError)
	username := fs.String("username", "", "username (required)")
	email := fs.String("email", "", "email (optional)")
	source := fs.String("source", "local", "local|entra")
	status := fs.String("status", "active", "active|disabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("-username is required")
	}
	var emailPtr *string
	if *email != "" {
		emailPtr = email
	}
	id, err := st.CreateUser(ctx, *username, emailPtr, *source, *status)
	if err != nil {
		return err
	}
	fmt.Printf("created user %q (id %s)\n", *username, id)
	return nil
}

func cmdAddKey(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-key", flag.ContinueOnError)
	user := fs.String("user", "", "username (required)")
	keyFile := fs.String("key-file", "", "path to a public key (.pub) file")
	keyInline := fs.String("key", "", "public key line, e.g. \"ssh-ed25519 AAAA...\"")
	comment := fs.String("comment", "", "comment/label for the key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return errors.New("-user is required")
	}
	line, err := pubKeyLine(*keyInline, *keyFile)
	if err != nil {
		return err
	}
	uid, err := resolveUser(ctx, st, *user)
	if err != nil {
		return err
	}
	id, err := st.AddUserKey(ctx, uid, line, *comment)
	if err != nil {
		return err
	}
	fmt.Printf("added key to user %q (key id %s)\n", *user, id)
	return nil
}

func cmdAddServiceAccount(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-service-account", flag.ContinueOnError)
	name := fs.String("name", "", "service account name (required)")
	keyFile := fs.String("key-file", "", "path to a public key (.pub) file")
	keyInline := fs.String("key", "", "public key line")
	status := fs.String("status", "active", "active|disabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-name is required")
	}
	line, err := pubKeyLine(*keyInline, *keyFile)
	if err != nil {
		return err
	}
	id, err := st.CreateServiceAccount(ctx, *name, line, *status)
	if err != nil {
		return err
	}
	fmt.Printf("created service account %q (id %s)\n", *name, id)
	return nil
}

func cmdSetUserStatus(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("set-user-status", flag.ContinueOnError)
	username := fs.String("username", "", "username (required)")
	status := fs.String("status", "", "active|disabled (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *status == "" {
		return errors.New("-username and -status are required")
	}
	uid, err := resolveUser(ctx, st, *username)
	if err != nil {
		return err
	}
	if err := st.SetUserStatus(ctx, uid, *status); err != nil {
		return err
	}
	fmt.Printf("user %q is now %s\n", *username, *status)
	return nil
}

// ---------- targets ----------

func cmdAddServer(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-server", flag.ContinueOnError)
	hostname := fs.String("hostname", "", "alias used in login+host (required)")
	address := fs.String("address", "", "dial address/host (required)")
	port := fs.Int("port", 22, "ssh port")
	fp := fs.String("host-key-fp", "", "target host key fingerprint SHA256:... (empty = dev accept-and-log)")
	principals := fs.String("principals", "", "comma-separated server login allowlist (enforced if set)")
	accessMode := fs.String("access-mode", "cert", "cert|jit_key|stored_cred")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hostname == "" || *address == "" {
		return errors.New("-hostname and -address are required")
	}
	id, err := st.CreateServer(ctx, store.CreateServerInput{
		Hostname:           *hostname,
		Address:            *address,
		Port:               *port,
		HostKeyFingerprint: *fp,
		AccessMode:         *accessMode,
		AllowedPrincipals:  csv(*principals),
	})
	if err != nil {
		return err
	}
	fmt.Printf("created server %q → %s:%d (id %s)\n", *hostname, *address, *port, id)
	return nil
}

// ---------- groups & RBAC ----------

func cmdCreateGroup(ctx context.Context, st *store.Store, args []string, kind string) error {
	fs := flag.NewFlagSet("create-"+kind+"-group", flag.ContinueOnError)
	name := fs.String("name", "", "group name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-name is required")
	}
	var id string
	var err error
	if kind == "user" {
		id, err = st.CreateUserGroup(ctx, *name)
	} else {
		id, err = st.CreateServerGroup(ctx, *name)
	}
	if err != nil {
		return err
	}
	fmt.Printf("created %s group %q (id %s)\n", kind, *name, id)
	return nil
}

func cmdAddUserToGroup(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-user-to-group", flag.ContinueOnError)
	user := fs.String("user", "", "username (required)")
	group := fs.String("group", "", "user-group name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" || *group == "" {
		return errors.New("-user and -group are required")
	}
	uid, err := resolveUser(ctx, st, *user)
	if err != nil {
		return err
	}
	gid, err := st.UserGroupIDByName(ctx, *group)
	if err != nil {
		return fmt.Errorf("user group %q: %w", *group, err)
	}
	if err := st.AddUserToGroup(ctx, gid, uid); err != nil {
		return err
	}
	fmt.Printf("added %q to user group %q\n", *user, *group)
	return nil
}

func cmdAddServerToGroup(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-server-to-group", flag.ContinueOnError)
	server := fs.String("server", "", "server hostname (required)")
	group := fs.String("group", "", "server-group name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *group == "" {
		return errors.New("-server and -group are required")
	}
	srv, err := st.GetServerByHostname(ctx, *server)
	if err != nil {
		return fmt.Errorf("server %q: %w", *server, err)
	}
	gid, err := st.ServerGroupIDByName(ctx, *group)
	if err != nil {
		return fmt.Errorf("server group %q: %w", *group, err)
	}
	if err := st.AddServerToGroup(ctx, gid, srv.ID); err != nil {
		return err
	}
	fmt.Printf("added %q to server group %q\n", *server, *group)
	return nil
}

func cmdAddGrant(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add-grant", flag.ContinueOnError)
	subjUser := fs.String("subject-user", "", "subject is this user")
	subjGroup := fs.String("subject-group", "", "subject is this user group")
	server := fs.String("server", "", "target is this server (hostname)")
	serverGroup := fs.String("server-group", "", "target is this server group")
	principals := fs.String("principals", "", "comma-separated logins this grant permits (required)")
	ttl := fs.Duration("ttl", 5*time.Minute, "certificate max TTL")
	shell := fs.Bool("shell", false, "allow interactive shell")
	exec := fs.Bool("exec", false, "allow exec")
	sftp := fs.Bool("sftp", false, "allow sftp")
	recording := fs.String("recording", "metadata", "metadata|full")
	reviewBy := fs.String("review-by", "", "recertification due date YYYY-MM-DD (default: now + review interval)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	subjectType, subjectID, err := resolveSubject(ctx, st, *subjUser, *subjGroup)
	if err != nil {
		return err
	}
	targetType, targetID, err := resolveTarget(ctx, st, *server, *serverGroup)
	if err != nil {
		return err
	}
	if csv(*principals) == nil {
		return errors.New("-principals is required (comma-separated)")
	}
	review, err := resolveReviewBy(*reviewBy)
	if err != nil {
		return err
	}
	id, err := st.CreateGrant(ctx, store.CreateGrantInput{
		SubjectType: subjectType, SubjectID: subjectID,
		TargetType: targetType, TargetID: targetID,
		Principals: csv(*principals), MaxTTL: *ttl,
		AllowShell: *shell, AllowExec: *exec, AllowSFTP: *sftp,
		Recording: *recording, ReviewBy: &review,
	})
	if err != nil {
		return err
	}
	fmt.Printf("created grant %s:%s → %s:%s for principals %v (id %s)\n",
		subjectType, subjectLabel(*subjUser, *subjGroup), targetType, targetLabel(*server, *serverGroup), csv(*principals), id)
	return nil
}

// ---------- inspect ----------

func cmdListUsers(ctx context.Context, st *store.Store, _ []string) error {
	users, err := st.ListUsers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tEMAIL\tSOURCE\tSTATUS\tKEYS")
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", u.Username, dash(u.Email), u.Source, u.Status, u.KeyCount)
	}
	return tw.Flush()
}

func cmdListServers(ctx context.Context, st *store.Store, _ []string) error {
	servers, err := st.ListServers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tADDRESS\tPORT\tMODE\tALLOWED-PRINCIPALS")
	for _, s := range servers {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", s.Hostname, s.Address, s.Port, s.AccessMode, strings.Join(s.AllowedPrincipals, ","))
	}
	return tw.Flush()
}

func cmdListGrants(ctx context.Context, st *store.Store, _ []string) error {
	grants, err := st.ListGrants(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUBJECT\tTARGET\tPRINCIPALS\tTTL\tCAPS\tREVIEW\tSTATUS")
	for _, g := range grants {
		review := "—"
		if g.ReviewBy != nil {
			review = g.ReviewBy.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s:%s\t%s:%s\t%s\t%s\t%s\t%s\t%s\n",
			g.SubjectType, g.Subject, g.TargetType, g.Target,
			strings.Join(g.Principals, ","), g.MaxTTL, caps(g), review, grantReviewStatus(g.ReviewBy, now))
	}
	return tw.Flush()
}

// grantReviewStatus mirrors the API's review classification (ADR-017).
func grantReviewStatus(reviewBy *time.Time, now time.Time) string {
	if reviewBy == nil {
		return "none"
	}
	day := 24 * time.Hour
	due := reviewBy.UTC().Truncate(day)
	today := now.UTC().Truncate(day)
	switch {
	case due.Before(today):
		return "overdue"
	case due.Before(today.Add(14 * day)):
		return "due-soon"
	default:
		return "ok"
	}
}

// resolveReviewBy parses an optional YYYY-MM-DD date, defaulting to
// now + the configured review interval (ADR-017).
func resolveReviewBy(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now().AddDate(0, 0, config.ReviewIntervalDays()), nil
	}
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid -review-by %q (want YYYY-MM-DD): %w", raw, err)
	}
	return t, nil
}

func cmdRecertifyGrant(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("recertify-grant", flag.ContinueOnError)
	id := fs.String("id", "", "grant id to recertify (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("-id is required")
	}
	review := time.Now().AddDate(0, 0, config.ReviewIntervalDays())
	if err := st.UpdateGrant(ctx, *id, store.UpdateGrantInput{ReviewBy: &review}); err != nil {
		return err
	}
	_ = st.AppendAudit(ctx, store.AuditEvent{
		Actor: "admin-cli", EventType: "grant.recertified", Target: *id,
		Detail: map[string]string{"grant_id": *id, "review_by": review.Format("2006-01-02")},
	})
	fmt.Printf("recertified grant %s; next review %s\n", *id, review.Format("2006-01-02"))
	return nil
}

// ---------- helpers ----------

func pubKeyLine(inline, file string) (string, error) {
	var raw []byte
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read key file: %w", err)
		}
		raw = b
	case inline != "":
		raw = []byte(inline)
	default:
		return "", errors.New("provide -key or -key-file")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	return proxy.AuthorizedKeyLine(pub), nil
}

func resolveUser(ctx context.Context, st *store.Store, username string) (string, error) {
	uid, err := st.UserIDByUsername(ctx, username)
	if err != nil {
		return "", fmt.Errorf("user %q: %w", username, err)
	}
	return uid, nil
}

func resolveSubject(ctx context.Context, st *store.Store, user, group string) (string, string, error) {
	switch {
	case user != "" && group != "":
		return "", "", errors.New("specify only one of -subject-user / -subject-group")
	case user != "":
		id, err := resolveUser(ctx, st, user)
		return "user", id, err
	case group != "":
		id, err := st.UserGroupIDByName(ctx, group)
		if err != nil {
			return "", "", fmt.Errorf("user group %q: %w", group, err)
		}
		return "user_group", id, nil
	default:
		return "", "", errors.New("one of -subject-user / -subject-group is required")
	}
}

func resolveTarget(ctx context.Context, st *store.Store, server, group string) (string, string, error) {
	switch {
	case server != "" && group != "":
		return "", "", errors.New("specify only one of -server / -server-group")
	case server != "":
		srv, err := st.GetServerByHostname(ctx, server)
		if err != nil {
			return "", "", fmt.Errorf("server %q: %w", server, err)
		}
		return "server", srv.ID, nil
	case group != "":
		id, err := st.ServerGroupIDByName(ctx, group)
		if err != nil {
			return "", "", fmt.Errorf("server group %q: %w", group, err)
		}
		return "server_group", id, nil
	default:
		return "", "", errors.New("one of -server / -server-group is required")
	}
}

func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func caps(g store.GrantRow) string {
	var c []string
	if g.Shell {
		c = append(c, "shell")
	}
	if g.Exec {
		c = append(c, "exec")
	}
	if g.SFTP {
		c = append(c, "sftp")
	}
	if len(c) == 0 {
		return "(none)"
	}
	return strings.Join(c, ",")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func subjectLabel(user, group string) string {
	if user != "" {
		return user
	}
	return group
}

func targetLabel(server, group string) string {
	if server != "" {
		return server
	}
	return group
}

func cmdTerminateSession(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("terminate-session", flag.ContinueOnError)
	id := fs.String("id", "", "session id to terminate (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("-id is required")
	}
	if err := st.RequestSessionTermination(ctx, *id); err != nil {
		return err
	}
	fmt.Printf("flagged session %s for termination (the broker kills it on its next revocation poll)\n", *id)
	return nil
}

func cmdSetLocalAdmin(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("set-local-admin", flag.ContinueOnError)
	username := fs.String("username", "", "break-glass admin username (required)")
	password := fs.String("password", "", "password (omit with -generate to auto-create one)")
	generate := fs.Bool("generate", false, "generate a strong random password and print it once")
	role := fs.String("role", "admin", "role for this admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("-username is required")
	}
	if !auth.RoleExists(*role) {
		return fmt.Errorf("unknown role %q", *role)
	}
	pw := *password
	if *generate {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		pw = base64.RawURLEncoding.EncodeToString(buf)
	}
	if pw == "" {
		return errors.New("provide -password or -generate")
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := st.UpsertLocalAdmin(ctx, *username, hash, *role); err != nil {
		return err
	}
	fmt.Printf("break-glass admin %q set (role %s)\n", *username, *role)
	if *generate {
		fmt.Printf("generated password (store securely, shown once): %s\n", pw)
	}
	return nil
}
