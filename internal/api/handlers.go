package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/proxy"
	"github.com/yourorg/sshbroker/internal/store"
)

// ---------- users ----------

type userDTO struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Source   string `json:"source"`
	Status   string `json:"status"`
	KeyCount int    `json:"key_count"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		out = append(out, userDTO{u.ID, u.Username, u.Email, u.Source, u.Status, u.KeyCount})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Source   string `json:"source"`
		Status   string `json:"status"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	var email *string
	if in.Email != "" {
		email = &in.Email
	}
	id, err := s.store.CreateUser(r.Context(), in.Username, email, in.Source, in.Status)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Status string `json:"status"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Status != "active" && in.Status != "disabled" {
		writeError(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}
	if err := s.store.SetUserStatus(r.Context(), id, in.Status); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": in.Status})
}

func (s *Server) addUserKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	var in struct {
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public key")
		return
	}
	line := proxy.AuthorizedKeyLine(pub) // canonical form authentication looks up
	id, err := s.store.AddUserKey(r.Context(), userID, line, in.Comment)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// ---------- servers ----------

type serverDTO struct {
	ID                string   `json:"id"`
	Hostname          string   `json:"hostname"`
	Address           string   `json:"address"`
	Port              int      `json:"port"`
	AccessMode        string   `json:"access_mode"`
	AllowedPrincipals []string `json:"allowed_principals"`
}

func (s *Server) listServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.store.ListServers(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]serverDTO, 0, len(servers))
	for _, sv := range servers {
		out = append(out, serverDTO{sv.ID, sv.Hostname, sv.Address, sv.Port, sv.AccessMode, sv.AllowedPrincipals})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hostname           string   `json:"hostname"`
		Address            string   `json:"address"`
		Port               int      `json:"port"`
		HostKeyFingerprint string   `json:"host_key_fingerprint"`
		AccessMode         string   `json:"access_mode"`
		AllowedPrincipals  []string `json:"allowed_principals"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Hostname == "" || in.Address == "" {
		writeError(w, http.StatusBadRequest, "hostname and address are required")
		return
	}
	id, err := s.store.CreateServer(r.Context(), store.CreateServerInput{
		Hostname:           in.Hostname,
		Address:            in.Address,
		Port:               in.Port,
		HostKeyFingerprint: in.HostKeyFingerprint,
		AccessMode:         in.AccessMode,
		AllowedPrincipals:  in.AllowedPrincipals,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// ---------- grants ----------

type grantDTO struct {
	ID            string   `json:"id"`
	SubjectType   string   `json:"subject_type"`
	Subject       string   `json:"subject"`
	TargetType    string   `json:"target_type"`
	Target        string   `json:"target"`
	Principals    []string `json:"principals"`
	MaxTTLSeconds int      `json:"max_ttl_seconds"`
	Shell         bool     `json:"shell"`
	Exec          bool     `json:"exec"`
	SFTP          bool     `json:"sftp"`
	PortForward   bool     `json:"port_forward"`
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.ListGrants(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]grantDTO, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantDTO{
			ID: g.ID, SubjectType: g.SubjectType, Subject: g.Subject,
			TargetType: g.TargetType, Target: g.Target, Principals: g.Principals,
			MaxTTLSeconds: int(g.MaxTTL / time.Second),
			Shell:         g.Shell, Exec: g.Exec, SFTP: g.SFTP, PortForward: g.PortForward,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SubjectType   string   `json:"subject_type"`
		SubjectID     string   `json:"subject_id"`
		TargetType    string   `json:"target_type"`
		TargetID      string   `json:"target_id"`
		Principals    []string `json:"principals"`
		MaxTTLSeconds int      `json:"max_ttl_seconds"`
		Shell         bool     `json:"shell"`
		Exec          bool     `json:"exec"`
		SFTP          bool     `json:"sftp"`
		PortForward   bool     `json:"port_forward"`
		Recording     string   `json:"recording"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.SubjectID == "" || in.TargetID == "" || len(in.Principals) == 0 {
		writeError(w, http.StatusBadRequest, "subject_id, target_id, and principals are required")
		return
	}
	id, err := s.store.CreateGrant(r.Context(), store.CreateGrantInput{
		SubjectType: in.SubjectType, SubjectID: in.SubjectID,
		TargetType: in.TargetType, TargetID: in.TargetID,
		Principals: in.Principals, MaxTTL: time.Duration(in.MaxTTLSeconds) * time.Second,
		AllowShell: in.Shell, AllowExec: in.Exec, AllowSFTP: in.SFTP, AllowPortForward: in.PortForward,
		Recording: in.Recording,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// ---------- groups ----------

func (s *Server) createUserGroup(w http.ResponseWriter, r *http.Request) {
	s.createGroup(w, r, s.store.CreateUserGroup)
}

type groupDTO struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Members int    `json:"members"`
}

func (s *Server) listUserGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListUserGroups(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.writeGroups(w, groups)
}

func (s *Server) listServerGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListServerGroups(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.writeGroups(w, groups)
}

func (s *Server) writeGroups(w http.ResponseWriter, groups []store.GroupRow) {
	out := make([]groupDTO, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupDTO{g.ID, g.Name, g.Members})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createServerGroup(w http.ResponseWriter, r *http.Request) {
	s.createGroup(w, r, s.store.CreateServerGroup)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, create func(ctx context.Context, name string) (string, error)) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	id, err := create(r.Context(), in.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) addUserGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	var in struct {
		UserID string `json:"user_id"`
	}
	if err := decode(r, &in); err != nil || in.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if err := s.store.AddUserToGroup(r.Context(), groupID, in.UserID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (s *Server) addServerGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	var in struct {
		ServerID string `json:"server_id"`
	}
	if err := decode(r, &in); err != nil || in.ServerID == "" {
		writeError(w, http.StatusBadRequest, "server_id is required")
		return
	}
	if err := s.store.AddServerToGroup(r.Context(), groupID, in.ServerID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

// ---------- sessions & audit ----------

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListRecentSessions(r.Context(), queryLimit(r))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	type dto struct {
		ID         string     `json:"id"`
		StartedAt  time.Time  `json:"started_at"`
		EndedAt    *time.Time `json:"ended_at"`
		Subject    string     `json:"subject"`
		Server     string     `json:"server"`
		Login      string     `json:"login"`
		SourceIP   string     `json:"source_ip"`
		CertSerial *int64     `json:"cert_serial"`
		BytesIn    int64      `json:"bytes_in"`
		BytesOut   int64      `json:"bytes_out"`
		ExitStatus *int       `json:"exit_status"`
		Recording  string     `json:"recording"`
	}
	out := make([]dto, 0, len(sessions))
	for _, x := range sessions {
		out = append(out, dto{x.ID, x.StartedAt, x.EndedAt, x.SubjectLabel, x.ServerLabel, x.Login,
			x.SourceIP, x.CertSerial, x.BytesIn, x.BytesOut, x.ExitStatus, x.Recording})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListRecentAudit(r.Context(), queryLimit(r))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	type dto struct {
		Seq       int64     `json:"seq"`
		At        time.Time `json:"at"`
		Actor     string    `json:"actor"`
		EventType string    `json:"event_type"`
		Target    string    `json:"target"`
		Detail    any       `json:"detail"`
	}
	out := make([]dto, 0, len(entries))
	for _, e := range entries {
		var detail any
		if len(e.Detail) > 0 {
			detail = e.Detail // json.RawMessage passes through as-is
		}
		out = append(out, dto{e.Seq, e.At, e.Actor, e.EventType, e.Target, detail})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.VerifyAuditChain(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "verified": n, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "verified": n})
}

func queryLimit(r *http.Request) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 50
}
