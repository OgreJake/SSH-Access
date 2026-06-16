package api

import (
	"net/http"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/store"
)

// sshLoginInfo returns the pending request's details so the approval page can
// show the user what they are about to approve (source IP + target), letting
// them spot a forged/mismatched request (ADR-021).
func (s *Server) sshLoginInfo(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}
	req, err := s.store.LookupSSHLoginByCode(r.Context(), auth.HashLoginCode(code))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	p, _ := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"source_ip":        req.SourceIP,
		"requested_target": req.RequestedTarget,
		"expires_at":       req.ExpiresAt,
		"approver":         p.Subject,
		"approver_source":  string(p.Source),
	})
}

// sshLoginApprove binds the authenticated Entra identity to a pending SSH login.
// Only SSO (OIDC) identities may approve — the SSH SSO flow resolves to an Entra
// user, and a break-glass admin is not an SSH identity.
func (s *Server) sshLoginApprove(w http.ResponseWriter, r *http.Request) {
	s.sshLoginDecision(w, r, false)
}

func (s *Server) sshLoginDeny(w http.ResponseWriter, r *http.Request) {
	s.sshLoginDecision(w, r, true)
}

func (s *Server) sshLoginDecision(w http.ResponseWriter, r *http.Request, deny bool) {
	p, _ := principalFrom(r.Context())
	if p.Source != auth.SourceOIDC {
		writeError(w, http.StatusForbidden, "SSH login approval requires SSO sign-in")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil || in.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	hash := auth.HashLoginCode(in.Code)

	// Capture target for the audit detail (best effort; lookup also validates
	// the code is still pending before we decide).
	target := ""
	if req, err := s.store.LookupSSHLoginByCode(r.Context(), hash); err == nil {
		target = req.RequestedTarget
	}

	event := "ssh.login.approved"
	decide := s.store.ApproveSSHLogin
	if deny {
		event = "ssh.login.denied"
		decide = s.store.DenySSHLogin
	}
	if err := decide(r.Context(), hash, p.Subject); err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{
		Actor:     p.Subject,
		EventType: event,
		Target:    target,
		Detail:    map[string]string{"target": target},
	})
	status := "approved"
	if deny {
		status = "denied"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}
