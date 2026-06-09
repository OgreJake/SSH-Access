package proxy

import (
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// proxySession wires a user-side session channel to a target-side session
// channel: data in both directions, request forwarding (with capability
// gating on the user→target side), and exit-status propagation.
func (s *Server) proxySession(user, target ssh.Channel, userReqs, targetReqs <-chan *ssh.Request, d *Decision) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, user) // user stdin → target
		_ = target.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(user, target) // target stdout → user
		_ = user.CloseWrite()
	}()
	go func() { _, _ = io.Copy(user.Stderr(), target.Stderr()) }()

	// user → target requests, gated by the grant's capabilities.
	go func() {
		for r := range userReqs {
			s.forwardUserRequest(r, target, d)
		}
	}()

	// target → user requests (exit-status, exit-signal, …). Draining to
	// completion guarantees the exit status reaches the user before close.
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for r := range targetReqs {
			ok, _ := user.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}()

	wg.Wait()
	_ = target.Close()
	<-targetDone
	_ = user.Close()
}

// forwardUserRequest gates and forwards a user→target session request.
func (s *Server) forwardUserRequest(r *ssh.Request, target ssh.Channel, d *Decision) {
	allowed := true
	switch r.Type {
	case "shell":
		allowed = d.AllowShell
	case "exec":
		allowed = d.AllowExec
	case "subsystem":
		allowed = d.AllowSFTP && isSFTPSubsystem(r.Payload)
	}
	if !allowed {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
		s.logger.Info("blocked channel request", "type", r.Type)
		return
	}
	ok, err := target.SendRequest(r.Type, r.WantReply, r.Payload)
	if err != nil {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
		return
	}
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

// isSFTPSubsystem reports whether a "subsystem" request payload names sftp.
func isSFTPSubsystem(payload []byte) bool {
	var p struct{ Name string }
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return false
	}
	return p.Name == "sftp"
}
