package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/ca"
)

// Server is the broker's SSH front door. It authenticates the user, resolves
// and authorizes the requested target, mints a certificate, dials the target,
// and proxies the session.
type Server struct {
	hostSigner       ssh.Signer
	auth             Authenticator
	authz            Authorizer
	issuer           *ca.Issuer
	auditor          Auditor
	brokerSourceAddr string
	logger           *slog.Logger
	serverVersion    string
	sessions         *sessionRegistry
	recorder         Recorder
}

// Config configures the Server.
type Config struct {
	HostKeyPath      string
	Authenticator    Authenticator
	Authorizer       Authorizer
	Issuer           *ca.Issuer
	Auditor          Auditor // optional; defaults to NopAuditor
	BrokerSourceAddr string
	Logger           *slog.Logger
	ServerVersion    string
	Recorder         Recorder // optional; defaults to NopRecorder (ADR-011)
}

// New loads the host key and constructs a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Authenticator == nil {
		return nil, fmt.Errorf("authenticator is required")
	}
	if cfg.Authorizer == nil {
		return nil, fmt.Errorf("authorizer is required")
	}
	if cfg.Issuer == nil {
		return nil, fmt.Errorf("issuer is required")
	}
	pem, err := os.ReadFile(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read host key %q: %w", cfg.HostKeyPath, err)
	}
	hostSigner, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	version := cfg.ServerVersion
	if version == "" {
		version = "SSH-2.0-sshbroker"
	}
	auditor := cfg.Auditor
	if auditor == nil {
		auditor = NopAuditor
	}
	recorder := cfg.Recorder
	if recorder == nil {
		recorder = NopRecorder{}
	}
	return &Server{
		hostSigner:       hostSigner,
		auth:             cfg.Authenticator,
		authz:            cfg.Authorizer,
		issuer:           cfg.Issuer,
		auditor:          auditor,
		brokerSourceAddr: cfg.BrokerSourceAddr,
		logger:           logger,
		serverVersion:    version,
		sessions:         newSessionRegistry(),
		recorder:         recorder,
	}, nil
}

// HostPublicKey returns the server's host public key (for client known_hosts).
func (s *Server) HostPublicKey() ssh.PublicKey { return s.hostSigner.PublicKey() }

// Serve accepts connections until ctx is cancelled or the listener errors.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) serverConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: s.serverVersion,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			id, err := s.auth.AuthenticatePublicKey(key)
			if err != nil {
				s.logger.Info("public key not registered",
					"remote", conn.RemoteAddr().String(),
					"request", conn.User(),
					"offered_key", ssh.FingerprintSHA256(key),
				)
				return nil, ErrUnauthorized
			}
			s.logger.Debug("public key accepted",
				"subject", id.Label,
				"offered_key", ssh.FingerprintSHA256(key),
			)
			return &ssh.Permissions{Extensions: map[string]string{
				"subject_type":  string(id.Subject),
				"subject_id":    id.ID,
				"subject_label": id.Label,
			}}, nil
		},
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *Server) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()
	remote := nConn.RemoteAddr().String()

	sConn, chans, reqs, err := ssh.NewServerConn(nConn, s.serverConfig())
	if err != nil {
		s.logger.Info("ssh handshake failed", "remote", remote, "err", err.Error())
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)

	id := identityFrom(sConn.Permissions)
	sourceIP := hostOnly(remote)
	log := s.logger.With("remote", remote, "subject", id.Label, "request", sConn.User())

	// Resolve and authorize the target, then dial it. Failures are reported to
	// the user over the first session channel rather than dropping silently.
	var (
		target    *ssh.Client
		decision  *Decision
		setupErr  string
		serial    uint64
		sessionID string
	)
	spec, perr := ParseTarget(sConn.User())
	switch {
	case perr != nil:
		setupErr = "sshbroker: " + perr.Error()
		s.auditor.RecordEvent(ctx, Event{Actor: id.Label, Type: "session.rejected", Target: sConn.User(),
			Detail: map[string]string{"reason": perr.Error(), "source_ip": sourceIP}})
	default:
		decision, err = s.authz.Authorize(ctx, id, spec)
		if err != nil {
			log.Info("authorization denied", "host", spec.Host, "requested", spec.RequestedLogin, "reason", err.Error())
			setupErr = fmt.Sprintf("sshbroker: not authorized to reach %q", spec.Host)
			s.auditor.RecordEvent(ctx, Event{Actor: id.Label, Type: "authz.denied", Target: spec.Host,
				Detail: map[string]string{"requested": spec.RequestedLogin, "reason": err.Error(), "source_ip": sourceIP}})
		} else if target, serial, err = s.connectTarget(ctx, id, spec, decision); err != nil {
			log.Warn("target connection failed", "host", spec.Host, "err", err.Error())
			setupErr = fmt.Sprintf("sshbroker: could not connect to %q", spec.Host)
			s.auditor.RecordEvent(ctx, Event{Actor: id.Label, Type: "target.unreachable", Target: spec.Host,
				Detail: map[string]string{"login": decision.Login, "address": decision.Address, "source_ip": sourceIP}})
		} else {
			log.Info("brokering session", "host", spec.Host, "requested", spec.RequestedLogin, "login", decision.Login, "address", decision.Address)
			sessionID, err = s.auditor.StartSession(ctx, SessionRecord{
				SubjectType:  string(id.Subject),
				SubjectLabel: id.Label,
				Host:         spec.Host,
				Address:      decision.Address,
				Login:        decision.Login,
				AccessMode:   "cert",
				SourceIP:     sourceIP,
				CertSerial:   serial,
			})
			if err != nil {
				log.Error("record session start", "err", err.Error())
			}
			if sessionID != "" {
				// Register so the revocation reaper can terminate this session
				// (ADR-016). Closing both connections unwinds the copy loops.
				userConn, tgt := sConn, target
				s.sessions.add(SessionInfo{
					ID: sessionID, SubjectType: string(id.Subject), SubjectID: id.ID,
					SubjectLabel: id.Label, Host: spec.Host, Login: decision.Login, Started: time.Now(),
				}, func() {
					_ = userConn.Close()
					if tgt != nil {
						_ = tgt.Close()
					}
				})
				defer s.sessions.remove(sessionID)
			}
		}
	}
	if target != nil {
		defer target.Close()
	}

	// Full session recording (ADR-011): opt-in per grant. Output stream only.
	var (
		recording    Recording = nopRecording{}
		recordingRef string
	)
	if sessionID != "" && decision != nil && decision.Recording == "full" {
		rec, ref, rerr := s.recorder.Open(sessionID, 0, 0)
		if rerr != nil {
			log.Error("open recording", "err", rerr.Error())
		} else {
			recording = rec
			recordingRef = ref
			defer recording.Close()
			log.Info("recording session", "session_id", sessionID, "ref", ref)
		}
	}

	var (
		bytesIn, bytesOut int64
		exit              *int
	)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		if setupErr != "" {
			rejectWithNotice(nc, setupErr)
			continue
		}
		in, out, ex := s.handleSession(nc, target, decision, recording)
		bytesIn += in
		bytesOut += out
		if ex != nil {
			exit = ex
		}
	}

	if sessionID != "" {
		if err := s.auditor.EndSession(ctx, sessionID, SessionOutcome{BytesIn: bytesIn, BytesOut: bytesOut, ExitStatus: exit, RecordingRef: recordingRef}); err != nil {
			log.Error("record session end", "err", err.Error())
		}
	}
	log.Info("session closed", "bytes_in", bytesIn, "bytes_out", bytesOut)
}

func (s *Server) handleSession(nc ssh.NewChannel, target *ssh.Client, d *Decision, rec Recording) (int64, int64, *int) {
	userCh, userReqs, err := nc.Accept()
	if err != nil {
		s.logger.Warn("accept user channel", "err", err.Error())
		return 0, 0, nil
	}
	targetCh, targetReqs, err := target.OpenChannel("session", nil)
	if err != nil {
		_, _ = io.WriteString(userCh, "sshbroker: failed to open target session\r\n")
		sendExitStatus(userCh, 1)
		_ = userCh.Close()
		return 0, 0, nil
	}
	return s.proxySession(userCh, targetCh, userReqs, targetReqs, d, rec)
}

// rejectWithNotice accepts a session only to deliver a one-line error, then
// closes it with a non-zero exit status.
func rejectWithNotice(nc ssh.NewChannel, msg string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go func() {
		defer ch.Close()
		for req := range reqs {
			switch req.Type {
			case "shell", "exec":
				_ = req.Reply(true, nil)
				_, _ = io.WriteString(ch, msg+"\r\n")
				sendExitStatus(ch, 1)
				return
			case "pty-req", "env", "window-change":
				_ = req.Reply(true, nil)
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()
}

func identityFrom(p *ssh.Permissions) Identity {
	id := Identity{Label: "unknown"}
	if p == nil || p.Extensions == nil {
		return id
	}
	id.Subject = subjectType(p.Extensions["subject_type"])
	id.ID = p.Extensions["subject_id"]
	if l := p.Extensions["subject_label"]; l != "" {
		id.Label = l
	}
	return id
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
