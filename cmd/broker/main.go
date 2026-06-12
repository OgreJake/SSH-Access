// Command broker is the SSH access broker.
//
// Phase 0 wires the foundations together: it loads configuration, connects to
// PostgreSQL, initializes the CA signer and the secret store behind their
// interfaces, and serves an HTTP health endpoint. The SSH proxy listener and
// certificate issuance arrive in Phase 1/2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/ca"
	"github.com/yourorg/sshbroker/internal/config"
	"github.com/yourorg/sshbroker/internal/model"
	"github.com/yourorg/sshbroker/internal/proxy"
	"github.com/yourorg/sshbroker/internal/secrets"
	"github.com/yourorg/sshbroker/internal/signer"
	"github.com/yourorg/sshbroker/internal/signer/kmsca"
	"github.com/yourorg/sshbroker/internal/store"
)

func main() {
	// `broker admin <command>` is a management CLI that needs only the database,
	// not the full broker config, so it is dispatched before run().
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		if err := runAdmin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var printCAKey bool
	flag.BoolVar(&printCAKey, "print-ca-key", false,
		"print the broker CA public key as a TrustedUserCAKeys line and exit")
	var verifyAudit bool
	flag.BoolVar(&verifyAudit, "verify-audit", false,
		"verify the audit log hash chain and exit (non-zero on tampering)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting broker", "env", cfg.Environment)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// CA signer: dev file key, or AWS KMS in production (ADR-006). Both
	// satisfy signer.Authority, so nothing downstream changes.
	auth, err := newAuthority(ctx, cfg)
	if err != nil {
		return err
	}

	// Utility: print the CA public key (for targets' TrustedUserCAKeys) and exit.
	if printCAKey {
		fmt.Println(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(auth.PublicKey()))))
		return nil
	}

	logger.Info("loaded CA",
		"backend", cfg.CABackend,
		"fingerprint", ssh.FingerprintSHA256(auth.PublicKey()),
		"type", auth.PublicKey().Type(),
	)

	// Secret store (dev: file; prod: KMS envelope encryption — ADR-009).
	secretStore, err := secrets.NewFileStore(cfg.SecretStoreDir, cfg.SecretStoreKey)
	if err != nil {
		return err
	}
	_ = secretStore // wired into legacy-mode connections in Phase 4.

	// Certificate issuer (policy layer over the signer, ADR-007). The
	// CounterAllocator is dev-only; a Postgres-sequence allocator replaces it
	// when persistence lands.
	issuer, err := ca.NewIssuer(auth, ca.NewCounterAllocator(0), cfg.CertMaxTTL,
		ca.WithClockSkew(cfg.CertClockSkew))
	if err != nil {
		return err
	}
	logger.Info("certificate issuer ready",
		"max_ttl", cfg.CertMaxTTL.String(),
		"source_pin", sourcePinStatus(cfg.BrokerSourceAddr),
	)

	// Database.
	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	logger.Info("connected to database")

	// Utility: verify the audit hash chain and exit.
	if verifyAudit {
		n, vErr := st.VerifyAuditChain(ctx)
		if vErr != nil {
			return fmt.Errorf("audit verification FAILED after %d records: %w", n, vErr)
		}
		fmt.Printf("audit chain OK: %d records verified\n", n)
		return nil
	}

	// SSH front door (Phase 2). Authenticate, resolve+authorize the target,
	// mint a cert, dial the target, and proxy the session.
	authn, err := loadAuthenticator(cfg, st, logger)
	if err != nil {
		return err
	}
	authz, err := loadAuthorizer(cfg, st, logger)
	if err != nil {
		return err
	}
	var recorder proxy.Recorder = proxy.NopRecorder{}
	if cfg.RecordingDir != "" {
		fr, ferr := proxy.NewFileRecorder(cfg.RecordingDir)
		if ferr != nil {
			return ferr
		}
		recorder = fr
		logger.Info("full session recording enabled", "dir", cfg.RecordingDir)
	}

	sshSrv, err := proxy.New(proxy.Config{
		HostKeyPath:      cfg.SSHHostKeyPath,
		Authenticator:    authn,
		Authorizer:       authz,
		Issuer:           issuer,
		Auditor:          auditAdapter{st: st, logger: logger},
		BrokerSourceAddr: cfg.BrokerSourceAddr,
		Logger:           logger,
		Recorder:         recorder,
	})
	if err != nil {
		return err
	}
	sshLn, err := net.Listen("tcp", cfg.SSHListenAddr)
	if err != nil {
		return fmt.Errorf("ssh listen on %s: %w", cfg.SSHListenAddr, err)
	}
	go func() {
		logger.Info("ssh front door listening",
			"addr", cfg.SSHListenAddr,
			"host_key", ssh.FingerprintSHA256(sshSrv.HostPublicKey()),
		)
		if err := sshSrv.Serve(ctx, sshLn); err != nil {
			logger.Error("ssh server error", "err", err)
			stop()
		}
	}()

	// Health server.
	srv := newHealthServer(cfg.HealthAddr, st)
	go func() {
		logger.Info("health server listening", "addr", cfg.HealthAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server error", "err", err)
			stop()
		}
	}()

	// Revocation reaper: terminate live sessions whose subject was disabled or
	// that were explicitly flagged for termination (ADR-016).
	go runReaper(ctx, sshSrv, st, cfg.RevocationInterval, logger)

	logger.Info("broker ready")
	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
	return nil
}

func newHealthServer(addr string, st *store.Store) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// storeKeyLookup adapts the database store to proxy.KeyLookup, translating
// store.ErrNotFound into a nil identity (the proxy's "no such key" signal).
type storeKeyLookup struct{ st *store.Store }

func (l storeKeyLookup) AuthnByKey(ctx context.Context, line string) (*proxy.ResolvedIdentity, error) {
	id, err := l.st.AuthnByKey(ctx, line)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &proxy.ResolvedIdentity{
		Subject: model.SubjectType(id.SubjectType),
		ID:      id.ID,
		Label:   id.Label,
		Active:  id.Active,
	}, nil
}

func loadAuthenticator(cfg *config.Config, st *store.Store, logger *slog.Logger) (proxy.Authenticator, error) {
	if cfg.AuthBackend == "db" {
		logger.Info("authentication backend: db")
		return proxy.NewDBAuthenticator(storeKeyLookup{st: st}, logger), nil
	}
	authn, err := proxy.LoadAuthorizedUsers(cfg.AuthorizedUsersPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("no authorized users file; starting with zero registered users",
				"path", cfg.AuthorizedUsersPath)
			return proxy.NewMemoryAuthenticator(), nil
		}
		return nil, err
	}
	logger.Info("loaded authorized users", "count", authn.Len(), "path", cfg.AuthorizedUsersPath)
	return authn, nil
}

// runReaper periodically asks the store which of this broker's live sessions
// must die (subject disabled or explicitly flagged) and terminates them,
// recording a session.killed audit event for each (ADR-016).
func runReaper(ctx context.Context, srv *proxy.Server, st *store.Store, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			live := srv.LiveSessions()
			if len(live) == 0 {
				continue
			}
			byID := make(map[string]proxy.SessionInfo, len(live))
			ids := make([]string, 0, len(live))
			for _, s := range live {
				byID[s.ID] = s
				ids = append(ids, s.ID)
			}
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			doomed, err := st.SessionsToTerminate(qctx, ids)
			cancel()
			if err != nil {
				logger.Error("reaper query failed", "err", err)
				continue
			}
			for _, id := range doomed {
				if srv.Kill(id) {
					info := byID[id]
					logger.Info("session terminated", "session_id", id, "subject", info.SubjectLabel, "host", info.Host)
					_ = st.AppendAudit(ctx, store.AuditEvent{
						Actor:     info.SubjectLabel,
						EventType: "session.killed",
						Target:    info.Host,
						Detail:    map[string]string{"session_id": id, "login": info.Login},
					})
				}
			}
		}
	}
}

// auditAdapter implements proxy.Auditor over the database store: it writes
// session rows and appends to the hash-chained audit log.
type auditAdapter struct {
	st     *store.Store
	logger *slog.Logger
}

func (a auditAdapter) StartSession(ctx context.Context, r proxy.SessionRecord) (string, error) {
	var serial *int64
	if r.CertSerial != 0 {
		v := int64(r.CertSerial)
		serial = &v
	}
	id, err := a.st.CreateSession(ctx, store.SessionStart{
		SubjectType:    r.SubjectType,
		SubjectLabel:   r.SubjectLabel,
		ServerLabel:    r.Host,
		LoginPrincipal: r.Login,
		AccessMode:     r.AccessMode,
		SourceIP:       r.SourceIP,
		CertSerial:     serial,
		Recording:      "metadata",
	})
	if err != nil {
		return "", err
	}
	if err := a.st.AppendAudit(ctx, store.AuditEvent{
		Actor: r.SubjectLabel, EventType: "session.start", Target: r.Host,
		Detail: map[string]string{"login": r.Login, "address": r.Address, "source_ip": r.SourceIP, "session_id": id},
	}); err != nil {
		a.logger.Error("append session.start audit", "err", err.Error())
	}
	return id, nil
}

func (a auditAdapter) EndSession(ctx context.Context, id string, o proxy.SessionOutcome) error {
	if id == "" {
		return nil
	}
	if err := a.st.EndSession(ctx, id, o.BytesIn, o.BytesOut, o.ExitStatus); err != nil {
		return err
	}
	if o.RecordingRef != "" {
		if err := a.st.SetSessionRecordingRef(ctx, id, o.RecordingRef); err != nil {
			a.logger.Error("set recording ref", "session_id", id, "err", err.Error())
		}
	}
	detail := map[string]string{
		"session_id": id,
		"bytes_in":   strconv.FormatInt(o.BytesIn, 10),
		"bytes_out":  strconv.FormatInt(o.BytesOut, 10),
	}
	if o.ExitStatus != nil {
		detail["exit_status"] = strconv.Itoa(*o.ExitStatus)
	}
	return a.st.AppendAudit(ctx, store.AuditEvent{Actor: "system", EventType: "session.end", Target: id, Detail: detail})
}

func (a auditAdapter) RecordEvent(ctx context.Context, e proxy.Event) {
	if err := a.st.AppendAudit(ctx, store.AuditEvent{Actor: e.Actor, EventType: e.Type, Target: e.Target, Detail: e.Detail}); err != nil {
		a.logger.Error("append audit", "type", e.Type, "err", err.Error())
	}
}

// storeAuthzBackend adapts the database store to proxy.AuthzBackend.
type storeAuthzBackend struct{ st *store.Store }

func (b storeAuthzBackend) ServerByHostname(ctx context.Context, hostname string) (*proxy.ResolvedServer, error) {
	srv, err := b.st.GetServerByHostname(ctx, hostname)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &proxy.ResolvedServer{
		ID:                 srv.ID,
		Address:            srv.Address,
		Port:               srv.Port,
		HostKeyFingerprint: srv.HostKeyFingerprint,
		AllowedPrincipals:  srv.AllowedPrincipals,
	}, nil
}

func (b storeAuthzBackend) GroupsForUser(ctx context.Context, userID string) ([]string, error) {
	return b.st.ListGroupsForUser(ctx, userID)
}

func (b storeAuthzBackend) GroupsForServer(ctx context.Context, serverID string) ([]string, error) {
	return b.st.ListGroupsForServer(ctx, serverID)
}

func (b storeAuthzBackend) MatchingGrants(ctx context.Context, subjectType, subjectID string, userGroupIDs []string, serverID string, serverGroupIDs []string) ([]proxy.ResolvedGrant, error) {
	gs, err := b.st.MatchingGrants(ctx, subjectType, subjectID, userGroupIDs, serverID, serverGroupIDs)
	if err != nil {
		return nil, err
	}
	out := make([]proxy.ResolvedGrant, len(gs))
	for i, g := range gs {
		out[i] = proxy.ResolvedGrant{
			Principals: g.Principals,
			MaxTTL:     g.MaxTTL,
			AllowShell: g.AllowShell,
			AllowExec:  g.AllowExec,
			AllowSFTP:  g.AllowSFTP,
			Recording:  g.Recording,
		}
	}
	return out, nil
}

func loadAuthorizer(cfg *config.Config, st *store.Store, logger *slog.Logger) (proxy.Authorizer, error) {
	if cfg.AuthzBackend == "db" {
		logger.Info("authorization backend: db")
		return proxy.NewDBAuthorizer(storeAuthzBackend{st: st}, logger), nil
	}
	authz, err := proxy.LoadTargets(cfg.TargetsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("no targets file; all target requests will be denied",
				"path", cfg.TargetsPath)
			return proxy.NewMemoryAuthorizer(), nil
		}
		return nil, err
	}
	logger.Info("loaded targets policy", "path", cfg.TargetsPath)
	return authz, nil
}

func newAuthority(ctx context.Context, cfg *config.Config) (signer.Authority, error) {
	switch cfg.CABackend {
	case "kms":
		return kmsca.New(ctx, cfg.KMSKeyID, kmsca.WithRegion(cfg.AWSRegion))
	default:
		return signer.NewFileAuthority(cfg.CAKeyPath, cfg.CAKeyPassphrase)
	}
}

func sourcePinStatus(addr string) string {
	if addr == "" {
		return "disabled"
	}
	return addr
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
