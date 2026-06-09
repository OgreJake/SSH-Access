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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/ca"
	"github.com/yourorg/sshbroker/internal/config"
	"github.com/yourorg/sshbroker/internal/secrets"
	"github.com/yourorg/sshbroker/internal/signer"
	"github.com/yourorg/sshbroker/internal/signer/kmsca"
	"github.com/yourorg/sshbroker/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
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
	_ = issuer // consumed by the SSH proxy in Phase 2.
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

	// Health server.
	srv := newHealthServer(cfg.HealthAddr, st)
	go func() {
		logger.Info("health server listening", "addr", cfg.HealthAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server error", "err", err)
			stop()
		}
	}()

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
