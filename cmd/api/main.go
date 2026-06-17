// Command api runs the broker's management API (ADR-005). It is intentionally
// a separate process from the SSH front door so the management plane can have
// its own network exposure and trust boundary. It needs only the database, an
// API token, and a listen address.
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

	"github.com/yourorg/sshbroker/internal/api"
	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/config"
	"github.com/yourorg/sshbroker/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("api startup failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	logger := newLogger(getenv("SSHBROKER_LOG_LEVEL", "info"))
	slog.SetDefault(logger)

	dsn := os.Getenv("SSHBROKER_DATABASE_URL")
	if dsn == "" {
		return errors.New("SSHBROKER_DATABASE_URL is required")
	}
	token := os.Getenv("SSHBROKER_API_TOKEN")
	if token == "" {
		return errors.New("SSHBROKER_API_TOKEN is required (the API refuses to start unauthenticated)")
	}
	addr := getenv("SSHBROKER_API_ADDR", ":8081")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	apiSrv, err := api.New(st, logger, token)
	if err != nil {
		return err
	}
	if dir := os.Getenv("SSHBROKER_RECORDING_DIR"); dir != "" {
		apiSrv.SetRecordingDir(dir)
		logger.Info("session-recording downloads enabled", "dir", dir)
	}
	if base := os.Getenv("SSHBROKER_ASCIINEMA_PUBLIC_URL"); base != "" {
		apiSrv.SetRecordingURLBase(base)
		logger.Info("asciinema viewer origin set", "url", base)
	}
	apiSrv.SetReviewIntervalDays(config.ReviewIntervalDays())

	authCfg := api.AuthConfig{
		OIDCEmailHeader:   os.Getenv("SSHBROKER_OIDC_EMAIL_HEADER"),
		OIDCGroupsHeader:  os.Getenv("SSHBROKER_OIDC_GROUPS_HEADER"),
		OIDCGroupsDelim:   os.Getenv("SSHBROKER_OIDC_GROUPS_DELIM"),
		ProxySecretHeader: os.Getenv("SSHBROKER_PROXY_SECRET_HEADER"),
		ProxySecret:       os.Getenv("SSHBROKER_PROXY_SECRET"),
		GroupRoles:        auth.ParseGroupRoleMapping(os.Getenv("SSHBROKER_OIDC_GROUP_ROLES")),
		SessionAbsolute:   getenvDuration("SSHBROKER_ADMIN_SESSION_ABSOLUTE", 12*time.Hour),
		SessionIdle:       getenvDuration("SSHBROKER_ADMIN_SESSION_IDLE", time.Hour),
		CookieSecure:      os.Getenv("SSHBROKER_ADMIN_COOKIE_INSECURE") == "",
		AllowBearerToken:  os.Getenv("SSHBROKER_ALLOW_BEARER_TOKEN") != "", // retired by default; opt-in for emergency/cutover
	}
	apiSrv.SetAuthConfig(authCfg)
	apiSrv.SetAuthURL(getenv("SSHBROKER_AUTH_URL", ""))
	if authCfg.AllowBearerToken {
		logger.Warn("static bearer token auth is ENABLED (SSHBROKER_ALLOW_BEARER_TOKEN) — disable once SSO/break-glass is verified")
	}
	if authCfg.ProxySecret == "" {
		logger.Warn("OIDC header trust disabled: SSHBROKER_PROXY_SECRET not set (break-glass + bearer only)")
	} else {
		logger.Info("management auth configured", "oidc_header_trust", true,
			"group_role_mappings", len(authCfg.GroupRoles))
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("management API listening", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}
