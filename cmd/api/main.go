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
