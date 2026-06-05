// Package config loads broker configuration from the environment.
//
// All settings are read from SSHBROKER_* environment variables so the same
// binary can run unchanged across dev and prod; only the backends differ
// (file-based signer/secret store in dev, AWS KMS in prod — see ADR-006/009).
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

// Environment selects dev vs prod behaviour.
type Environment string

const (
	EnvDev  Environment = "dev"
	EnvProd Environment = "prod"
)

// Config holds all runtime settings. Phase 0 wires the foundations; the SSH
// proxy listener and KMS backends are added in later phases behind the same
// interfaces referenced here.
type Config struct {
	Environment Environment
	LogLevel    string // debug|info|warn|error

	// HealthAddr is the address for the HTTP health/admin listener.
	HealthAddr string

	// DatabaseURL is the PostgreSQL DSN/URL.
	DatabaseURL string

	// CA signer (dev file backend). In prod this is replaced by the AWS KMS
	// backend behind signer.Authority (ADR-006).
	CAKeyPath       string
	CAKeyPassphrase string

	// Secret store (dev file backend). In prod this is KMS envelope
	// encryption behind secrets.Store (ADR-009).
	SecretStoreDir string
	SecretStoreKey []byte // 32-byte AES-256 key (decoded from base64)

	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		Environment:     Environment(getenv("SSHBROKER_ENV", string(EnvDev))),
		LogLevel:        getenv("SSHBROKER_LOG_LEVEL", "info"),
		HealthAddr:      getenv("SSHBROKER_HEALTH_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("SSHBROKER_DATABASE_URL"),
		CAKeyPath:       getenv("SSHBROKER_CA_KEY_PATH", "dev/ca_key"),
		CAKeyPassphrase: os.Getenv("SSHBROKER_CA_KEY_PASSPHRASE"),
		SecretStoreDir:  getenv("SSHBROKER_SECRET_STORE_DIR", "dev/secrets"),
	}

	switch c.Environment {
	case EnvDev, EnvProd:
	default:
		return nil, fmt.Errorf("invalid SSHBROKER_ENV %q (want dev|prod)", c.Environment)
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("invalid SSHBROKER_LOG_LEVEL %q", c.LogLevel)
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("SSHBROKER_DATABASE_URL is required")
	}

	rawKey := os.Getenv("SSHBROKER_SECRET_STORE_KEY")
	if rawKey == "" {
		return nil, fmt.Errorf("SSHBROKER_SECRET_STORE_KEY is required (base64-encoded 32 bytes; `make gen-secret-key`)")
	}
	key, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		return nil, fmt.Errorf("SSHBROKER_SECRET_STORE_KEY is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("SSHBROKER_SECRET_STORE_KEY must decode to 32 bytes, got %d", len(key))
	}
	c.SecretStoreKey = key

	timeout := getenv("SSHBROKER_SHUTDOWN_TIMEOUT", "10s")
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid SSHBROKER_SHUTDOWN_TIMEOUT %q: %w", timeout, err)
	}
	c.ShutdownTimeout = d

	return c, nil
}

// IsProd reports whether the broker is running in the production environment.
func (c *Config) IsProd() bool { return c.Environment == EnvProd }

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
