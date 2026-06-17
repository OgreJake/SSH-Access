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
	"strconv"
	"strings"
	"time"
)

// ReviewIntervalDays is the default grant recertification cadence in days,
// from SSHBROKER_REVIEW_INTERVAL_DAYS (default 90 — quarterly, ADR-017). It is
// the interval applied when a grant is created without an explicit review date
// and when a grant is recertified.
func ReviewIntervalDays() int {
	if v := os.Getenv("SSHBROKER_REVIEW_INTERVAL_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 90
}

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

	// CA signer backend: "file" (dev) or "kms" (production, ADR-006).
	CABackend string

	// Identity backend for authentication: "file" (dev authorized_users) or
	// "db" (PostgreSQL user/service-account keys, Phase 3).
	AuthBackend string

	// Authorization backend: "file" (dev targets.json) or "db" (PostgreSQL
	// servers/groups/grants RBAC, Phase 3).
	AuthzBackend string

	// CA signer (dev file backend). In prod this is replaced by the AWS KMS
	// backend behind signer.Authority (ADR-006).
	CAKeyPath       string
	CAKeyPassphrase string

	// KMS CA backend settings (used when CABackend == "kms").
	KMSKeyID  string // key id, ARN, or alias of the asymmetric signing key
	AWSRegion string // optional; otherwise from environment / instance metadata

	// Secret store (dev file backend). In prod this is KMS envelope
	// encryption behind secrets.Store (ADR-009).
	SecretStoreDir string
	SecretStoreKey []byte // 32-byte AES-256 key (decoded from base64)

	// Certificate issuance policy (ADR-007).
	CertMaxTTL       time.Duration // hard cap on every certificate's lifetime
	CertClockSkew    time.Duration // tolerance subtracted from ValidAfter
	BrokerSourceAddr string        // if set, pin issued certs to this source address/CIDR

	// SSH front door (Phase 2). The broker terminates user SSH here.
	SSHListenAddr       string // address the broker's SSH server listens on
	SSHHostKeyPath      string // broker host key (generate with `make gen-host-key`)
	AuthorizedUsersPath string // dev authorized_keys-format file of registered users
	TargetsPath         string // dev JSON policy: targets + grants (Phase 2b)

	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration

	// RevocationInterval is how often the broker checks live sessions for
	// termination (account disabled or explicit kill); ADR-016.
	RevocationInterval time.Duration

	// RecordingDir, when set, enables full session recording to .cast files in
	// this directory for grants with recording policy "full" (ADR-011).
	RecordingDir string

	// AsciinemaServerURL, when set, makes the broker upload each finished .cast
	// to that asciinema server and store the returned playback URL (ADR-011).
	AsciinemaServerURL string
	// AsciinemaBin is the asciinema CLI to invoke (default "asciinema").
	AsciinemaBin string

	// DeleteLocalRecordingAfterUpload removes the local .cast file once it has
	// been successfully uploaded to the asciinema server and its URL recorded
	// (ADR-011). Default true: the uploaded copy on the (encrypted) asciinema
	// volume becomes the system of record, so the broker does not retain a
	// plaintext copy. Has no effect when upload is disabled.
	DeleteLocalRecordingAfterUpload bool

	// AuthURL is the public base URL of the oauth2-proxy auth server
	// (e.g. https://auth.disdev.net). Returned to the SPA via the whoami
	// endpoint so the frontend can construct SSO URLs without hardcoding
	// the auth domain (SSHBROKER_AUTH_URL).
	AuthURL string

	// BrowserLoginURLBase, when set, enables SSH browser SSO/MFA (ADR-021): the
	// public origin of the broker UI/API behind oauth2-proxy, used to build the
	// approval URL (e.g. https://broker.example.com). Empty disables the flow
	// (publickey only).
	BrowserLoginURLBase string
	// BrowserLoginTimeout bounds how long the SSH front door waits for browser
	// approval, and is also the one-time code's lifetime (default 2m).
	BrowserLoginTimeout time.Duration
	// JITProvision auto-creates a broker user (with no grants) for an unknown
	// authenticated Entra subject on SSH login (default true).
	JITProvision bool
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
		CABackend:       getenv("SSHBROKER_CA_BACKEND", "file"),
		AuthBackend:     getenv("SSHBROKER_AUTH_BACKEND", "file"),
		AuthzBackend:    getenv("SSHBROKER_AUTHZ_BACKEND", "file"),
		KMSKeyID:        os.Getenv("SSHBROKER_KMS_KEY_ID"),
		AWSRegion:       os.Getenv("SSHBROKER_AWS_REGION"),
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

	switch c.CABackend {
	case "file":
	case "kms":
		if c.KMSKeyID == "" {
			return nil, fmt.Errorf("SSHBROKER_KMS_KEY_ID is required when SSHBROKER_CA_BACKEND=kms")
		}
	default:
		return nil, fmt.Errorf("invalid SSHBROKER_CA_BACKEND %q (want file|kms)", c.CABackend)
	}

	switch c.AuthBackend {
	case "file", "db":
	default:
		return nil, fmt.Errorf("invalid SSHBROKER_AUTH_BACKEND %q (want file|db)", c.AuthBackend)
	}

	switch c.AuthzBackend {
	case "file", "db":
	default:
		return nil, fmt.Errorf("invalid SSHBROKER_AUTHZ_BACKEND %q (want file|db)", c.AuthzBackend)
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

	revInterval := getenv("SSHBROKER_REVOCATION_INTERVAL", "10s")
	c.RevocationInterval, err = time.ParseDuration(revInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid SSHBROKER_REVOCATION_INTERVAL %q: %w", revInterval, err)
	}

	c.RecordingDir = os.Getenv("SSHBROKER_RECORDING_DIR")
	c.AsciinemaServerURL = os.Getenv("SSHBROKER_ASCIINEMA_SERVER_URL")
	c.AsciinemaBin = getenv("SSHBROKER_ASCIINEMA_BIN", "asciinema")
	c.DeleteLocalRecordingAfterUpload = os.Getenv("SSHBROKER_DELETE_LOCAL_RECORDING_AFTER_UPLOAD") != "false"

	c.AuthURL = os.Getenv("SSHBROKER_AUTH_URL")

	c.BrowserLoginURLBase = os.Getenv("SSHBROKER_SSH_LOGIN_URL_BASE")
	c.BrowserLoginTimeout = 2 * time.Minute
	if v := os.Getenv("SSHBROKER_SSH_LOGIN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.BrowserLoginTimeout = d
		}
	}
	c.JITProvision = os.Getenv("SSHBROKER_SSH_JIT_PROVISION") != "false"

	maxTTL := getenv("SSHBROKER_CERT_MAX_TTL", "5m")
	c.CertMaxTTL, err = time.ParseDuration(maxTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid SSHBROKER_CERT_MAX_TTL %q: %w", maxTTL, err)
	}
	if c.CertMaxTTL <= 0 {
		return nil, fmt.Errorf("SSHBROKER_CERT_MAX_TTL must be positive")
	}

	skew := getenv("SSHBROKER_CERT_CLOCK_SKEW", "1m")
	c.CertClockSkew, err = time.ParseDuration(skew)
	if err != nil {
		return nil, fmt.Errorf("invalid SSHBROKER_CERT_CLOCK_SKEW %q: %w", skew, err)
	}
	if c.CertClockSkew < 0 {
		return nil, fmt.Errorf("SSHBROKER_CERT_CLOCK_SKEW must not be negative")
	}

	c.BrokerSourceAddr = os.Getenv("SSHBROKER_BROKER_SOURCE_ADDR")

	c.SSHListenAddr = getenv("SSHBROKER_SSH_LISTEN_ADDR", ":2222")
	c.SSHHostKeyPath = getenv("SSHBROKER_SSH_HOST_KEY_PATH", "dev/host_key")
	c.AuthorizedUsersPath = getenv("SSHBROKER_AUTHORIZED_USERS_PATH", "dev/authorized_users")
	c.TargetsPath = getenv("SSHBROKER_TARGETS_PATH", "dev/targets.json")

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
