// Package config reads the server's settings from the environment.
//
// Environment variables rather than a config file because the server is meant to
// run in a container, where that is how secrets and per-host differences arrive.
// Every name is prefixed SYNCBOX_ so a shared host can run two servers.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is everything the server needs to start.
type Config struct {
	// ListenAddr is the host and port to bind. It defaults to loopback, so an
	// operator has to opt in to exposing the server on a network.
	ListenAddr string
	// Password is the single account credential. It is never stored by the
	// server, only compared to buy a token.
	Password string
	// TokenSecret signs bearer tokens. Empty means "generated at boot", which
	// invalidates tokens on restart.
	TokenSecret string
	// TokenTTL is how long an issued token stays valid.
	TokenTTL time.Duration
	// DataDir is where the durable store keeps chunks and metadata. Unused until
	// the SQLite store replaces the in-memory one in M2, but read now so the
	// container's volume mount is already correct.
	DataDir string
	// BackupTarget is a directory to write snapshots into. Empty disables the
	// administrative backup endpoints.
	BackupTarget string
	// BackupSchedule is how often the server snapshots itself, e.g. "1h". Zero
	// disables the timer; backups remain available on demand.
	BackupSchedule time.Duration
	// MaxChunkBytes bounds one uploaded chunk.
	MaxChunkBytes int64
}

// Defaults returns the settings a server runs with when the environment says
// nothing.
func Defaults() Config {
	return Config{
		ListenAddr:     "127.0.0.1:8080",
		TokenTTL:       24 * time.Hour,
		DataDir:        "./data",
		MaxChunkBytes:  8 << 20,
		BackupSchedule: 0,
	}
}

// FromEnv reads SYNCBOX_* variables over the defaults.
//
// With no password set it generates one and reports that it did, rather than
// starting an unauthenticated server: a random secret in the log is recoverable
// by whoever can read the log, which is a narrower exposure than no credential at
// all. That convenience is for development; a container deployment should always
// set one.
func FromEnv() (Config, error) {
	cfg := Defaults()
	var generated string

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_LISTEN_ADDR")); value != "" {
		cfg.ListenAddr = value
	}
	if value := strings.TrimSpace(os.Getenv("SYNCBOX_PASSWORD")); value != "" {
		cfg.Password = value
	} else {
		secret, err := randomHex(16)
		if err != nil {
			return Config{}, err
		}
		cfg.Password = secret
		generated = secret
	}
	cfg.TokenSecret = strings.TrimSpace(os.Getenv("SYNCBOX_TOKEN_SECRET"))
	cfg.DataDir = valueOr(os.Getenv("SYNCBOX_DATA_DIR"), cfg.DataDir)
	cfg.BackupTarget = strings.TrimSpace(os.Getenv("SYNCBOX_BACKUP_TARGET"))

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_TOKEN_TTL")); value != "" {
		ttl, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("SYNCBOX_TOKEN_TTL %q is not a duration: %w", value, err)
		}
		if ttl <= 0 {
			return Config{}, fmt.Errorf("SYNCBOX_TOKEN_TTL must be positive, got %s", ttl)
		}
		cfg.TokenTTL = ttl
	}

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_BACKUP_SCHEDULE")); value != "" {
		every, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("SYNCBOX_BACKUP_SCHEDULE %q is not a duration: %w", value, err)
		}
		if every < time.Minute {
			return Config{}, fmt.Errorf("SYNCBOX_BACKUP_SCHEDULE %s is too aggressive, use at least 1m", every)
		}
		cfg.BackupSchedule = every
	}

	if generated != "" {
		fmt.Printf("config: SYNCBOX_PASSWORD is unset, using the generated password %s\n", generated)
		fmt.Printf("config: set SYNCBOX_PASSWORD before exposing this server on a network\n")
	}
	return cfg, nil
}

// Warnings lists configuration choices that are legal but worth printing at
// startup, so an operator sees them in the container log instead of discovering
// them later.
func (c Config) Warnings() []string {
	var warnings []string
	if c.TokenSecret == "" {
		warnings = append(warnings,
			"SYNCBOX_TOKEN_SECRET is unset; tokens are signed with a key generated at boot and stop working after a restart")
	}
	if c.BackupTarget == "" {
		warnings = append(warnings,
			"SYNCBOX_BACKUP_TARGET is unset; this server holds the only copy of the data")
	}
	if strings.HasPrefix(c.ListenAddr, "0.0.0.0") || strings.HasPrefix(c.ListenAddr, "[::]") {
		warnings = append(warnings,
			"listening on all interfaces; put TLS in front of it")
	}
	return warnings
}

// valueOr returns env when it is non-empty, and fallback otherwise.
func valueOr(env, fallback string) string {
	if value := strings.TrimSpace(env); value != "" {
		return value
	}
	return fallback
}

// randomHex returns n random bytes as hex.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating a secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ParseInt64 reads an environment-sized integer, used by tests and by future
// numeric settings.
func ParseInt64(raw string, fallback int64) (int64, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not an integer", raw)
	}
	return value, nil
}
