// Package config reads the server's settings from the environment.
//
// Environment variables rather than a config file because the server is meant to
// run in a container, where that is how secrets and per-host differences arrive.
// Every name is prefixed SYNCBOX_ so a shared host can run two servers.
package config

import (
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
	// DataDir is where the durable store keeps chunks (in a chunks/ subdir) and its
	// SQLite metadata. It defaults to ./data so the container's volume mount is
	// correct out of the box.
	DataDir string
	// BackupTarget is a directory to write snapshots into, or an
	// "s3://bucket[/prefix]" URL for object storage. Empty disables the
	// administrative backup endpoints.
	BackupTarget string
	// S3Endpoint points the backup target at an S3-compatible service
	// (MinIO, R2, Wasabi) instead of AWS; requests then go path-style.
	S3Endpoint string
	// S3Region signs requests for; AWS_REGION is honored, "us-east-1" assumed.
	S3Region string
	// S3AccessKey and S3SecretKey sign backup requests. The AWS_* names are
	// the fallback; without either pair an s3:// target fails at boot.
	S3AccessKey string
	S3SecretKey string
	// BackupLockDays is the COMPLIANCE object-lock retention each sealed
	// snapshot gets on an s3:// target — how long even the bucket owner
	// cannot delete a snapshot. Default 400: past the yearly rung of the
	// GFS ladder, so no snapshot is retired while a rung still wants it.
	BackupLockDays int
	// BackupSchedule is how often the server snapshots itself, e.g. "1h". Zero
	// disables the timer; backups remain available on demand.
	BackupSchedule time.Duration
	// BackupPost is a shell command run after every sealed snapshot — the seam
	// where restic, rsync, or borg carry the sealed bundle offsite. The
	// snapshot's name and path arrive in the environment; see docs/backup.md.
	BackupPost string
	// MaxChunkBytes bounds one uploaded chunk.
	MaxChunkBytes int64
	// RatePerSecond sustains requests per second per caller IP; zero (the
	// default) runs the server unthrottled.
	RatePerSecond float64
	// RateBurst is how many requests a caller may spend at once before the
	// sustained rate takes over.
	RateBurst int
	// RequireRegisteredVaults turns the vault registry from a report into a
	// gate: with it on, a commit to a vault id the registry does not know is
	// refused instead of birthing a vault nameless. Off by default, because
	// the right moment to turn it on is after every client has been pointed
	// at a registered vault — so no old client breaks the moment the registry
	// lands.
	RequireRegisteredVaults bool
	// ShareTTL is the longest a minted share link stays valid, for sync spaces.
	// A mint may ask for a shorter life; nothing extends one. Default 168h.
	ShareTTL time.Duration
	// RecycleDays is how long a deleted file stays restorable in a sync space's
	// recycle bin before the retention sweep drops the recoverable history
	// behind it. Default 30; zero disables the sweep, keeping everything.
	RecycleDays int
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
		RateBurst:      100,
		ShareTTL:       168 * time.Hour,
		RecycleDays:    30,
	}
}

// FromEnv reads SYNCBOX_* variables over the defaults.
//
// With no SYNCBOX_PASSWORD it leaves Password empty rather than inventing one:
// a fresh server then awaits first-run setup in the console, where the operator
// chooses a password and the server seals it with Argon2id into the data
// directory. A container deployment that wants its credential from the
// environment still sets SYNCBOX_PASSWORD, and that always wins.
func FromEnv() (Config, error) {
	cfg := Defaults()

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_LISTEN_ADDR")); value != "" {
		cfg.ListenAddr = value
	}
	// An unset SYNCBOX_PASSWORD is left unset. The server then falls back to a
	// password stored on an earlier first run, or to awaiting first-run setup in the
	// console. It no longer invents one and prints it to the log: sealing a first
	// password is the console's job now (internal/credential + internal/api/firstrun).
	if value := strings.TrimSpace(os.Getenv("SYNCBOX_PASSWORD")); value != "" {
		cfg.Password = value
	}
	cfg.TokenSecret = strings.TrimSpace(os.Getenv("SYNCBOX_TOKEN_SECRET"))
	cfg.DataDir = valueOr(os.Getenv("SYNCBOX_DATA_DIR"), cfg.DataDir)
	cfg.BackupTarget = strings.TrimSpace(os.Getenv("SYNCBOX_BACKUP_TARGET"))
	cfg.BackupPost = strings.TrimSpace(os.Getenv("SYNCBOX_BACKUP_POST"))
	cfg.S3Endpoint = strings.TrimSpace(os.Getenv("SYNCBOX_S3_ENDPOINT"))
	cfg.S3Region = firstSet(os.Getenv("SYNCBOX_S3_REGION"), os.Getenv("AWS_REGION"), "us-east-1")
	cfg.S3AccessKey = firstSet(os.Getenv("SYNCBOX_S3_ACCESS_KEY"), os.Getenv("AWS_ACCESS_KEY_ID"))
	cfg.S3SecretKey = firstSet(os.Getenv("SYNCBOX_S3_SECRET_KEY"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
	cfg.BackupLockDays = 400
	if value := strings.TrimSpace(os.Getenv("SYNCBOX_BACKUP_LOCK_DAYS")); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil || days <= 0 {
			return Config{}, fmt.Errorf("SYNCBOX_BACKUP_LOCK_DAYS %q is not a positive number of days", value)
		}
		cfg.BackupLockDays = days
	}

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

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_RATE_LIMIT")); value != "" {
		rate, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return Config{}, fmt.Errorf("SYNCBOX_RATE_LIMIT %q is not a number: %w", value, err)
		}
		if rate <= 0 {
			return Config{}, fmt.Errorf("SYNCBOX_RATE_LIMIT must be positive to throttle, got %s", value)
		}
		cfg.RatePerSecond = rate
	}
	if value := strings.TrimSpace(os.Getenv("SYNCBOX_RATE_BURST")); value != "" {
		burst, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("SYNCBOX_RATE_BURST %q is not a count: %w", value, err)
		}
		if burst < 1 {
			return Config{}, fmt.Errorf("SYNCBOX_RATE_BURST must be at least 1, got %d", burst)
		}
		cfg.RateBurst = burst
	}

	if value := strings.TrimSpace(os.Getenv("SYNCBOX_SHARE_TTL")); value != "" {
		ttl, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("SYNCBOX_SHARE_TTL %q is not a duration: %w", value, err)
		}
		if ttl <= 0 {
			return Config{}, fmt.Errorf("SYNCBOX_SHARE_TTL must be positive, got %s", ttl)
		}
		cfg.ShareTTL = ttl
	}

	// Zero is a value, not an absence: it turns the recycle sweep off, so the bin
	// keeps every deletion. Only something that is not a number at all falls back.
	if value := strings.TrimSpace(os.Getenv("SYNCBOX_RECYCLE_DAYS")); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil || days < 0 {
			return Config{}, fmt.Errorf("SYNCBOX_RECYCLE_DAYS %q is not a non-negative number of days", value)
		}
		cfg.RecycleDays = days
	}

	requireRegistered, err := parseSwitch("SYNCBOX_REQUIRE_REGISTERED_VAULTS", os.Getenv("SYNCBOX_REQUIRE_REGISTERED_VAULTS"))
	if err != nil {
		return Config{}, err
	}
	cfg.RequireRegisteredVaults = requireRegistered

	return cfg, nil
}

// Warnings lists configuration choices that are legal but worth printing at
// startup, so an operator sees them in the container log instead of discovering
// them later.
func (c Config) Warnings() []string {
	var warnings []string
	if c.Password == "" {
		warnings = append(warnings,
			"SYNCBOX_PASSWORD is unset and no password is stored yet; the server awaits first-run setup in the console")
	}
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

// firstSet returns the first non-empty value, for the settings where a
// Syncbox-specific name shadows a shared AWS_* one.
func firstSet(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

// parseSwitch reads a boolean-ish environment switch. Unset or empty is false;
// the usual spellings of yes and no are accepted in any case; anything else is
// a configuration mistake worth failing on rather than silently reading as
// false.
func parseSwitch(name, value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("%s %q is not a yes/no switch (use 1/0, true/false, yes/no or on/off)", name, value)
	}
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
