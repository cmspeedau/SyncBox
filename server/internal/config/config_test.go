package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreConservative(t *testing.T) {
	cfg := Defaults()

	// Loopback by default is the difference between an accidental public server
	// and an intentional one.
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8080", cfg.ListenAddr)
	}
	if cfg.TokenTTL != 24*time.Hour {
		t.Errorf("TokenTTL = %s, want 24h", cfg.TokenTTL)
	}
	if cfg.MaxChunkBytes <= 0 {
		t.Errorf("MaxChunkBytes = %d, want a positive limit", cfg.MaxChunkBytes)
	}
	if cfg.BackupSchedule != 0 {
		t.Errorf("BackupSchedule = %s, want off until configured", cfg.BackupSchedule)
	}
}

func TestFromEnvReadsTheDocumentedNames(t *testing.T) {
	t.Setenv("SYNCBOX_LISTEN_ADDR", "0.0.0.0:9999")
	t.Setenv("SYNCBOX_PASSWORD", "a-real-password")
	t.Setenv("SYNCBOX_TOKEN_SECRET", "a-signing-secret")
	t.Setenv("SYNCBOX_DATA_DIR", "/srv/syncbox")
	t.Setenv("SYNCBOX_BACKUP_TARGET", "/mnt/nas/snapshots")
	t.Setenv("SYNCBOX_TOKEN_TTL", "90s")
	t.Setenv("SYNCBOX_BACKUP_SCHEDULE", "6h")
	t.Setenv("SYNCBOX_BACKUP_POST", "restic -r s3://backup/restic backup $SYNCBOX_SNAPSHOT_PATH")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}

	if cfg.ListenAddr != "0.0.0.0:9999" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.Password != "a-real-password" {
		t.Errorf("Password = %q", cfg.Password)
	}
	if cfg.TokenSecret != "a-signing-secret" {
		t.Errorf("TokenSecret = %q", cfg.TokenSecret)
	}
	if cfg.DataDir != "/srv/syncbox" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.BackupTarget != "/mnt/nas/snapshots" {
		t.Errorf("BackupTarget = %q", cfg.BackupTarget)
	}
	if cfg.TokenTTL != 90*time.Second {
		t.Errorf("TokenTTL = %s", cfg.TokenTTL)
	}
	if cfg.BackupSchedule != 6*time.Hour {
		t.Errorf("BackupSchedule = %s", cfg.BackupSchedule)
	}
	if cfg.BackupPost != "restic -r s3://backup/restic backup $SYNCBOX_SNAPSHOT_PATH" {
		t.Errorf("BackupPost = %q", cfg.BackupPost)
	}
}

func TestS3BackupSettingsAndAwsFallback(t *testing.T) {
	t.Run("syncbox names shadow the aws ones", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-central-1")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAWS")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "awssecret")
		t.Setenv("SYNCBOX_BACKUP_TARGET", "s3://syncbox-snapshots/prod")
		t.Setenv("SYNCBOX_S3_ENDPOINT", "http://127.0.0.1:9000")
		t.Setenv("SYNCBOX_S3_REGION", "us-east-1")
		t.Setenv("SYNCBOX_S3_ACCESS_KEY", "AKI SYNCBOX")
		t.Setenv("SYNCBOX_S3_SECRET_KEY", "syncboxsecret")
		t.Setenv("SYNCBOX_BACKUP_LOCK_DAYS", "30")

		cfg, err := FromEnv()
		if err != nil {
			t.Fatalf("FromEnv: %v", err)
		}
		if cfg.BackupTarget != "s3://syncbox-snapshots/prod" {
			t.Errorf("BackupTarget = %q", cfg.BackupTarget)
		}
		if cfg.S3Endpoint != "http://127.0.0.1:9000" {
			t.Errorf("S3Endpoint = %q", cfg.S3Endpoint)
		}
		if cfg.S3Region != "us-east-1" {
			t.Errorf("S3Region = %q, want the SYNCBOX name to win", cfg.S3Region)
		}
		if cfg.S3AccessKey != "AKI SYNCBOX" || cfg.S3SecretKey != "syncboxsecret" {
			t.Errorf("credentials = %q/%q, want the SYNCBOX names to win", cfg.S3AccessKey, cfg.S3SecretKey)
		}
		if cfg.BackupLockDays != 30 {
			t.Errorf("BackupLockDays = %d", cfg.BackupLockDays)
		}
	})

	t.Run("aws names and the default horizon apply alone", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-central-1")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAWS")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "awssecret")

		cfg, err := FromEnv()
		if err != nil {
			t.Fatalf("FromEnv: %v", err)
		}
		if cfg.S3Region != "eu-central-1" {
			t.Errorf("S3Region = %q, want the AWS_REGION fallback", cfg.S3Region)
		}
		if cfg.S3AccessKey != "AKIAWS" || cfg.S3SecretKey != "awssecret" {
			t.Errorf("credentials = %q/%q, want the AWS_* fallback", cfg.S3AccessKey, cfg.S3SecretKey)
		}
		if cfg.BackupLockDays != 400 {
			t.Errorf("BackupLockDays = %d, want the 400-day default", cfg.BackupLockDays)
		}
		if cfg.S3Region == "" {
			t.Error("region must never end up empty when AWS_REGION names one")
		}
	})
}

func TestBackupLockDaysRejectsNonsense(t *testing.T) {
	for _, value := range []string{"zero", "0", "-5"} {
		t.Setenv("SYNCBOX_BACKUP_LOCK_DAYS", value)
		if _, err := FromEnv(); err == nil {
			t.Errorf("SYNCBOX_BACKUP_LOCK_DAYS=%q must be refused", value)
		}
	}
}

func TestRateLimitParsesAndRejects(t *testing.T) {
	t.Setenv("SYNCBOX_RATE_LIMIT", "12.5")
	t.Setenv("SYNCBOX_RATE_BURST", "40")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RatePerSecond != 12.5 || cfg.RateBurst != 40 {
		t.Errorf("rate = %v/%v, want 12.5/40", cfg.RatePerSecond, cfg.RateBurst)
	}

	for _, bad := range []struct{ name, value string }{
		{"SYNCBOX_RATE_LIMIT", "0"},
		{"SYNCBOX_RATE_LIMIT", "fast"},
		{"SYNCBOX_RATE_BURST", "0"},
		{"SYNCBOX_RATE_BURST", "many"},
	} {
		t.Setenv(bad.name, bad.value)
		if _, err := FromEnv(); err == nil {
			t.Errorf("%s=%q was accepted", bad.name, bad.value)
		}
		t.Setenv(bad.name, "")
	}
}

// TestVaultEnforcementSwitch pins S5's toggle: off unless asked, the usual
// spellings accepted in any case, and a nonsense value reported rather than
// quietly read as off.
func TestVaultEnforcementSwitch(t *testing.T) {
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RequireRegisteredVaults {
		t.Error("enforcement is on with nothing set, want off")
	}

	t.Setenv("SYNCBOX_PASSWORD", "a-real-password")
	for _, spelling := range []string{"1", "true", "yes", "on", "ON", " True "} {
		t.Setenv("SYNCBOX_REQUIRE_REGISTERED_VAULTS", spelling)
		cfg, err := FromEnv()
		if err != nil {
			t.Fatalf("FromEnv(%q): %v", spelling, err)
		}
		if !cfg.RequireRegisteredVaults {
			t.Errorf("%q read as off, want on", spelling)
		}
	}
	for _, spelling := range []string{"0", "false", "no", "off"} {
		t.Setenv("SYNCBOX_REQUIRE_REGISTERED_VAULTS", spelling)
		cfg, err := FromEnv()
		if err != nil {
			t.Fatalf("FromEnv(%q): %v", spelling, err)
		}
		if cfg.RequireRegisteredVaults {
			t.Errorf("%q read as on, want off", spelling)
		}
	}
	t.Setenv("SYNCBOX_REQUIRE_REGISTERED_VAULTS", "maybe")
	if _, err := FromEnv(); err == nil {
		t.Error("a nonsense switch was accepted instead of reported")
	}
}

func TestMissingPasswordIsGeneratedNotAbsent(t *testing.T) {
	t.Setenv("SYNCBOX_PASSWORD", "")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Password == "" {
		t.Fatal("an unset password left the server with no credential at all")
	}
	if cfg.Password == Defaults().Password {
		t.Error("the generated password is a constant")
	}

	other, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv again: %v", err)
	}
	if other.Password == cfg.Password {
		t.Error("two generations produced the same password")
	}
}

func TestBadDurationsAreReportedByName(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "token ttl", key: "SYNCBOX_TOKEN_TTL", value: "hour"},
		{name: "backup schedule", key: "SYNCBOX_BACKUP_SCHEDULE", value: "0"},
		{name: "schedule too eager", key: "SYNCBOX_BACKUP_SCHEDULE", value: "5s"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.value)

			_, err := FromEnv()
			if err == nil {
				t.Fatalf("%s = %q accepted", test.key, test.value)
			}
			if got := err.Error(); len(got) == 0 {
				t.Error("error has no message")
			}
		})
	}
}

func TestWarningsNameTheRiskyDefaults(t *testing.T) {
	cfg := Defaults()
	cfg.Password = "set"

	warnings := cfg.Warnings()
	joined := ""
	for _, warning := range warnings {
		joined += warning + "\n"
	}

	// Both of these are the "why is my backup gone" class of surprise, so they
	// have to be visible at startup rather than discovered later.
	if joined == "" {
		t.Fatal("an unconfigured server reported no warnings")
	}
	containsAllText(t, joined, "SYNCBOX_TOKEN_SECRET", "SYNCBOX_BACKUP_TARGET")

	cfg.TokenSecret = "secret"
	cfg.BackupTarget = "/mnt/nas"
	cfg.ListenAddr = "127.0.0.1:8080"
	if remaining := cfg.Warnings(); len(remaining) != 0 {
		t.Errorf("a fully configured server still warned: %v", remaining)
	}
}

func TestListeningOnAllInterfacesIsFlagged(t *testing.T) {
	cfg := Defaults()
	cfg.Password = "set"
	cfg.TokenSecret = "secret"
	cfg.BackupTarget = "/mnt/nas"
	cfg.ListenAddr = "0.0.0.0:8080"

	warnings := cfg.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one about the interface", warnings)
	}
}

func TestParseInt64(t *testing.T) {
	value, err := ParseInt64("", 42)
	if err != nil || value != 42 {
		t.Errorf("ParseInt64(\"\", 42) = %d, %v", value, err)
	}
	value, err = ParseInt64(" 17 ", 42)
	if err != nil || value != 17 {
		t.Errorf("ParseInt64(\" 17 \", 42) = %d, %v", value, err)
	}
	if _, err := ParseInt64("twelve", 42); err == nil {
		t.Error("ParseInt64 accepted a word")
	}
}

func containsAllText(t *testing.T, joined string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(joined, needle) {
			t.Errorf("warnings do not mention %q:\n%s", needle, joined)
		}
	}
}

// The sync-space settings (M11 S3) both have a default worth stating out loud:
// a week for a share link, a month in the recycle bin. And the bin's zero is a
// value — it turns the sweep off — rather than an absence to fall back from.
func TestShareAndRecycleDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.ShareTTL != 168*time.Hour {
		t.Errorf("ShareTTL = %s, want a week", cfg.ShareTTL)
	}
	if cfg.RecycleDays != 30 {
		t.Errorf("RecycleDays = %d, want 30", cfg.RecycleDays)
	}
}

func TestShareAndRecycleReadFromTheEnvironment(t *testing.T) {
	t.Setenv("SYNCBOX_SHARE_TTL", "45m")
	t.Setenv("SYNCBOX_RECYCLE_DAYS", "7")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ShareTTL != 45*time.Minute {
		t.Errorf("ShareTTL = %s, want 45m", cfg.ShareTTL)
	}
	if cfg.RecycleDays != 7 {
		t.Errorf("RecycleDays = %d, want 7", cfg.RecycleDays)
	}
}

func TestRecycleDaysZeroDisablesTheSweepRatherThanFallingBack(t *testing.T) {
	t.Setenv("SYNCBOX_RECYCLE_DAYS", "0")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RecycleDays != 0 {
		t.Errorf("RecycleDays = %d, want the sweep switched off", cfg.RecycleDays)
	}
}

func TestShareAndRecycleRejectNonsense(t *testing.T) {
	tests := []struct {
		key, value string
	}{
		{"SYNCBOX_SHARE_TTL", "a week"},
		{"SYNCBOX_SHARE_TTL", "0"},
		{"SYNCBOX_SHARE_TTL", "-1h"},
		{"SYNCBOX_RECYCLE_DAYS", "thirty"},
		{"SYNCBOX_RECYCLE_DAYS", "-1"},
	}
	for _, test := range tests {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("%s = %q accepted", test.key, test.value)
			} else if !strings.Contains(err.Error(), test.key) {
				t.Errorf("error %q does not name the setting", err)
			}
		})
	}
}
