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
