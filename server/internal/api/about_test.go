package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/backup"
	"github.com/syncbox/server/internal/backup/target"
	"github.com/syncbox/server/internal/store"
)

// About is a read-only operator summary. What matters: it reflects what the
// deployment was wired with (data dir, storage, lifetimes, backup target), it is
// authenticated, and with no backup target it says so rather than naming a blank
// location.

func newAboutClient(t *testing.T, backups *backup.Manager, tune func(*Server)) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	srv := New(stored, backups, issuer, testPassword)
	if tune != nil {
		tune(srv)
	}

	server := httptest.NewServer(srv.Routes())
	t.Cleanup(server.Close)
	c := &client{t: t, server: server}
	c.token = c.login()
	return c
}

func TestAboutReportsTheDeployment(t *testing.T) {
	dir := t.TempDir()
	tgt, err := target.NewLocal(dir)
	if err != nil {
		t.Fatalf("opening a local target: %v", err)
	}
	backups := backup.NewManager(tgt, store.NewMemory(MaxChunkBytes), "test-version")

	// A fixed clock so uptime is deterministic: the server started 90 minutes before
	// its own clock reads "now". The clock sits in the future so the login token the
	// test client checks (against the real wall clock) is still live.
	fixed := time.Now().Add(365 * 24 * time.Hour)
	c := newAboutClient(t, backups, func(s *Server) {
		s.SetVersion("9.9.9")
		s.SetDeployment("/var/lib/syncbox", "SQLite")
		s.SetShareTTL(24 * time.Hour)
		s.SetRecycleDays(30)
		s.SetRateLimit(5, 10)
		s.SetRequireRegisteredVaults(true)
		s.now = func() time.Time { return fixed }
		s.started = fixed.Add(-90 * time.Minute)
	})

	var body aboutBody
	c.mustDecode(c.do(http.MethodGet, "/admin/about", nil), &body)

	if body.Version != "9.9.9" {
		t.Errorf("Version = %q, want 9.9.9", body.Version)
	}
	if body.Storage != "SQLite" {
		t.Errorf("Storage = %q, want SQLite", body.Storage)
	}
	if body.DataDir != "/var/lib/syncbox" {
		t.Errorf("DataDir = %q, want /var/lib/syncbox", body.DataDir)
	}
	if body.ShareTTL != 86400 {
		t.Errorf("ShareTTL = %d, want 86400", body.ShareTTL)
	}
	if body.RecycleDays != 30 {
		t.Errorf("RecycleDays = %d, want 30", body.RecycleDays)
	}
	if !body.BackupsConfigured {
		t.Error("a server built with a backup manager reported it unconfigured")
	}
	if body.BackupTarget != tgt.Location() {
		t.Errorf("BackupTarget = %q, want the target location %q", body.BackupTarget, tgt.Location())
	}
	if body.TokenTTLSeconds != 3600 {
		t.Errorf("TokenTTLSeconds = %d, want 3600 (the 1h issuer TTL)", body.TokenTTLSeconds)
	}
	if body.RateLimitRPS != 5 || body.RateBurst != 10 {
		t.Errorf("rate limit = %g/%d, want 5 req/s burst 10", body.RateLimitRPS, body.RateBurst)
	}
	if !body.RequireRegistered {
		t.Error("SetRequireRegisteredVaults(true) was not reported")
	}
	// testPassword arrives as the env password, so the source reads environment.
	if body.PasswordSource != "environment" {
		t.Errorf("PasswordSource = %q, want environment", body.PasswordSource)
	}
	if want := fixed.Add(-90 * time.Minute).Unix(); body.StartedUnix != want {
		t.Errorf("StartedUnix = %d, want %d", body.StartedUnix, want)
	}
	if body.UptimeSeconds != 5400 {
		t.Errorf("UptimeSeconds = %d, want 5400 (90 minutes)", body.UptimeSeconds)
	}
	// An environment password is not something this server wrote, so it has no age.
	if body.PasswordChangedUnix != 0 {
		t.Errorf("PasswordChangedUnix = %d, want 0 for an environment password", body.PasswordChangedUnix)
	}
}

func TestAboutWithNoBackupTarget(t *testing.T) {
	c := newAboutClient(t, nil, nil) // no SetDeployment, no backups

	var body aboutBody
	c.mustDecode(c.do(http.MethodGet, "/admin/about", nil), &body)

	if body.Version != "dev" {
		t.Errorf("Version = %q, want the dev fallback", body.Version)
	}
	if body.BackupsConfigured || body.BackupTarget != "" {
		t.Errorf("a server with no target reported configured=%v target=%q", body.BackupsConfigured, body.BackupTarget)
	}
	// Unset deployment facts read back empty rather than fabricating a location.
	if body.DataDir != "" || body.Storage != "" {
		t.Errorf("deployment facts leaked a default: dir=%q storage=%q", body.DataDir, body.Storage)
	}
	// The default posture: a 1h session, no throttle, unknown vaults accepted.
	if body.TokenTTLSeconds != 3600 {
		t.Errorf("TokenTTLSeconds = %d, want 3600 (issuer default)", body.TokenTTLSeconds)
	}
	if body.RateLimitRPS != 0 {
		t.Errorf("RateLimitRPS = %g, want 0 (unlimited by default)", body.RateLimitRPS)
	}
	if body.RequireRegistered {
		t.Error("commits to unknown vaults should be accepted by default")
	}
}

func TestAboutNeedsAToken(t *testing.T) {
	c := newAboutClient(t, nil, nil)
	c.token = ""
	response := c.do(http.MethodGet, "/admin/about", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /admin/about = %s, want 401", response.Status)
	}
}
