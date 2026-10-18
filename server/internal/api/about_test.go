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

	c := newAboutClient(t, backups, func(s *Server) {
		s.SetVersion("9.9.9")
		s.SetDeployment("/var/lib/syncbox", "SQLite")
		s.SetShareTTL(24 * time.Hour)
		s.SetRecycleDays(30)
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
