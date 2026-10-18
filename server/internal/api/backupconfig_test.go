package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/backup"
	"github.com/syncbox/server/internal/store"
)

// The snapshot schedule is read and set over the admin API, and the rules that
// matter are: a configured server reports and accepts a cadence, a floor stops an
// eager one, zero means off, and a server with no backup target refuses rather
// than pretending.

// newConfigClient is a signed-in server whose scheduler starts at `sched` (nil
// when no backup target is configured). The config endpoints touch only the
// scheduler, so a real backup target is not needed.
func newConfigClient(t *testing.T, sched *backup.Scheduler) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	srv := New(stored, nil, issuer, testPassword)
	srv.SetScheduler(sched)

	server := httptest.NewServer(srv.Routes())
	t.Cleanup(server.Close)
	c := &client{t: t, server: server}
	c.token = c.login()
	return c
}

// getSchedule reads the current backup config.
func (c *client) getSchedule() backupConfigBody {
	c.t.Helper()
	var body backupConfigBody
	c.mustDecode(c.do(http.MethodGet, "/admin/backups/config", nil), &body)
	return body
}

// setSchedule PUTs a new interval and returns the status and error code.
func (c *client) setSchedule(seconds int) (int, string) {
	c.t.Helper()
	reqBody, _ := json.Marshal(map[string]int{"interval_seconds": seconds})
	response := c.do(http.MethodPut, "/admin/backups/config", reqBody)
	if response.StatusCode >= http.StatusBadRequest {
		code, _ := c.errorBodyOf(response)
		return response.StatusCode, code
	}
	defer response.Body.Close()
	var body backupConfigBody
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		c.t.Fatalf("decoding schedule reply: %v", err)
	}
	return response.StatusCode, ""
}

func TestBackupScheduleIsReadAndSet(t *testing.T) {
	sched := backup.NewScheduler(time.Hour)
	c := newConfigClient(t, sched)

	got := c.getSchedule()
	if !got.Configured || got.IntervalSeconds != 3600 {
		t.Fatalf("initial schedule = %+v, want configured with 3600s", got)
	}

	// Switch off: reported as zero, and the scheduler agrees.
	if code, errCode := c.setSchedule(0); code != http.StatusOK || errCode != "" {
		t.Fatalf("setSchedule(0) = %d %q, want 200", code, errCode)
	}
	if c.getSchedule().IntervalSeconds != 0 {
		t.Error("switching off was not reflected in the read-back")
	}
	if sched.Every() != 0 {
		t.Errorf("scheduler Every = %v, want 0 after switch-off", sched.Every())
	}

	// A real cadence takes and is reported back.
	if code, errCode := c.setSchedule(900); code != http.StatusOK || errCode != "" {
		t.Fatalf("setSchedule(900) = %d %q, want 200", code, errCode)
	}
	if c.getSchedule().IntervalSeconds != 900 {
		t.Error("the new cadence was not reflected in the read-back")
	}
	if sched.Every() != 15*time.Minute {
		t.Errorf("scheduler Every = %v, want 15m", sched.Every())
	}

	// Below the floor is refused and leaves the schedule untouched.
	if code, errCode := c.setSchedule(59); code != http.StatusBadRequest || errCode != "schedule_too_eager" {
		t.Errorf("setSchedule(59) = %d %q, want 400 schedule_too_eager", code, errCode)
	}
	if sched.Every() != 15*time.Minute {
		t.Errorf("a refused change altered the schedule: %v", sched.Every())
	}

	// A negative interval is simply a bad request.
	if code, errCode := c.setSchedule(-1); code != http.StatusBadRequest || errCode != "bad_request" {
		t.Errorf("setSchedule(-1) = %d %q, want 400 bad_request", code, errCode)
	}
}

func TestBackupScheduleNeedsATarget(t *testing.T) {
	c := newConfigClient(t, nil) // no backup target

	if got := c.getSchedule(); got.Configured {
		t.Errorf("a server with no target reported configured: %+v", got)
	}
	if code, errCode := c.setSchedule(3600); code != http.StatusConflict || errCode != "not_configured" {
		t.Errorf("setSchedule with no target = %d %q, want 409 not_configured", code, errCode)
	}
}

// next_due_unix is the loop's armed next fire, so the console can say "next in a
// moment". A test server runs no loop, so it starts unarmed (0); the point is that
// whatever the scheduler has armed is what the endpoint reports, and a cadence
// change clears it until the loop re-arms.
func TestBackupConfigReportsNextDue(t *testing.T) {
	sched := backup.NewScheduler(time.Hour)
	c := newConfigClient(t, sched)

	if got := c.getSchedule(); got.NextDueUnix != 0 {
		t.Errorf("unarmed next_due = %d, want 0", got.NextDueUnix)
	}

	due := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	sched.Arm(due)
	if got := c.getSchedule(); got.NextDueUnix != due.Unix() {
		t.Errorf("armed next_due = %d, want %d", got.NextDueUnix, due.Unix())
	}

	// A cadence change drops the armed time, so a reader never sees a stale "next".
	c.setSchedule(3600)
	if got := c.getSchedule(); got.NextDueUnix != 0 {
		t.Errorf("next_due after a change = %d, want 0 (cleared until the loop re-arms)", got.NextDueUnix)
	}
}
