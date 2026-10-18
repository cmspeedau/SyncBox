package api

// The snapshot schedule as a live setting. The reference settings page wants the
// operator to change or switch off the cadence from the browser and have it take
// effect without a restart (docs/reference-web-settings.md), while a headless
// deployment keeps driving it from SYNCBOX_BACKUP_SCHEDULE. So this reads and
// writes the running scheduler only: a restart returns to whatever the environment
// says, which is why the endpoint edits the process and never a file.

import (
	"net/http"
	"time"
)

// backupConfigBody is the shape both the read and the write return.
// interval_seconds is the machine-readable truth the console's select maps to;
// schedule is a human label ("off", or a duration) for anywhere it is shown raw.
type backupConfigBody struct {
	Configured      bool   `json:"configured"`
	IntervalSeconds int    `json:"interval_seconds"`
	Schedule        string `json:"schedule"`
	// NextDueUnix is when the running scheduler expects the next snapshot, or 0
	// when nothing is pending (off, or a change not yet re-armed). omitempty so a
	// server that has not armed a wait simply omits it.
	NextDueUnix int64 `json:"next_due_unix,omitempty"`
	// BootIntervalSeconds and BootSchedule are the cadence the environment set at
	// startup, which a restart returns to; Drifted says whether the live cadence
	// differs from it. Because the schedule is deliberately not persisted, this is
	// the only way the console can warn that a change made here is temporary.
	BootIntervalSeconds int    `json:"boot_interval_seconds"`
	BootSchedule        string `json:"boot_schedule"`
	Drifted             bool   `json:"drifted"`
}

// minScheduleSeconds mirrors the config floor: a snapshot every few seconds would
// hammer the target, so the shortest live schedule is a minute. Zero is "off".
const minScheduleSeconds = 60

func scheduleConfig(s *Server) backupConfigBody {
	if s.sched == nil {
		return backupConfigBody{Configured: false, IntervalSeconds: 0, Schedule: "off", BootSchedule: "off"}
	}
	every := s.sched.Every()
	boot := s.sched.Boot()
	body := backupConfigBody{
		Configured:          true,
		IntervalSeconds:     int(every / time.Second),
		Schedule:            scheduleLabel(every),
		BootIntervalSeconds: int(boot / time.Second),
		BootSchedule:        scheduleLabel(boot),
		Drifted:             every != boot,
	}
	if due := s.sched.NextDue(); !due.IsZero() {
		body.NextDueUnix = due.Unix()
	}
	return body
}

func scheduleLabel(every time.Duration) string {
	if every <= 0 {
		return "off"
	}
	return every.String()
}

func (s *Server) handleBackupConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, scheduleConfig(s))
}

// handleBackupConfigPut sets the cadence for this running server. Without a backup
// target there is nothing to schedule, so that is refused rather than accepted and
// quietly ignored. A negative interval is a mistake; a positive one below the floor
// would snapshot too eagerly; zero switches scheduled snapshots off.
func (s *Server) handleBackupConfigPut(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IntervalSeconds int `json:"interval_seconds"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if s.sched == nil {
		writeError(w, http.StatusConflict, "not_configured",
			"no backup target is configured; set SYNCBOX_BACKUP_TARGET before scheduling snapshots")
		return
	}
	if request.IntervalSeconds < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "interval_seconds cannot be negative")
		return
	}
	if request.IntervalSeconds > 0 && request.IntervalSeconds < minScheduleSeconds {
		writeError(w, http.StatusBadRequest, "schedule_too_eager",
			"snapshots may be scheduled at most once a minute, or 0 to switch them off")
		return
	}

	s.sched.SetInterval(time.Duration(request.IntervalSeconds) * time.Second)
	writeJSON(w, http.StatusOK, scheduleConfig(s))
}
