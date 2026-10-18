package backup

import (
	"sync"
	"time"
)

// Scheduler owns the snapshot cadence and lets it change while the server runs.
// It holds only the interval and a one-slot signal that a change happened; the
// timer loop and the snapshot itself live in the caller (cmd/syncboxd), so this
// package stays free of the logging and context that drive them, and the API can
// reach in to read or set the cadence.
//
// The interval is deliberately not persisted. SYNCBOX_BACKUP_SCHEDULE decides it
// at boot, and a restart returns to that: the durable source of truth for a
// headless deployment stays the environment. A change made over the API adjusts
// this running process only, which is exactly what the console's schedule select
// promises (docs/reference-web-settings.md).
type Scheduler struct {
	mu      sync.Mutex
	every   time.Duration // 0 means snapshots are off
	changed chan struct{} // capacity 1: one pending nudge is enough
	// nextDue is when the timer loop expects to fire the next snapshot, armed on
	// each pass it starts a wait. The zero time means nothing is pending — off, or
	// the loop has not run yet. It is reported to the console so an operator sees
	// "how long until the next one", not just the spacing.
	nextDue time.Time
}

// NewScheduler makes a scheduler with the given boot interval; 0 starts it off.
func NewScheduler(every time.Duration) *Scheduler {
	return &Scheduler{every: every, changed: make(chan struct{}, 1)}
}

// Every reports the current cadence; zero means off.
func (s *Scheduler) Every() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.every
}

// SetInterval changes the cadence live. Zero switches snapshots off; any positive
// value switches them back on at that spacing. It takes the value as given — any
// floor is the caller's to enforce — and nudges the loop so a shorter interval
// (or a switch on) takes effect now rather than after the wait already started.
func (s *Scheduler) SetInterval(every time.Duration) {
	s.mu.Lock()
	s.every = every
	// The armed wait no longer matches the new cadence; drop it so a reader does
	// not see a stale "next" until the loop wakes on the nudge and re-arms.
	s.nextDue = time.Time{}
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default: // a nudge is already pending; the loop will re-read the latest value
	}
}

// Arm records when the timer loop expects to fire the next snapshot. It calls
// this each pass before starting a wait, and passes the zero time when off, so
// NextDue never goes stale on its own.
func (s *Scheduler) Arm(due time.Time) {
	s.mu.Lock()
	s.nextDue = due
	s.mu.Unlock()
}

// NextDue reports when the loop has armed the next snapshot, or the zero time
// when nothing is pending (off, or the loop has not started a wait yet).
func (s *Scheduler) NextDue() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextDue
}

// Changed yields a signal each time the interval may have changed. The timer loop
// selects on this alongside its timer and the shutdown context, and re-reads
// Every when it wakes.
func (s *Scheduler) Changed() <-chan struct{} {
	return s.changed
}
