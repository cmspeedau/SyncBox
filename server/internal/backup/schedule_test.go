package backup

import (
	"testing"
	"time"
)

// The scheduler holds only a cadence and a one-slot change signal, so the tests
// check exactly those: reads reflect the last write, and every change nudges so a
// timer loop wakes to re-read — without a goroutine in the way.

func TestSchedulerReadsBackWhatItIsSetTo(t *testing.T) {
	s := NewScheduler(time.Hour)
	if got := s.Every(); got != time.Hour {
		t.Fatalf("NewScheduler(1h).Every = %v, want 1h", got)
	}

	s.SetInterval(0)
	if got := s.Every(); got != 0 {
		t.Fatalf("after SetInterval(0) Every = %v, want 0", got)
	}

	s.SetInterval(2 * time.Hour)
	if got := s.Every(); got != 2*time.Hour {
		t.Fatalf("after SetInterval(2h) Every = %v, want 2h", got)
	}
}

func TestSchedulerNudgesOncePerChange(t *testing.T) {
	s := NewScheduler(time.Hour)

	// A fresh scheduler has nothing pending.
	if received(s.Changed()) {
		t.Fatal("a new scheduler should not be mid-nudge")
	}

	// A change signals the loop to re-read.
	s.SetInterval(time.Minute)
	if !received(s.Changed()) {
		t.Fatal("SetInterval did not signal the loop")
	}

	// Two rapid changes with nobody listening queue at most one nudge — the
	// one-slot channel drops the extra, and the loop re-reads the latest value
	// whenever it does wake.
	s.SetInterval(0)
	s.SetInterval(time.Hour)
	if !received(s.Changed()) {
		t.Fatal("a change should have left one nudge queued")
	}
	if received(s.Changed()) {
		t.Fatal("more than one nudge queued; the loop needs only one")
	}
	if s.Every() != time.Hour {
		t.Errorf("Every = %v, want the latest value 1h", s.Every())
	}
}

func TestSchedulerArmsTheNextFire(t *testing.T) {
	s := NewScheduler(time.Hour)

	// A fresh scheduler has armed nothing: the loop has not started a wait yet.
	if !s.NextDue().IsZero() {
		t.Fatalf("a fresh scheduler should have no next-due, got %v", s.NextDue())
	}

	// The loop arms the time it expects to fire, and the API reads it back.
	due := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	s.Arm(due)
	if got := s.NextDue(); !got.Equal(due) {
		t.Errorf("NextDue = %v, want %v", got, due)
	}

	// A cadence change drops the stale armed time until the loop re-arms.
	s.SetInterval(time.Minute)
	if !s.NextDue().IsZero() {
		t.Errorf("SetInterval left a stale next-due of %v, want zero", s.NextDue())
	}

	// Arming zero (the off path) clears it too.
	s.Arm(time.Now())
	s.Arm(time.Time{})
	if !s.NextDue().IsZero() {
		t.Errorf("Arm(zero) left next-due of %v, want zero", s.NextDue())
	}
}

// Boot is the cadence a restart returns to, so it must survive live changes.
func TestSchedulerRemembersItsBootInterval(t *testing.T) {
	s := NewScheduler(time.Hour)
	if got := s.Boot(); got != time.Hour {
		t.Fatalf("NewScheduler(1h).Boot = %v, want 1h", got)
	}

	// Live changes move Every but never the remembered boot value.
	s.SetInterval(0)
	s.SetInterval(15 * time.Minute)
	if got := s.Boot(); got != time.Hour {
		t.Errorf("Boot after live changes = %v, want the original 1h", got)
	}

	// A scheduler that booted off reports boot as off, so any live cadence reads
	// as a difference from what a restart will bring back.
	if got := NewScheduler(0).Boot(); got != 0 {
		t.Errorf("NewScheduler(0).Boot = %v, want 0", got)
	}
}

// received reports whether a nudge is waiting and consumes it if so.
func received(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
