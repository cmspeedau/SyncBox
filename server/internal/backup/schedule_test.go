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

// received reports whether a nudge is waiting and consumes it if so.
func received(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
