package ratelimit

import (
	"testing"
	"time"
)

// clock is a hand-wound clock: tests advance it explicitly, so burst and
// refill are proven without waiting.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }
func (c *clock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestBurstThenRefill(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	l := New(2, 3) // 2/s sustained, burst of 3
	l.now = c.Now

	for i := range 3 {
		ok, _ := l.Allow("1.2.3.4")
		if !ok {
			t.Fatalf("request %d refused an empty-but-fresh bucket", i+1)
		}
	}
	ok, wait := l.Allow("1.2.3.4")
	if ok {
		t.Fatal("the fourth request fit a burst of three")
	}
	if wait != 500*time.Millisecond {
		t.Errorf("retry-after = %s, want the 500ms a 2/s refill needs", wait)
	}

	c.Advance(500 * time.Millisecond)
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Error("the refill did not land")
	}
	ok, _ = l.Allow("1.2.3.4")
	if ok {
		t.Error("half a second of 2/s refill is one token, not two")
	}
}

func TestIdleDoesNotBankForever(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	l := New(1, 4)
	l.now = c.Now

	// One request first, so the bucket is not merely un-created yet.
	if ok, _ := l.Allow("host"); !ok {
		t.Fatal("first request refused")
	}
	c.Advance(time.Hour)

	for range 4 {
		if ok, _ := l.Allow("host"); !ok {
			t.Fatal("a full bucket refused")
		}
	}
	if ok, _ := l.Allow("host"); ok {
		t.Error("an hour idle banked more than the burst — the bucket must cap")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	l := New(1, 1)
	l.now = c.Now

	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a refused fresh")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a's burst of one fit two")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Error("b paid for a's traffic")
	}
}

func TestZeroRateDisables(t *testing.T) {
	l := New(0, 10)
	for range 100 {
		if ok, _ := l.Allow("anyone"); !ok {
			t.Fatal("a disabled limiter refused something")
		}
	}
	var nilLimiter *Limiter
	if ok, _ := nilLimiter.Allow("anyone"); !ok {
		t.Fatal("a nil limiter must admit, not nil-panic")
	}
}

func TestSweepForgetsIdleKeys(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	l := New(1, 2)
	l.now = c.Now

	l.Allow("guest")
	c.Advance(2 * time.Minute)
	l.Allow("resident")

	l.mu.Lock()
	_, stale := l.buckets["guest"]
	l.mu.Unlock()
	if stale {
		t.Error("the sweep left a long-idle, full bucket behind to grow the map")
	}
}
