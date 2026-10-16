// Package ratelimit holds one token bucket per caller.
//
// The server is meant to run on a home connection, where the thing most worth
// protecting is the machine itself: a sync loop with a bug, or a hostile guesser
// at the password endpoint, should not be able to spend unbounded CPU or
// bandwidth. A token bucket per key (an IP) is the shape that lets a legitimate
// burst — a first sync, a big pull — through at full speed while holding the
// sustained rate to what the operator configured.
//
// Buckets fill lazily: no ticker, no goroutine. The clock is injectable so the
// semantics are tested without waiting in real time.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter decides per key, in isolation from every other key.
type Limiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second, sustained
	burst float64 // capacity: how many requests a full bucket serves at once
	now   func() time.Time

	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens  float64
	updated time.Time
}

// sweepInterval is how often stale buckets are dropped. A key that has been
// full-refilled for a whole interval will start fresh anyway if it returns, so
// forgetting it is invisible — and forgetting bounds the map's memory against a
// caller that rotates keys.
const sweepInterval = time.Minute

// New returns a limiter admitting rate requests per second with a burst of
// burst. A non-positive rate disables it (Allow always admits), so callers can
// pass a zero config through without a special case.
func New(rate float64, burst int) *Limiter {
	if rate <= 0 {
		return &Limiter{rate: -1}
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    rate,
		burst:   float64(burst),
		now:     time.Now,
		buckets: map[string]*bucket{},
	}
}

// Allow spends one token for key. When it refuses, it spends nothing and says
// how long until a token lands — the value an Retry-After header can carry
// verbatim after rounding up.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil || l.rate <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastSweep) >= sweepInterval {
		l.sweepLocked(now)
	}

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, updated: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.updated = now
	}

	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}

	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweepLocked drops buckets that are already full: they hold no information a
// returning caller would notice. Caller holds l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	for key, b := range l.buckets {
		refill := time.Duration((l.burst - b.tokens) / l.rate * float64(time.Second))
		if now.Sub(b.updated) >= refill {
			delete(l.buckets, key)
		}
	}
	l.lastSweep = now
}
