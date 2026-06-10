// Package ratelimit provides a per-client token-bucket rate limiter.
//
// The clock is injectable so behavior is deterministic under test.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter holds an independent token bucket per client id.
type Limiter struct {
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Limiter that reads the current time from now. If now is nil,
// time.Now is used.
func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, buckets: make(map[string]*bucket)}
}

// Allow reports whether a request from client may proceed under a bucket that
// refills at rps tokens per second up to a maximum of burst tokens. The first
// call for a client starts the bucket full. A non-positive rps or burst means
// "no limit" and always allows.
func (l *Limiter) Allow(client string, rps, burst float64) bool {
	if rps <= 0 || burst <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[client]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[client] = b
	}

	// Refill based on elapsed time since the last observation.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rps
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
