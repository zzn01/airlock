package ratelimit

import (
	"testing"
	"time"
)

func TestAllowConsumesBurstThenDenies(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(func() time.Time { return now })

	// burst of 2: first two requests pass, third is denied (no refill yet).
	if !l.Allow("c1", 1, 2) {
		t.Fatal("first request should be allowed")
	}
	if !l.Allow("c1", 1, 2) {
		t.Fatal("second request should be allowed")
	}
	if l.Allow("c1", 1, 2) {
		t.Fatal("third request should be denied: burst exhausted")
	}
}

func TestRefillOverTime(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(func() time.Time { return now })

	if !l.Allow("c1", 1, 1) {
		t.Fatal("first request should be allowed")
	}
	if l.Allow("c1", 1, 1) {
		t.Fatal("second immediate request should be denied")
	}

	// advance one second at 1 rps => one token refilled.
	now = now.Add(time.Second)
	if !l.Allow("c1", 1, 1) {
		t.Fatal("request after refill should be allowed")
	}
}

func TestPerClientIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(func() time.Time { return now })

	if !l.Allow("c1", 1, 1) {
		t.Fatal("c1 first request should be allowed")
	}
	// c1 is now drained, but c2 has its own independent bucket.
	if !l.Allow("c2", 1, 1) {
		t.Fatal("c2 should have its own bucket and be allowed")
	}
	if l.Allow("c1", 1, 1) {
		t.Fatal("c1 should still be drained")
	}
}
