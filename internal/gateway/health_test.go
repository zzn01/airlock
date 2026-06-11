package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthEndpointsUnauthenticated asserts the liveness and readiness probes
// return 200 with no credential and are not subject to the default-deny gate,
// while a gated route served by the same handler still requires auth.
func TestHealthEndpointsUnauthenticated(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	h := g.Handler()

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest("GET", path, nil) // deliberately no credential
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s without credential = %d, want 200", path, rec.Code)
		}
	}

	// The same handler must still default-deny a gated route presented without
	// a credential: the probes are a separate, ungated path, not a hole.
	req := httptest.NewRequest("GET", "/redis/get?key=x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("gated route without credential = %d, want 401", rec.Code)
	}
}

// TestReadyzReflectsReadiness verifies /readyz reports not-ready once readiness
// is cleared (as graceful shutdown does), while /healthz stays up.
func TestReadyzReflectsReadiness(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	g.SetReady(false)
	h := g.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz when not ready = %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz when not ready = %d, want 200 (liveness independent of readiness)", rec.Code)
	}
}
