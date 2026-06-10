package gateway

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zzn01/airlock/internal/backend"
	"github.com/zzn01/airlock/internal/backend/redisro"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/ratelimit"
)

type fakeRedis struct{ data map[string]string }

func (f *fakeRedis) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := f.data[k]
	return v, ok, nil
}
func (f *fakeRedis) Scan(_ context.Context, _ uint64, _ string, _ int64) ([]string, uint64, error) {
	return nil, 0, nil
}
func (f *fakeRedis) Exists(_ context.Context, k string) (bool, error) {
	_, ok := f.data[k]
	return ok, nil
}
func (f *fakeRedis) TTL(_ context.Context, _ string) (time.Duration, error) { return 0, nil }

// buildGateway wires a gateway whose only client "llm-1" (token "tok") may call
// redis.get but NOT redis.scan, with a generous rate limit by default.
func buildGateway(t *testing.T, rps, burst float64) (*Gateway, *bytes.Buffer) {
	t.Helper()
	cfg := &config.Config{
		Clients: []config.Client{{
			ID:        "llm-1",
			Token:     "tok",
			Allow:     []string{"redis.get"},
			RateLimit: config.RateLimit{RPS: rps, Burst: burst},
		}},
	}
	reg := backend.NewRegistry()
	if err := reg.Register(redisro.New(&fakeRedis{data: map[string]string{"user:1": "alice"}})); err != nil {
		t.Fatalf("register: %v", err)
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	now := time.Unix(0, 0)
	g := New(cfg, reg, ratelimit.New(func() time.Time { return now }), logger)
	return g, &logBuf
}

func do(g *Gateway, method, target, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func TestMissingTokenReturns401(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	rec := do(g, "GET", "/redis/get?key=user:1", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestInvalidTokenReturns401(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	rec := do(g, "GET", "/redis/get?key=user:1", "wrong-token")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAPIKeyHeaderAuthenticates(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	req := httptest.NewRequest("GET", "/redis/get?key=user:1", nil)
	req.Header.Set("X-API-Key", "tok")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 via X-API-Key", rec.Code)
	}
}

func TestAllowedOperationHappyPath(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	rec := do(g, "GET", "/redis/get?key=user:1", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "alice") {
		t.Errorf("body = %s, want value alice", rec.Body.String())
	}
}

func TestNonAllowlistedOperationReturns403(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	// redis.scan is a registered route but NOT in llm-1's allowlist.
	rec := do(g, "GET", "/redis/scan?pattern=*", "tok")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestUnknownRouteReturns404(t *testing.T) {
	g, _ := buildGateway(t, 100, 100)
	rec := do(g, "GET", "/redis/nope", "tok")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	g, _ := buildGateway(t, 1, 1) // burst of 1, no refill (clock frozen)
	if rec := do(g, "GET", "/redis/get?key=user:1", "tok"); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}
	if rec := do(g, "GET", "/redis/get?key=user:1", "tok"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", rec.Code)
	}
}

func TestAuditLogsDecisionAndClient(t *testing.T) {
	g, logBuf := buildGateway(t, 100, 100)

	do(g, "GET", "/redis/get?key=user:1", "tok") // allow
	do(g, "GET", "/redis/scan?pattern=*", "tok") // deny (403)

	logs := logBuf.String()
	if !strings.Contains(logs, `"decision":"allow"`) {
		t.Errorf("expected an allow decision in audit log:\n%s", logs)
	}
	if !strings.Contains(logs, `"decision":"deny"`) {
		t.Errorf("expected a deny decision in audit log:\n%s", logs)
	}
	if !strings.Contains(logs, `"client_id":"llm-1"`) {
		t.Errorf("expected client_id in audit log:\n%s", logs)
	}
}
