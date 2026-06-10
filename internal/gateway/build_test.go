package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zzn01/airlock/internal/config"
)

func TestBuildWiresRedisBackendAndAuth(t *testing.T) {
	cfg := &config.Config{
		Clients: []config.Client{{
			ID: "llm-1", Token: "tok", Allow: []string{"redis.get"},
			RateLimit: config.RateLimit{RPS: 10, Burst: 10},
		}},
		Backends: map[string]config.Backend{"redis": {Addr: "127.0.0.1:6379"}},
	}
	g, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// No token => 401, without ever touching Redis (auth precedes execution).
	req := httptest.NewRequest("GET", "/redis/get?key=x", nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}

	// The redis.scan route must be registered (even if not allowlisted here).
	if _, ok := g.reg.Lookup("GET", "/redis/scan"); !ok {
		t.Error("redis.scan route should be registered by Build")
	}
}

func TestBuildRequiresRedisBackend(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{{ID: "a", Token: "t"}}}
	if _, err := Build(cfg, nil); err == nil {
		t.Error("expected error when redis backend is not configured")
	}
}
