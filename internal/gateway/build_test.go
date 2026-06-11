package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
)

func TestExampleConfigLoadsAndBuilds(t *testing.T) {
	// The example config sources the Grafana upstream token via env:GRAFANA_TOKEN,
	// so the secret reference must resolve for the load to succeed.
	cfg, err := config.Load("../../airlock.example.json", map[string]string{"GRAFANA_TOKEN": "Bearer test-token"})
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if _, err := Build(cfg, nil); err != nil {
		t.Fatalf("build from example config: %v", err)
	}
}

func TestBuildWiresRedisBackendAndAuth(t *testing.T) {
	cfg := &config.Config{
		Clients: []config.Client{{
			ID: "llm-1", Token: "tok", Allow: []string{"redis.get"},
			RateLimit: config.RateLimit{RPS: 10, Burst: 10},
		}},
		Backends: config.Backends{Redis: &config.RedisBackend{Addr: "127.0.0.1:6379"}},
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

func TestBuildRequiresAtLeastOneBackend(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{{ID: "a", Token: "t"}}}
	if _, err := Build(cfg, nil); err == nil {
		t.Error("expected error when no backend is configured")
	}
}

func TestBuildWiresHTTPProxyWithoutRedis(t *testing.T) {
	cfg := &config.Config{
		Groups: []string{"sre"},
		Clients: []config.Client{{
			ID: "llm-1", Token: "tok", Groups: []string{"sre"},
			RateLimit: config.RateLimit{RPS: 10, Burst: 10},
		}},
		Backends: config.Backends{HTTPProxy: []httpproxy.Config{{
			Name: "prom", Type: "prometheus", BaseURL: "http://prometheus.invalid",
			AllowedGroups: []string{"sre"},
		}}},
	}
	if _, err := Build(cfg, nil); err != nil {
		t.Fatalf("Build with only httpproxy should succeed: %v", err)
	}
}
