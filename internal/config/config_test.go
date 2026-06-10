package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `{
  "listen": ":8080",
  "clients": [
    {"id": "llm-1", "token": "tok-abc", "allow": ["redis.get", "redis.scan"], "rate_limit": {"rps": 10, "burst": 20}}
  ],
  "backends": {"redis": {"addr": "localhost:6379"}}
}`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "airlock.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestLoadParsesClientsAndBackends(t *testing.T) {
	cfg, err := Load(writeTemp(t, sample), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", cfg.Listen)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(cfg.Clients))
	}
	c := cfg.Clients[0]
	if c.ID != "llm-1" || c.Token != "tok-abc" {
		t.Errorf("client = %+v, want id llm-1 token tok-abc", c)
	}
	if c.RateLimit.RPS != 10 || c.RateLimit.Burst != 20 {
		t.Errorf("rate limit = %+v, want 10/20", c.RateLimit)
	}
	if cfg.Backends["redis"].Addr != "localhost:6379" {
		t.Errorf("redis addr = %q", cfg.Backends["redis"].Addr)
	}
}

func TestLoadEnvOverridesListen(t *testing.T) {
	env := map[string]string{"AIRLOCK_LISTEN": ":9999"}
	cfg, err := Load(writeTemp(t, sample), env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("Listen = %q, want override :9999", cfg.Listen)
	}
}

func TestClientByTokenLookup(t *testing.T) {
	cfg, err := Load(writeTemp(t, sample), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c, ok := cfg.ClientByToken("tok-abc"); !ok || c.ID != "llm-1" {
		t.Errorf("ClientByToken(tok-abc) = %+v, %v", c, ok)
	}
	if _, ok := cfg.ClientByToken("nope"); ok {
		t.Error("ClientByToken(nope) should not resolve")
	}
	if _, ok := cfg.ClientByToken(""); ok {
		t.Error("ClientByToken(empty) should not resolve")
	}
}

func TestLoadRejectsDuplicateTokens(t *testing.T) {
	dup := `{"clients":[{"id":"a","token":"x"},{"id":"b","token":"x"}]}`
	if _, err := Load(writeTemp(t, dup), nil); err == nil {
		t.Error("expected error on duplicate tokens")
	}
}
