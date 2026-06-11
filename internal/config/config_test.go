package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `{
  "listen": ":8080",
  "groups": ["team-a", "team-b"],
  "clients": [
    {"id": "llm-1", "token": "tok-abc", "groups": ["team-a"], "allow": ["redis.get", "redis.scan"], "rate_limit": {"rps": 10, "burst": 20}}
  ],
  "backends": {
    "redis": {"addr": "localhost:6379"},
    "httpproxy": [
      {
        "name": "victorialogs-a",
        "type": "victorialogs",
        "base_url": "http://vl-a:9428",
        "allowed_groups": ["team-a"],
        "grants": [{"group": "team-a", "endpoints": ["vl.query"], "scope": {"victorialogs": {"account_id": "1", "mandatory_filter": "app:\"a\""}}}]
      }
    ]
  }
}`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "airlock.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestLoadParsesMCPSection(t *testing.T) {
	body := `{
	  "groups": ["team-a"],
	  "clients": [{"id": "llm-1", "token": "tok-abc", "groups": ["team-a"]}],
	  "backends": {"redis": {"addr": "localhost:6379"}},
	  "mcp": {"enable": true, "listen": ":9000", "path": "/mcp"}
	}`
	cfg, err := Load(writeTemp(t, body), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCP == nil || !cfg.MCP.Enable || cfg.MCP.Listen != ":9000" || cfg.MCP.Path != "/mcp" {
		t.Errorf("mcp = %+v, want enabled :9000 /mcp", cfg.MCP)
	}
}

func TestLoadRejectsMCPPathWithoutLeadingSlash(t *testing.T) {
	body := `{
	  "groups": ["team-a"],
	  "clients": [{"id": "llm-1", "token": "tok-abc", "groups": ["team-a"]}],
	  "backends": {"redis": {"addr": "localhost:6379"}},
	  "mcp": {"enable": true, "path": "mcp"}
	}`
	if _, err := Load(writeTemp(t, body), nil); err == nil {
		t.Fatal("expected error for mcp path without leading slash, got nil")
	}
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
	if len(c.Groups) != 1 || c.Groups[0] != "team-a" {
		t.Errorf("client groups = %v, want [team-a]", c.Groups)
	}
	if c.RateLimit.RPS != 10 || c.RateLimit.Burst != 20 {
		t.Errorf("rate limit = %+v, want 10/20", c.RateLimit)
	}
	if cfg.Backends.Redis == nil || cfg.Backends.Redis.Addr != "localhost:6379" {
		t.Errorf("redis addr = %+v", cfg.Backends.Redis)
	}
	if len(cfg.Backends.HTTPProxy) != 1 || cfg.Backends.HTTPProxy[0].Name != "victorialogs-a" {
		t.Errorf("httpproxy = %+v, want one victorialogs-a", cfg.Backends.HTTPProxy)
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

func TestLoadRejectsUndefinedClientGroup(t *testing.T) {
	bad := `{"groups":["team-a"],"clients":[{"id":"a","token":"x","groups":["ghost"]}]}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: client references a group not in groups[]")
	}
}

func TestLoadRejectsUndefinedBackendGroup(t *testing.T) {
	bad := `{
	  "groups":["team-a"],
	  "clients":[{"id":"a","token":"x","groups":["team-a"]}],
	  "backends":{"httpproxy":[{"name":"vl","type":"victorialogs","base_url":"http://x","allowed_groups":["ghost"]}]}
	}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: backend allowed_groups references an undefined group")
	}
}

func TestLoadRejectsUndefinedGrantGroup(t *testing.T) {
	bad := `{
	  "groups":["team-a"],
	  "clients":[{"id":"a","token":"x","groups":["team-a"]}],
	  "backends":{"httpproxy":[{"name":"vl","type":"victorialogs","base_url":"http://x","allowed_groups":["team-a"],"grants":[{"group":"ghost","endpoints":["vl.query"]}]}]}
	}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: grant references an undefined group")
	}
}

func TestLoadRejectsUnknownBackendType(t *testing.T) {
	bad := `{
	  "groups":["team-a"],
	  "clients":[{"id":"a","token":"x","groups":["team-a"]}],
	  "backends":{"httpproxy":[{"name":"vl","type":"mystery","base_url":"http://x","allowed_groups":["team-a"]}]}
	}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: unknown backend type")
	}
}

func TestLoadRejectsMissingBaseURL(t *testing.T) {
	bad := `{
	  "groups":["team-a"],
	  "clients":[{"id":"a","token":"x","groups":["team-a"]}],
	  "backends":{"httpproxy":[{"name":"vl","type":"victorialogs","allowed_groups":["team-a"]}]}
	}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: backend base_url is required")
	}
}

func TestLoadRejectsDuplicateBackendInstanceName(t *testing.T) {
	bad := `{
	  "groups":["team-a"],
	  "clients":[{"id":"a","token":"x","groups":["team-a"]}],
	  "backends":{"httpproxy":[
	    {"name":"vl","type":"victorialogs","base_url":"http://x","allowed_groups":["team-a"]},
	    {"name":"vl","type":"victorialogs","base_url":"http://y","allowed_groups":["team-a"]}
	  ]}
	}`
	if _, err := Load(writeTemp(t, bad), nil); err == nil {
		t.Error("expected error: duplicate httpproxy instance name")
	}
}
