package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSecretPlaintext(t *testing.T) {
	got, err := resolveSecret("plain-token", func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "plain-token" {
		t.Errorf("got %q, want plain-token", got)
	}
}

func TestResolveSecretFromEnv(t *testing.T) {
	env := map[string]string{"GRAFANA_TOKEN": "s3cr3t"}
	get := func(k string) string { return env[k] }

	got, err := resolveSecret("env:GRAFANA_TOKEN", get)
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want s3cr3t", got)
	}
}

func TestResolveSecretFromEnvMissing(t *testing.T) {
	if _, err := resolveSecret("env:NOPE", func(string) string { return "" }); err == nil {
		t.Error("expected error when env var is unset")
	}
}

func TestResolveSecretFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := resolveSecret("file:"+p, func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("got %q, want file-secret (trailing newline trimmed)", got)
	}
}

func TestResolveSecretFromFileMissing(t *testing.T) {
	if _, err := resolveSecret("file:/no/such/path", func(string) string { return "" }); err == nil {
		t.Error("expected error when file is unreadable")
	}
}

func TestLoadResolvesSecretReferences(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client-token")
	if err := os.WriteFile(p, []byte("tok-from-file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := `{
	  "groups":["sre"],
	  "clients":[{"id":"a","token":"file:` + p + `","groups":["sre"]}],
	  "backends":{"httpproxy":[{
	    "name":"grafana","type":"grafana","base_url":"http://grafana","allowed_groups":["sre"],
	    "upstream_auth":{"Authorization":"env:GRAFANA_TOKEN"}
	  }]}
	}`
	env := map[string]string{"GRAFANA_TOKEN": "Bearer abc123"}
	cfg, err := Load(writeTemp(t, body), env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Clients[0].Token != "tok-from-file" {
		t.Errorf("client token = %q, want tok-from-file", cfg.Clients[0].Token)
	}
	if got := cfg.Backends.HTTPProxy[0].UpstreamAuth["Authorization"]; got != "Bearer abc123" {
		t.Errorf("upstream_auth = %q, want resolved from env", got)
	}
}

func TestLoadFailsOnUnresolvableSecret(t *testing.T) {
	body := `{
	  "groups":["sre"],
	  "clients":[{"id":"a","token":"env:MISSING_TOKEN","groups":["sre"]}],
	  "backends":{"redis":{"addr":"localhost:6379"}}
	}`
	if _, err := Load(writeTemp(t, body), map[string]string{}); err == nil {
		t.Error("expected Load to fail fast when a secret reference cannot be resolved")
	}
}
