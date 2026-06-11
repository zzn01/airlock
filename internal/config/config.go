// Package config defines airlock's configuration model and loading.
//
// Configuration is read from a JSON file; a small set of environment variables
// may override individual fields.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
)

// Config is the top-level airlock configuration.
type Config struct {
	Listen   string   `json:"listen"`
	Groups   []string `json:"groups"`
	Clients  []Client `json:"clients"`
	Backends Backends `json:"backends"`
}

// Backends holds the configured backends. Both are optional, but at least one
// must be present (enforced by gateway.Build).
type Backends struct {
	Redis     *RedisBackend      `json:"redis"`
	HTTPProxy []httpproxy.Config `json:"httpproxy"`
}

// RedisBackend is the read-only Redis tool's connection config.
type RedisBackend struct {
	Addr string `json:"addr"`
}

// Client is an authenticated caller: a token, an identity, the groups it
// belongs to, an explicit allowlist of legacy operation ids (Redis), and a
// rate limit. Group membership decides access to httpproxy backends.
type Client struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Groups    []string  `json:"groups"`
	Allow     []string  `json:"allow"`
	RateLimit RateLimit `json:"rate_limit"`
}

// RateLimit configures a client's token bucket. Non-positive values disable
// limiting for that client.
type RateLimit struct {
	RPS   float64 `json:"rps"`
	Burst float64 `json:"burst"`
}

// Allowed reports whether the client's allowlist permits the given operation
// id. The default is deny: an empty allowlist permits nothing.
func (c Client) Allowed(opID string) bool {
	for _, a := range c.Allow {
		if a == opID {
			return true
		}
	}
	return false
}

// Load reads and parses the JSON config at path, then applies overrides from
// env. If env is nil, the process environment is consulted. Recognized
// overrides: AIRLOCK_LISTEN.
func Load(path string, env map[string]string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	get := func(k string) string {
		if env != nil {
			return env[k]
		}
		return os.Getenv(k)
	}
	if v := get("AIRLOCK_LISTEN"); v != "" {
		cfg.Listen = v
	}

	// Resolve env:/file: secret references before validation so that
	// uniqueness and non-empty checks see the effective plaintext values.
	if err := cfg.resolveSecrets(get); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate fails fast on a malformed configuration: unknown backend types,
// duplicate backend instance names, missing required fields (e.g. base_url),
// references to undefined groups, and clients with empty or duplicate tokens.
// It is invoked by Load at startup so a typo fails loudly rather than silently
// denying (or, worse, silently widening) access at request time.
func (c *Config) Validate() error {
	defined := make(map[string]bool, len(c.Groups))
	for _, g := range c.Groups {
		defined[g] = true
	}

	seen := make(map[string]string, len(c.Clients))
	for _, cl := range c.Clients {
		if cl.Token == "" {
			return fmt.Errorf("client %q has an empty token", cl.ID)
		}
		if other, dup := seen[cl.Token]; dup {
			return fmt.Errorf("clients %q and %q share a token", other, cl.ID)
		}
		seen[cl.Token] = cl.ID
		for _, g := range cl.Groups {
			if !defined[g] {
				return fmt.Errorf("client %q references undefined group %q", cl.ID, g)
			}
		}
	}

	names := make(map[string]bool, len(c.Backends.HTTPProxy))
	for _, b := range c.Backends.HTTPProxy {
		// Static, construction-independent invariants (name, known type,
		// usable base_url) are owned by the backend type itself.
		if err := b.Validate(); err != nil {
			return err
		}
		if names[b.Name] {
			return fmt.Errorf("duplicate httpproxy instance name %q", b.Name)
		}
		names[b.Name] = true
		for _, g := range b.AllowedGroups {
			if !defined[g] {
				return fmt.Errorf("httpproxy %q allowed_groups references undefined group %q", b.Name, g)
			}
		}
		for _, gr := range b.Grants {
			if !defined[gr.Group] {
				return fmt.Errorf("httpproxy %q grant references undefined group %q", b.Name, gr.Group)
			}
		}
	}
	return nil
}

// ClientByToken returns the client owning token. An empty token never resolves.
func (c *Config) ClientByToken(token string) (Client, bool) {
	if token == "" {
		return Client{}, false
	}
	for _, cl := range c.Clients {
		if cl.Token == token {
			return cl, true
		}
	}
	return Client{}, false
}
