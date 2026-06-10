// Package config defines airlock's configuration model and loading.
//
// Configuration is read from a JSON file; a small set of environment variables
// may override individual fields.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the top-level airlock configuration.
type Config struct {
	Listen   string             `json:"listen"`
	Clients  []Client           `json:"clients"`
	Backends map[string]Backend `json:"backends"`
}

// Client is an authenticated caller: a token, an identity, an explicit
// allowlist of operation ids, and a rate limit.
type Client struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Allow     []string  `json:"allow"`
	RateLimit RateLimit `json:"rate_limit"`
}

// RateLimit configures a client's token bucket. Non-positive values disable
// limiting for that client.
type RateLimit struct {
	RPS   float64 `json:"rps"`
	Burst float64 `json:"burst"`
}

// Backend is a backend definition (e.g. a Redis address).
type Backend struct {
	Addr string `json:"addr"`
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

	seen := make(map[string]string, len(cfg.Clients))
	for _, c := range cfg.Clients {
		if c.Token == "" {
			return nil, fmt.Errorf("client %q has an empty token", c.ID)
		}
		if other, dup := seen[c.Token]; dup {
			return nil, fmt.Errorf("clients %q and %q share a token", other, c.ID)
		}
		seen[c.Token] = c.ID
	}

	return &cfg, nil
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
