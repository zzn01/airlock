// Package config defines airlock's configuration model and loading.
//
// Configuration is read from a JSON file; a small set of environment variables
// may override individual fields.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
)

// Config is the top-level airlock configuration.
type Config struct {
	Listen   string     `json:"listen"`
	Groups   []string   `json:"groups"`
	Clients  []Client   `json:"clients"`
	Backends Backends   `json:"backends"`
	MCP      *MCPServer `json:"mcp"`
	Web      *WebAuth   `json:"web"`
}

// WebAuth configures the optional local-account web login front-end. It runs
// alongside the HTTP gateway on its own listen address and issues short-lived
// bearer tokens that resolve to a user's groups through the same access-control
// core static config clients use. When nil or disabled, no web login is served.
type WebAuth struct {
	Enable    bool           `json:"enable"`
	Listen    string         `json:"listen"`     // default ":8082" (applied by the caller)
	UsersFile string         `json:"users_file"` // path to the persisted local user store
	TokenTTL  string         `json:"token_ttl"`  // session lifetime as a Go duration, e.g. "12h"; default 12h
	Bootstrap *BootstrapUser `json:"bootstrap"`  // optional initial user created at startup if absent
	OIDC      *OIDC          `json:"oidc"`       // optional OIDC/SSO login, served alongside local accounts
}

// OIDC configures the optional OIDC/SSO login, a second identity source served
// alongside local accounts within the web front-end. When nil or disabled, only
// local login is offered; a disabled or unreachable provider never breaks local
// login. Group membership is derived from a configurable ID-token claim (and an
// optional admin override) and then drives the same access-control core as every
// other identity. ClientSecret is a secret reference (env:/file:/plain).
type OIDC struct {
	Enable       bool                `json:"enable"`
	Issuer       string              `json:"issuer"`        // OIDC issuer URL (discovery base)
	ClientID     string              `json:"client_id"`     // OAuth2 client id
	ClientSecret string              `json:"client_secret"` // OAuth2 client secret (secret reference)
	RedirectURL  string              `json:"redirect_url"`  // this server's /oidc/callback URL
	Scopes       []string            `json:"scopes"`        // default ["openid","profile","email"]
	GroupsClaim  string              `json:"groups_claim"`  // ID-token claim holding group values; default "groups"
	GroupMapping map[string][]string `json:"group_mapping"` // IdP claim value -> airlock group names
	Overrides    []OIDCOverride      `json:"overrides"`     // admin manual per-user group overrides (override-first)
}

// OIDCOverride pins a specific authenticated user to a fixed set of airlock
// groups, taking precedence over the claim-derived groups. A user matches when
// the override's Subject equals the OIDC `sub` claim or its Email equals the
// `email` claim. It is the operator's escape hatch independent of the IdP's
// asserted groups.
type OIDCOverride struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
}

// BootstrapUser is an initial local account created at startup when the user
// store does not already contain it, so a fresh deployment has a way in without
// hardcoded credentials. The password is a secret reference (env:/file:/plain).
type BootstrapUser struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Groups   []string `json:"groups"`
}

// MCPServer configures the optional MCP (Model Context Protocol) front-end. It
// runs alongside the HTTP gateway on its own listen address and path and reuses
// the same access-control core. When nil or disabled, only the HTTP gateway is
// served.
type MCPServer struct {
	Enable bool   `json:"enable"`
	Listen string `json:"listen"` // default ":8081" (applied by the caller)
	Path   string `json:"path"`   // default "/mcp" (applied by the caller)
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

	if c.MCP != nil && c.MCP.Enable && c.MCP.Path != "" && !strings.HasPrefix(c.MCP.Path, "/") {
		return fmt.Errorf("mcp path %q must begin with %q", c.MCP.Path, "/")
	}

	if c.Web != nil && c.Web.Enable {
		if c.Web.UsersFile == "" {
			return fmt.Errorf("web: users_file is required when web login is enabled")
		}
		if c.Web.TokenTTL != "" {
			d, err := time.ParseDuration(c.Web.TokenTTL)
			if err != nil {
				return fmt.Errorf("web: token_ttl %q: %w", c.Web.TokenTTL, err)
			}
			if d <= 0 {
				return fmt.Errorf("web: token_ttl %q must be positive", c.Web.TokenTTL)
			}
		}
		if b := c.Web.Bootstrap; b != nil {
			if b.Username == "" {
				return fmt.Errorf("web: bootstrap user has an empty username")
			}
			for _, g := range b.Groups {
				if !defined[g] {
					return fmt.Errorf("web: bootstrap user %q references undefined group %q", b.Username, g)
				}
			}
		}
		if o := c.Web.OIDC; o != nil && o.Enable {
			if err := o.validate(defined); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks an enabled OIDC block: the required provider fields are
// present and every group produced by the claim mapping or an override is a
// defined group (a typo fails fast rather than silently granting nothing).
func (o *OIDC) validate(defined map[string]bool) error {
	for field, val := range map[string]string{
		"issuer":        o.Issuer,
		"client_id":     o.ClientID,
		"client_secret": o.ClientSecret,
		"redirect_url":  o.RedirectURL,
	} {
		if val == "" {
			return fmt.Errorf("web.oidc: %s is required when OIDC is enabled", field)
		}
	}
	for claim, groups := range o.GroupMapping {
		for _, g := range groups {
			if !defined[g] {
				return fmt.Errorf("web.oidc: group_mapping for %q references undefined group %q", claim, g)
			}
		}
	}
	for i, ov := range o.Overrides {
		if ov.Subject == "" && ov.Email == "" {
			return fmt.Errorf("web.oidc: overrides[%d] must set subject or email", i)
		}
		for _, g := range ov.Groups {
			if !defined[g] {
				return fmt.Errorf("web.oidc: override %d references undefined group %q", i, g)
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
