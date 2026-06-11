package config

import (
	"fmt"
	"os"
	"strings"
)

// Secret reference prefixes. A configured secret value may be given indirectly
// so plaintext credentials need not live in the config file (or version
// control): "env:NAME" reads NAME from the environment, "file:/path" reads the
// (whitespace-trimmed) contents of a file. Any value without a recognized
// prefix is treated as a plaintext secret, for backward compatibility.
const (
	envRefPrefix  = "env:"
	fileRefPrefix = "file:"
)

// resolveSecret resolves a possibly-indirect secret reference to its plaintext
// value, using getenv as the environment source.
func resolveSecret(ref string, getenv func(string) string) (string, error) {
	switch {
	case strings.HasPrefix(ref, envRefPrefix):
		name := strings.TrimSpace(strings.TrimPrefix(ref, envRefPrefix))
		if name == "" {
			return "", fmt.Errorf("secret reference %q: empty environment variable name", ref)
		}
		v := getenv(name)
		if v == "" {
			return "", fmt.Errorf("secret reference %q: environment variable %s is not set", ref, name)
		}
		return v, nil
	case strings.HasPrefix(ref, fileRefPrefix):
		path := strings.TrimSpace(strings.TrimPrefix(ref, fileRefPrefix))
		if path == "" {
			return "", fmt.Errorf("secret reference %q: empty file path", ref)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("secret reference %q: %w", ref, err)
		}
		v := strings.TrimSpace(string(raw))
		if v == "" {
			return "", fmt.Errorf("secret reference %q: file %s is empty", ref, path)
		}
		return v, nil
	default:
		return ref, nil
	}
}

// resolveSecrets resolves every secret-bearing field in the config in place:
// client tokens, each httpproxy instance's upstream_auth header values, and the
// optional web bootstrap user's password.
func (c *Config) resolveSecrets(getenv func(string) string) error {
	for i := range c.Clients {
		v, err := resolveSecret(c.Clients[i].Token, getenv)
		if err != nil {
			return fmt.Errorf("client %q token: %w", c.Clients[i].ID, err)
		}
		c.Clients[i].Token = v
	}
	for i := range c.Backends.HTTPProxy {
		b := &c.Backends.HTTPProxy[i]
		for k, ref := range b.UpstreamAuth {
			v, err := resolveSecret(ref, getenv)
			if err != nil {
				return fmt.Errorf("httpproxy %q upstream_auth %q: %w", b.Name, k, err)
			}
			b.UpstreamAuth[k] = v
		}
	}
	if c.Web != nil && c.Web.Bootstrap != nil && c.Web.Bootstrap.Password != "" {
		v, err := resolveSecret(c.Web.Bootstrap.Password, getenv)
		if err != nil {
			return fmt.Errorf("web bootstrap user %q password: %w", c.Web.Bootstrap.Username, err)
		}
		c.Web.Bootstrap.Password = v
	}
	return nil
}
