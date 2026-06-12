package gateway

import (
	"net/http"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
)

// This file exposes the read-only seams the MCP front-end (internal/mcpserver)
// needs to introspect identity and instances for tool-list filtering, and to
// re-dispatch tool calls through the very same pipeline as the HTTP path. The
// Gateway itself is an http.Handler via ServeHTTP; the MCP adapter holds no
// authorization or tenancy logic of its own.

// Config returns the gateway's configuration. The MCP adapter uses it to read
// group/grant membership when deciding which tools to expose. Token resolution
// goes through Gateway.ResolveClient so web-issued tokens are accepted too.
func (g *Gateway) Config() *config.Config { return g.cfg }

// Proxies returns the httpproxy instance manager, used to enumerate reachable
// instances when generating the per-client tool list.
func (g *Gateway) Proxies() *httpproxy.Manager { return g.proxies }

// HasOperation reports whether an op-pipeline route is registered. The MCP
// adapter uses it so a redis tool is not advertised when the redis backend is
// not configured (its operations are absent from the registry).
func (g *Gateway) HasOperation(method, path string) bool {
	_, ok := g.reg.Lookup(method, path)
	return ok
}

// BearerToken extracts the request credential using the same rule as the HTTP
// pipeline: the Authorization: Bearer header, then the X-API-Key header.
func BearerToken(r *http.Request) string { return bearerToken(r) }
