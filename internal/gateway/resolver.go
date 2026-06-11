package gateway

import "github.com/zzn01/airlock/internal/config"

// TokenResolver maps a bearer token to a client identity. It is the seam by
// which dynamically-issued tokens (e.g. the web-login session store) feed the
// gateway's existing access-control core: the resolved client carries groups
// that are run through exactly the same authorization the static config clients
// use. Returns false for unknown, expired, or revoked tokens.
type TokenResolver interface {
	ClientByToken(token string) (config.Client, bool)
}

// SetTokenResolver registers an additional dynamic token resolver. It is
// consulted only after the static config clients, so config clients always take
// precedence and continue to resolve unchanged. A nil resolver clears it.
func (g *Gateway) SetTokenResolver(r TokenResolver) { g.resolver = r }

// ResolveClient maps a bearer token to a client identity, checking static
// config clients first and then any registered dynamic resolver. It is the one
// place both the HTTP pipeline and the MCP front-end resolve identity, so both
// accept web-issued tokens without duplicating logic.
func (g *Gateway) ResolveClient(token string) (config.Client, bool) {
	if c, ok := g.cfg.ClientByToken(token); ok {
		return c, true
	}
	if g.resolver != nil {
		return g.resolver.ClientByToken(token)
	}
	return config.Client{}, false
}
