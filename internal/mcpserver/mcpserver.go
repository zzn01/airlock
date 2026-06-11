// Package mcpserver is airlock's MCP (Model Context Protocol) front-end. It
// serves a streamable-HTTP MCP server alongside the HTTP gateway and exposes the
// curated operations as MCP tools.
//
// It is a protocol adapter only: it holds no authorization or tenancy logic.
// Authentication maps a bearer token to a client with the same mechanism the
// gateway uses; the tool list is filtered to the client's grants; and every
// tool call is re-dispatched through gateway.Gateway.ServeHTTP, so the coarse
// group gate, endpoint allowlist, (group,backend) grant check, per-client rate
// limit, server-side data scoping (VictoriaLogs tenancy + mandatory filter), and
// audit all happen in the one place they already live.
package mcpserver

import (
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zzn01/airlock/internal/gateway"
)

const (
	serverName    = "airlock"
	serverVersion = "0.1.0"
)

// Server adapts the MCP protocol onto an existing gateway.Gateway.
type Server struct {
	g      *gateway.Gateway
	logger *slog.Logger
}

// New returns an MCP front-end over g. The logger is used for transport-level
// diagnostics only; per-request audit is emitted by the gateway pipeline.
func New(g *gateway.Gateway, logger *slog.Logger) *Server {
	return &Server{g: g, logger: logger}
}

// Handler returns the HTTP handler for the MCP streamable transport, wrapped
// with bearer-token authentication. Mount it at the configured path.
func (s *Server) Handler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(s.getServer, nil)
	return s.requireAuth(streamable)
}

// requireAuth rejects requests whose bearer token does not resolve to a
// configured client with 401 (an MCP-level auth error): no tools are exposed.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := gateway.BearerToken(r)
		if _, ok := s.g.ResolveClient(token); !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="airlock"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getServer builds the per-connection MCP server for the request's bearer
// token. requireAuth normally rejects unauthenticated requests before this
// runs; an unresolved token here yields a server with no tools (fail-closed).
func (s *Server) getServer(r *http.Request) *mcp.Server {
	return s.serverForToken(gateway.BearerToken(r))
}

// serverForToken constructs an MCP server exposing exactly the tools the client
// owning token may call. An empty/unknown token yields a no-tool server.
func (s *Server) serverForToken(token string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	client, ok := s.g.ResolveClient(token)
	if !ok {
		return srv
	}
	s.addTools(srv, client, token)
	return srv
}
