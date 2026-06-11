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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
)

const (
	serverName    = "airlock"
	serverVersion = "0.1.0"

	// tokenInfoWindow is the expiry stamped on the per-request TokenInfo. The
	// SDK's bearer-token middleware requires a non-zero, future expiry, but it is
	// not the source of truth for token lifetime: every request is re-resolved
	// through gateway.ResolveClient, which is where real expiry/revocation lives.
	tokenInfoWindow = time.Hour
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
//
// Authentication uses the SDK's auth.RequireBearerToken middleware, which
// records a TokenInfo (carrying a stable per-client user id) in the request
// context. The streamable transport captures that user id when a session is
// created and rejects (403) any later request on the same session whose user id
// differs — binding every MCP session to the client that created it. Without
// this, a client that learned another client's Mcp-Session-Id could ride that
// session with the creator's identity, grants, token, and tenancy. normalizeAuth
// lets X-API-Key callers travel the same path as Authorization: Bearer.
func (s *Server) Handler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(s.getServer, nil)
	authed := auth.RequireBearerToken(s.verifyToken, nil)(streamable)
	return normalizeAuth(authed)
}

// verifyToken resolves the bearer token to a client and returns a TokenInfo
// whose UserID is the stable principal binding the SDK uses to pin a session to
// its creator. An unresolved token fails closed (401, no tools).
func (s *Server) verifyToken(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	client, ok := s.g.ResolveClient(token)
	if !ok {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{
		UserID:     sessionUserID(client, token),
		Expiration: time.Now().Add(tokenInfoWindow),
	}, nil
}

// sessionUserID is the stable identifier a session is bound to. It is the
// resolved client identity (static config id or web-login username), so a
// session created by client A is only usable by subsequent requests that also
// authenticate as A. If the resolved identity is ever empty it falls back to a
// token-derived id: an empty user id silently disables the SDK's hijack guard,
// so the binding must never be empty.
func sessionUserID(client config.Client, token string) string {
	if client.ID != "" {
		return client.ID
	}
	sum := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(sum[:])
}

// normalizeAuth lets callers that present the credential via X-API-Key reach the
// bearer-token middleware: it copies the resolved token into an Authorization
// header when one is absent, preserving the HTTP pipeline's dual-header rule.
func normalizeAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			if tok := gateway.BearerToken(r); tok != "" {
				r.Header.Set("Authorization", "Bearer "+tok)
			}
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
