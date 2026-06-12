// Command airlock runs the authenticating L7 gateway.
//
// Configuration is read from the JSON file named by AIRLOCK_CONFIG (default
// ./airlock.json). The AIRLOCK_LISTEN environment variable overrides the listen
// address. The process serves unauthenticated /healthz and /readyz probes and
// shuts down gracefully on SIGINT/SIGTERM, draining in-flight requests.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
	"github.com/zzn01/airlock/internal/mcpserver"
	"github.com/zzn01/airlock/internal/webauth"
)

// shutdownTimeout bounds how long the server waits for in-flight requests to
// drain on SIGINT/SIGTERM before forcing the connections closed.
const shutdownTimeout = 15 * time.Second

// Defaults for the optional MCP front-end when enabled without explicit values.
const (
	defaultMCPListen = ":8081"
	defaultMCPPath   = "/mcp"
)

// Defaults for the optional web-login front-end when enabled without explicit
// values.
const (
	defaultWebListen = ":8082"
	defaultTokenTTL  = 12 * time.Hour
)

// oidcDiscoveryTimeout bounds the OIDC provider discovery at startup so an
// unreachable issuer cannot hang the boot; on timeout, local login still serves.
const oidcDiscoveryTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	path := os.Getenv("AIRLOCK_CONFIG")
	if path == "" {
		path = "airlock.json"
	}

	cfg, err := config.Load(path, nil)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	g, err := gateway.Build(cfg, logger)
	if err != nil {
		logger.Error("build gateway", "error", err)
		os.Exit(1)
	}

	addr := cfg.Listen
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{Addr: addr, Handler: g.Handler()}

	// Optional MCP front-end, served alongside the gateway on its own address
	// and path. It reuses the same gateway pipeline for every tool call.
	mcpSrv := buildMCPServer(cfg, g, logger)

	// Optional web-login front-end, served alongside the gateway on its own
	// address. It issues bearer tokens that resolve to a user's groups through
	// the gateway's token-resolver seam, reusing the same access-control core.
	webSrv, err := buildWebServer(cfg, g, logger)
	if err != nil {
		logger.Error("build web front-end", "error", err)
		os.Exit(1)
	}

	// Trap SIGINT/SIGTERM and shut down gracefully so in-flight requests drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 3)
	go func() {
		logger.Info("airlock listening", "addr", addr)
		serveErr <- srv.ListenAndServe()
	}()
	if mcpSrv != nil {
		go func() {
			logger.Info("airlock mcp listening", "addr", mcpSrv.Addr)
			serveErr <- mcpSrv.ListenAndServe()
		}()
	}
	if webSrv != nil {
		go func() {
			logger.Info("airlock web login listening", "addr", webSrv.Addr)
			serveErr <- webSrv.ListenAndServe()
		}()
	}

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		stop() // restore default signal handling so a second signal aborts hard
		logger.Info("shutdown signal received, draining", "timeout", shutdownTimeout)
		g.SetReady(false) // fail readiness so load balancers stop routing here

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if mcpSrv != nil {
			if err := mcpSrv.Shutdown(shutdownCtx); err != nil {
				logger.Error("graceful shutdown failed (mcp)", "error", err)
			}
		}
		if webSrv != nil {
			if err := webSrv.Shutdown(shutdownCtx); err != nil {
				logger.Error("graceful shutdown failed (web)", "error", err)
			}
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		logger.Info("shutdown complete")
	}
}

// buildMCPServer constructs the MCP front-end's http.Server if it is enabled in
// the config, mounting the streamable MCP handler at the configured path.
// Returns nil when the MCP front-end is disabled.
func buildMCPServer(cfg *config.Config, g *gateway.Gateway, logger *slog.Logger) *http.Server {
	if cfg.MCP == nil || !cfg.MCP.Enable {
		return nil
	}
	addr := cfg.MCP.Listen
	if addr == "" {
		addr = defaultMCPListen
	}
	mountPath := cfg.MCP.Path
	if mountPath == "" {
		mountPath = defaultMCPPath
	}
	mux := http.NewServeMux()
	mux.Handle(mountPath, mcpserver.New(g, logger).Handler())
	logger.Info("airlock mcp front-end enabled", "addr", addr, "path", mountPath)
	return &http.Server{Addr: addr, Handler: mux}
}

// buildWebServer constructs the web-login front-end's http.Server if it is
// enabled in the config. It loads (creating on first save) the persisted user
// store, applies the optional bootstrap user, wires an in-memory session store
// as the gateway's dynamic token resolver, and mounts the login handler.
// Returns (nil, nil) when the web front-end is disabled.
func buildWebServer(cfg *config.Config, g *gateway.Gateway, logger *slog.Logger) (*http.Server, error) {
	if cfg.Web == nil || !cfg.Web.Enable {
		return nil, nil
	}

	users, err := webauth.LoadUserStore(cfg.Web.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("load user store: %w", err)
	}
	if b := cfg.Web.Bootstrap; b != nil {
		created, err := users.EnsureUser(b.Username, b.Password, b.Groups)
		if err != nil {
			return nil, fmt.Errorf("bootstrap user: %w", err)
		}
		if created {
			logger.Info("web bootstrap user created", "username", b.Username)
		}
	}

	ttl := defaultTokenTTL
	if cfg.Web.TokenTTL != "" {
		// Already validated by config.Load; parse cannot fail here.
		ttl, _ = time.ParseDuration(cfg.Web.TokenTTL)
	}
	sessions := webauth.NewSessionStore(ttl, nil)
	g.SetTokenResolver(sessions)

	web := webauth.NewServer(users, sessions, logger)

	// Optional OIDC/SSO login, a second identity source alongside local
	// accounts. Provider discovery reaches the issuer, so a failure here must
	// NOT break startup or local login: log and continue with local-only login.
	if o := cfg.Web.OIDC; o != nil && o.Enable {
		ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
		provider, err := webauth.NewOIDCProvider(ctx, o)
		cancel()
		if err != nil {
			logger.Warn("oidc disabled: provider setup failed; local login unaffected", "error", err)
		} else {
			web.EnableOIDC(provider, o)
			logger.Info("airlock oidc login enabled", "issuer", o.Issuer)
		}
	}

	addr := cfg.Web.Listen
	if addr == "" {
		addr = defaultWebListen
	}
	logger.Info("airlock web login front-end enabled", "addr", addr, "token_ttl", ttl)
	return &http.Server{Addr: addr, Handler: web.Handler()}, nil
}
