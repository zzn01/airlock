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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
	"github.com/zzn01/airlock/internal/mcpserver"
)

// shutdownTimeout bounds how long the server waits for in-flight requests to
// drain on SIGINT/SIGTERM before forcing the connections closed.
const shutdownTimeout = 15 * time.Second

// Defaults for the optional MCP front-end when enabled without explicit values.
const (
	defaultMCPListen = ":8081"
	defaultMCPPath   = "/mcp"
)

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

	// Trap SIGINT/SIGTERM and shut down gracefully so in-flight requests drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 2)
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
