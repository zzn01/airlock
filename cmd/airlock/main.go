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
)

// shutdownTimeout bounds how long the server waits for in-flight requests to
// drain on SIGINT/SIGTERM before forcing the connections closed.
const shutdownTimeout = 15 * time.Second

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

	// Trap SIGINT/SIGTERM and shut down gracefully so in-flight requests drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("airlock listening", "addr", addr)
		serveErr <- srv.ListenAndServe()
	}()

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
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		logger.Info("shutdown complete")
	}
}
