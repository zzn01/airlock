// Command airlock runs the authenticating L7 gateway.
//
// Configuration is read from the JSON file named by AIRLOCK_CONFIG (default
// ./airlock.json). The AIRLOCK_LISTEN environment variable overrides the listen
// address.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
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
	logger.Info("airlock listening", "addr", addr)
	if err := http.ListenAndServe(addr, g); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
