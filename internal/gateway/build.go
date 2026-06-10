package gateway

import (
	"fmt"
	"log/slog"

	"github.com/zzn01/airlock/internal/backend"
	"github.com/zzn01/airlock/internal/backend/redisro"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/ratelimit"
)

// Build is the composition root: it constructs the backend registry and a
// Gateway from cfg. The Redis client connects lazily, so Build performs no I/O.
// A nil logger disables audit logging.
func Build(cfg *config.Config, logger *slog.Logger) (*Gateway, error) {
	redisCfg, ok := cfg.Backends["redis"]
	if !ok || redisCfg.Addr == "" {
		return nil, fmt.Errorf("config: backends.redis.addr is required")
	}

	reg := backend.NewRegistry()
	if err := reg.Register(redisro.New(redisro.Dial(redisCfg.Addr))); err != nil {
		return nil, fmt.Errorf("register redis backend: %w", err)
	}

	return New(cfg, reg, ratelimit.New(nil), logger), nil
}
