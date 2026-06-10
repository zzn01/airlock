package gateway

import (
	"fmt"
	"log/slog"

	"github.com/zzn01/airlock/internal/backend"
	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/backend/redisro"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/ratelimit"
)

// Build is the composition root: it constructs the legacy op registry (Redis)
// and the httpproxy instance manager from cfg, then wires a Gateway. Clients
// connect lazily, so Build performs no I/O. At least one backend (redis or
// httpproxy) must be configured. A nil logger disables audit logging.
func Build(cfg *config.Config, logger *slog.Logger) (*Gateway, error) {
	reg := backend.NewRegistry()
	redisConfigured := cfg.Backends.Redis != nil && cfg.Backends.Redis.Addr != ""
	if redisConfigured {
		if err := reg.Register(redisro.New(redisro.Dial(cfg.Backends.Redis.Addr))); err != nil {
			return nil, fmt.Errorf("register redis backend: %w", err)
		}
	}

	proxies := httpproxy.NewManager()
	for _, pc := range cfg.Backends.HTTPProxy {
		inst, err := httpproxy.New(pc)
		if err != nil {
			return nil, fmt.Errorf("build httpproxy backend: %w", err)
		}
		if err := proxies.Add(inst); err != nil {
			return nil, err
		}
	}

	if !redisConfigured && len(cfg.Backends.HTTPProxy) == 0 {
		return nil, fmt.Errorf("config: at least one backend (redis or httpproxy) must be configured")
	}

	return New(cfg, reg, proxies, ratelimit.New(nil), logger), nil
}
