// Package gateway is airlock's request pipeline: authenticate, route,
// authorize (default deny), rate-limit, execute, and audit — in that order.
package gateway

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/zzn01/airlock/internal/audit"
	"github.com/zzn01/airlock/internal/backend"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/ratelimit"
)

// Gateway is the single authenticating entry point for the LLM side.
type Gateway struct {
	cfg     *config.Config
	reg     *backend.Registry
	limiter *ratelimit.Limiter
	logger  *slog.Logger
}

// New constructs a Gateway. None of the arguments may be nil except logger,
// which when nil disables audit logging.
func New(cfg *config.Config, reg *backend.Registry, limiter *ratelimit.Limiter, logger *slog.Logger) *Gateway {
	return &Gateway{cfg: cfg, reg: reg, limiter: limiter, logger: logger}
}

// statusRecorder wraps http.ResponseWriter to capture the status code an
// operation handler writes, for the audit record.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		ClientID:   "unknown",
	}

	// [1] Authenticate.
	token := bearerToken(r)
	client, ok := g.cfg.ClientByToken(token)
	if !ok {
		reason := "invalid_credential"
		if token == "" {
			reason = "missing_credential"
		}
		g.deny(w, ev, http.StatusUnauthorized, reason)
		return
	}
	ev.ClientID = client.ID

	// [2] Route — explicit endpoint addressing, no wildcard forwarding.
	op, ok := g.reg.Lookup(r.Method, r.URL.Path)
	if !ok {
		g.deny(w, ev, http.StatusNotFound, "unknown_route")
		return
	}
	ev.Operation = op.ID

	// [3] Authorize — default deny.
	if !client.Allowed(op.ID) {
		g.deny(w, ev, http.StatusForbidden, "not_allowed")
		return
	}

	// [4] Rate limit.
	if !g.limiter.Allow(client.ID, client.RateLimit.RPS, client.RateLimit.Burst) {
		g.deny(w, ev, http.StatusTooManyRequests, "rate_limited")
		return
	}

	// [5] Execute, capturing the outcome status.
	rec := &statusRecorder{ResponseWriter: w}
	op.Handler(rec, r)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}

	// [6] Audit the allowed request and its outcome.
	ev.Decision = audit.Allow
	ev.Status = rec.status
	audit.Log(g.logger, ev)
}

// deny writes status as an error response and audits the denial.
func (g *Gateway) deny(w http.ResponseWriter, ev audit.Event, status int, reason string) {
	ev.Decision = audit.Deny
	ev.Reason = reason
	ev.Status = status
	audit.Log(g.logger, ev)
	http.Error(w, http.StatusText(status), status)
}

// bearerToken extracts the credential from the Authorization: Bearer header or
// the X-API-Key header.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, found := strings.CutPrefix(h, "Bearer "); found {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}
