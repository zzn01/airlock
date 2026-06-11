// Package gateway is airlock's request pipeline: authenticate, route,
// authorize (default deny), rate-limit, execute, and audit — in that order.
package gateway

import (
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/zzn01/airlock/internal/audit"
	"github.com/zzn01/airlock/internal/backend"
	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/ratelimit"
)

// proxyPrefix is the namespace under which httpproxy instances are addressed.
// The first path segment after it names exactly one instance.
const proxyPrefix = "/b/"

// Gateway is the single authenticating entry point for the LLM side.
type Gateway struct {
	cfg      *config.Config
	reg      *backend.Registry
	proxies  *httpproxy.Manager
	limiter  *ratelimit.Limiter
	logger   *slog.Logger
	resolver TokenResolver // optional dynamic token resolver (e.g. web-login sessions)
	ready    atomic.Bool   // readiness reported by /readyz; see Handler.
}

// New constructs a Gateway. None of the arguments may be nil except logger,
// which when nil disables audit logging. The gateway starts ready: by the time
// New is called, config has been loaded and validated.
func New(cfg *config.Config, reg *backend.Registry, proxies *httpproxy.Manager, limiter *ratelimit.Limiter, logger *slog.Logger) *Gateway {
	g := &Gateway{cfg: cfg, reg: reg, proxies: proxies, limiter: limiter, logger: logger}
	g.ready.Store(true)
	return g
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
	client, ok := g.ResolveClient(token)
	if !ok {
		reason := "invalid_credential"
		if token == "" {
			reason = "missing_credential"
		}
		g.deny(w, ev, http.StatusUnauthorized, reason)
		return
	}
	ev.ClientID = client.ID

	// httpproxy instances live under /b/<name>/...; they use the group-based
	// authorization + data-scoping pipeline rather than the legacy op registry.
	if strings.HasPrefix(r.URL.Path, proxyPrefix) {
		g.serveProxy(w, r, ev, client)
		return
	}

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

// serveProxy is the group-based pipeline for httpproxy backends:
//
//	resolve instance (strict per-instance boundary) → coarse group gate →
//	endpoint allowlist → grant (default deny) → rate limit → scoped proxy.
func (g *Gateway) serveProxy(w http.ResponseWriter, r *http.Request, ev audit.Event, client config.Client) {
	rest := strings.TrimPrefix(r.URL.Path, proxyPrefix)
	name, up, _ := strings.Cut(rest, "/")
	if name == "" {
		g.deny(w, ev, http.StatusNotFound, "unknown_backend")
		return
	}
	upstreamPath := "/" + up

	// Resolve exactly one instance by name. There is no merged global path
	// table: the upstream path is matched only against this instance.
	inst, ok := g.proxies.Instance(name)
	if !ok {
		g.deny(w, ev, http.StatusNotFound, "unknown_backend")
		return
	}
	ev.Operation = name

	// Coarse gate: the client's groups must intersect the instance's
	// allowed_groups, else the backend is entirely off-limits.
	effective := inst.Effective(client.Groups)
	if len(effective) == 0 {
		g.deny(w, ev, http.StatusForbidden, "group_denied")
		return
	}

	// Endpoint must be in this instance's read-only allowlist.
	ep, ok := inst.MatchEndpoint(r.Method, upstreamPath)
	if !ok {
		g.deny(w, ev, http.StatusForbidden, "endpoint_not_allowed")
		return
	}
	ev.Operation = name + ":" + ep.ID

	// Some grant for an effective group must authorize this endpoint.
	grant, ok := inst.Grant(effective, ep.ID)
	if !ok {
		g.deny(w, ev, http.StatusForbidden, "not_granted")
		return
	}

	if !g.limiter.Allow(client.ID, client.RateLimit.RPS, client.RateLimit.Burst) {
		g.deny(w, ev, http.StatusTooManyRequests, "rate_limited")
		return
	}

	rec := &statusRecorder{ResponseWriter: w}
	inst.Proxy(rec, r, upstreamPath, ep, grant)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
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
