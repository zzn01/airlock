package gateway

import "net/http"

// healthzPath and readyzPath are the unauthenticated probe routes. They live
// outside the auth/authz pipeline and the /b/<instance> backend routing: a
// load balancer or orchestrator must be able to probe liveness and readiness
// without holding a client credential.
const (
	healthzPath = "/healthz"
	readyzPath  = "/readyz"
)

// Handler returns the top-level HTTP handler for the process: the
// unauthenticated liveness (/healthz) and readiness (/readyz) probes, plus the
// authenticated gateway pipeline (g itself) for every other path. The probes
// are registered on a dedicated mux entry and never reach the auth pipeline or
// backend routing.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(healthzPath, g.handleHealthz)
	mux.HandleFunc(readyzPath, g.handleReadyz)
	mux.Handle("/", g) // everything else flows through the gated pipeline
	return mux
}

// handleHealthz is the liveness probe: 200 whenever the process is up,
// independent of readiness, so a not-ready instance is not killed.
func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeProbe(w, http.StatusOK, "ok")
}

// handleReadyz is the readiness probe: 200 once config is loaded and the server
// is ready, 503 while readiness is cleared (e.g. during graceful shutdown) so
// traffic drains away from the instance.
func (g *Gateway) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !g.ready.Load() {
		writeProbe(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	writeProbe(w, http.StatusOK, "ready")
}

// SetReady sets the readiness state reported by /readyz.
func (g *Gateway) SetReady(ready bool) { g.ready.Store(ready) }

func writeProbe(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}
