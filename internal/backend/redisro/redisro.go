// Package redisro is a read-only Redis backend. It exposes a curated set of
// read HTTP operations (GET/SCAN/EXISTS/TTL) and nothing else.
//
// The single seam to Redis is the ReadClient interface, whose method set is
// deliberately limited to read commands. There is no code path in this package
// that issues a write or destructive command, and a reflection-based test
// guards that surface.
package redisro

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zzn01/airlock/internal/backend"
)

// ReadClient is the read-only view of Redis used by the tool. It MUST contain
// only read commands — see TestReadClientSurfaceHasNoWriteMethods.
type ReadClient interface {
	Get(ctx context.Context, key string) (value string, found bool, err error)
	Scan(ctx context.Context, cursor uint64, match string, count int64) (keys []string, next uint64, err error)
	Exists(ctx context.Context, key string) (found bool, err error)
	TTL(ctx context.Context, key string) (ttl time.Duration, err error)
}

// Tool is a read-only Redis backend.
type Tool struct {
	client ReadClient
}

// New returns a Tool backed by client.
func New(client ReadClient) *Tool { return &Tool{client: client} }

// Name implements backend.Backend.
func (t *Tool) Name() string { return "redis" }

// Operations implements backend.Backend. All operations are GETs.
func (t *Tool) Operations() []backend.Operation {
	return []backend.Operation{
		{ID: "redis.get", Method: http.MethodGet, Path: "/redis/get", Handler: t.handleGet},
		{ID: "redis.scan", Method: http.MethodGet, Path: "/redis/scan", Handler: t.handleScan},
		{ID: "redis.exists", Method: http.MethodGet, Path: "/redis/exists", Handler: t.handleExists},
		{ID: "redis.ttl", Method: http.MethodGet, Path: "/redis/ttl", Handler: t.handleTTL},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (t *Tool) handleGet(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing required query parameter: key", http.StatusBadRequest)
		return
	}
	value, found, err := t.client.Get(r.Context(), key)
	if err != nil {
		http.Error(w, "backend error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"key": key, "value": value, "found": found})
}

func (t *Tool) handleScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pattern := q.Get("pattern")
	if pattern == "" {
		pattern = "*"
	}
	cursor := parseUint(q.Get("cursor"), 0)
	count := int64(parseUint(q.Get("count"), 100))

	keys, next, err := t.client.Scan(r.Context(), cursor, pattern, count)
	if err != nil {
		http.Error(w, "backend error", http.StatusBadGateway)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, map[string]any{"keys": keys, "cursor": next})
}

func (t *Tool) handleExists(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing required query parameter: key", http.StatusBadRequest)
		return
	}
	found, err := t.client.Exists(r.Context(), key)
	if err != nil {
		http.Error(w, "backend error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"key": key, "exists": found})
}

func (t *Tool) handleTTL(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing required query parameter: key", http.StatusBadRequest)
		return
	}
	ttl, err := t.client.TTL(r.Context(), key)
	if err != nil {
		http.Error(w, "backend error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"key": key, "ttl_seconds": int64(ttl.Seconds())})
}

func parseUint(s string, def uint64) uint64 {
	if s == "" {
		return def
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}
