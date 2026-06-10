package redisro

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeRedis is an in-memory ReadClient for deterministic tests — no network.
type fakeRedis struct {
	data map[string]string
	ttl  map[string]time.Duration
}

func (f *fakeRedis) Get(_ context.Context, key string) (string, bool, error) {
	v, ok := f.data[key]
	return v, ok, nil
}

func (f *fakeRedis) Scan(_ context.Context, _ uint64, match string, _ int64) ([]string, uint64, error) {
	var keys []string
	for k := range f.data {
		if match == "" || match == "*" || strings.HasPrefix(k, strings.TrimSuffix(match, "*")) {
			keys = append(keys, k)
		}
	}
	return keys, 0, nil
}

func (f *fakeRedis) Exists(_ context.Context, key string) (bool, error) {
	_, ok := f.data[key]
	return ok, nil
}

func (f *fakeRedis) TTL(_ context.Context, key string) (time.Duration, error) {
	return f.ttl[key], nil
}

func newTool() *Tool {
	return New(&fakeRedis{
		data: map[string]string{"user:1": "alice", "user:2": "bob"},
		ttl:  map[string]time.Duration{"user:1": 30 * time.Second},
	})
}

// handlerFor returns the handler for the operation with the given id.
func handlerFor(t *testing.T, tool *Tool, id string) http.HandlerFunc {
	t.Helper()
	for _, o := range tool.Operations() {
		if o.ID == id {
			return o.Handler
		}
	}
	t.Fatalf("no operation %q", id)
	return nil
}

func TestGetHappyPath(t *testing.T) {
	tool := newTool()
	req := httptest.NewRequest("GET", "/redis/get?key=user:1", nil)
	rec := httptest.NewRecorder()
	handlerFor(t, tool, "redis.get")(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Found bool   `json:"found"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Key != "user:1" || body.Value != "alice" || !body.Found {
		t.Errorf("body = %+v", body)
	}
}

func TestGetMissingKeyParam(t *testing.T) {
	tool := newTool()
	req := httptest.NewRequest("GET", "/redis/get", nil)
	rec := httptest.NewRecorder()
	handlerFor(t, tool, "redis.get")(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing key", rec.Code)
	}
}

func TestScanHappyPath(t *testing.T) {
	tool := newTool()
	req := httptest.NewRequest("GET", "/redis/scan?pattern=user:*", nil)
	rec := httptest.NewRecorder()
	handlerFor(t, tool, "redis.scan")(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Keys   []string `json:"keys"`
		Cursor uint64   `json:"cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 2 {
		t.Errorf("keys = %v, want 2 entries", body.Keys)
	}
}

func TestExistsAndTTL(t *testing.T) {
	tool := newTool()

	rec := httptest.NewRecorder()
	handlerFor(t, tool, "redis.exists")(rec, httptest.NewRequest("GET", "/redis/exists?key=user:1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"exists":true`) {
		t.Errorf("exists: code=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handlerFor(t, tool, "redis.ttl")(rec, httptest.NewRequest("GET", "/redis/ttl?key=user:1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ttl_seconds":30`) {
		t.Errorf("ttl: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestReadClientSurfaceHasNoWriteMethods is the security guard: the ReadClient
// interface — the only seam through which airlock touches Redis — must expose
// exactly the curated read methods and nothing resembling a write/destructive
// command. A new method forces a deliberate edit here.
func TestReadClientSurfaceHasNoWriteMethods(t *testing.T) {
	allowed := map[string]bool{"Get": true, "Scan": true, "Exists": true, "TTL": true}
	// Substrings of well-known mutating/destructive Redis commands.
	forbidden := []string{
		"Set", "Del", "Expire", "Flush", "Rename", "Append", "Incr", "Decr",
		"Push", "Pop", "Add", "Rem", "Move", "Persist", "Eval", "Exec", "Pub",
		"Sub", "Restore", "Migrate", "Copy", "Unlink", "Swap", "Config",
	}

	typ := reflect.TypeOf((*ReadClient)(nil)).Elem()
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if !allowed[name] {
			t.Errorf("ReadClient exposes unexpected method %q — read-only surface must be curated", name)
		}
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("ReadClient method %q matches forbidden write verb %q", name, bad)
			}
		}
	}
}

// TestAllOperationsAreReads asserts every exposed operation is a GET on the
// redis namespace — no operation can carry a mutating method.
func TestAllOperationsAreReads(t *testing.T) {
	for _, o := range newTool().Operations() {
		if o.Method != http.MethodGet {
			t.Errorf("operation %q uses method %q, want GET", o.ID, o.Method)
		}
		if !strings.HasPrefix(o.ID, "redis.") {
			t.Errorf("operation id %q not in redis namespace", o.ID)
		}
	}
}
