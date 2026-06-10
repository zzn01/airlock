// Package backend defines the operation/backend model and a registry that
// maps HTTP routes to operations.
//
// A backend contributes a set of Operations; each operation is addressed
// explicitly by its (method, path). There is no wildcard forwarding — the set
// of reachable actions is exactly the set of registered operations.
package backend

import (
	"fmt"
	"net/http"
	"sort"
)

// Operation is a single curated capability exposed by a backend.
type Operation struct {
	ID      string // stable identity used by authorization, e.g. "redis.get"
	Method  string // HTTP method, e.g. "GET"
	Path    string // HTTP path, e.g. "/redis/get"
	Handler http.HandlerFunc
}

// Backend contributes operations to the registry.
type Backend interface {
	Name() string
	Operations() []Operation
}

// Registry indexes operations by method+path.
type Registry struct {
	ops map[string]Operation
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{ops: make(map[string]Operation)}
}

func key(method, path string) string { return method + " " + path }

// Register adds all of b's operations. It is an error for two operations to
// share a (method, path) route.
func (r *Registry) Register(b Backend) error {
	for _, o := range b.Operations() {
		k := key(o.Method, o.Path)
		if existing, dup := r.ops[k]; dup {
			return fmt.Errorf("route %q already registered by operation %q", k, existing.ID)
		}
		r.ops[k] = o
	}
	return nil
}

// Lookup returns the operation registered for method+path, if any.
func (r *Registry) Lookup(method, path string) (Operation, bool) {
	o, ok := r.ops[key(method, path)]
	return o, ok
}

// Operations returns all registered operations, sorted by id for stable output.
func (r *Registry) Operations() []Operation {
	out := make([]Operation, 0, len(r.ops))
	for _, o := range r.ops {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
