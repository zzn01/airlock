package backend

import (
	"net/http"
	"testing"
)

type fakeBackend struct {
	name string
	ops  []Operation
}

func (f fakeBackend) Name() string            { return f.name }
func (f fakeBackend) Operations() []Operation { return f.ops }

func op(id, method, path string) Operation {
	return Operation{ID: id, Method: method, Path: path, Handler: func(http.ResponseWriter, *http.Request) {}}
}

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(fakeBackend{name: "redis", ops: []Operation{
		op("redis.get", "GET", "/redis/get"),
		op("redis.scan", "GET", "/redis/scan"),
	}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Lookup("GET", "/redis/get")
	if !ok || got.ID != "redis.get" {
		t.Errorf("Lookup(GET /redis/get) = %+v, %v", got, ok)
	}
	if _, ok := r.Lookup("GET", "/redis/unknown"); ok {
		t.Error("unknown path should not resolve")
	}
	if _, ok := r.Lookup("POST", "/redis/get"); ok {
		t.Error("wrong method should not resolve")
	}
}

func TestRegisterRejectsDuplicateRoute(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(fakeBackend{name: "a", ops: []Operation{op("a.x", "GET", "/x")}}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register(fakeBackend{name: "b", ops: []Operation{op("b.x", "GET", "/x")}}); err == nil {
		t.Error("expected duplicate-route error")
	}
}
