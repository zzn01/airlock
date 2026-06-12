package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
	"github.com/zzn01/airlock/internal/webauth"
)

// This file proves that a web-issued token plugs into the EXISTING group-based
// access-control core: a token carrying a user's groups is authorized exactly
// like a static config client, while static clients keep working and bad tokens
// are rejected. It exercises the real proxy pipeline against a fake upstream.

func buildWebAuthGateway(t *testing.T) (*gateway.Gateway, *webauth.SessionStore, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{
		Groups: []string{"team-a", "team-b"},
		Clients: []config.Client{
			// A static config client in team-a must keep working unchanged.
			{ID: "static-a", Token: "static-tok", Groups: []string{"team-a"}, RateLimit: config.RateLimit{RPS: 1000, Burst: 1000}},
		},
		Backends: config.Backends{
			HTTPProxy: []httpproxy.Config{{
				Name: "grafana-main", Type: "grafana", BaseURL: upstream.URL,
				AllowedGroups: []string{"team-a"},
				Grants:        []httpproxy.Grant{{Group: "team-a", Endpoints: []string{"grafana.search"}}},
			}},
		},
	}
	g, err := gateway.Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	sessions := webauth.NewSessionStore(time.Hour, func() time.Time { return time.Unix(0, 0) })
	g.SetTokenResolver(sessions)
	return g, sessions, upstream
}

func get(g *gateway.Gateway, target, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

const grafanaSearch = "/b/grafana-main/api/search?query=x"

func TestWebTokenResolvesToGroupsThroughPipeline(t *testing.T) {
	g, sessions, _ := buildWebAuthGateway(t)

	// A web user in team-a reaches the team-a-gated backend, just like a static
	// team-a client would.
	token, _, err := sessions.Issue(webauth.User{Username: "alice", Groups: []string{"team-a"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if rec := get(g, grafanaSearch, token); rec.Code != http.StatusOK {
		t.Fatalf("team-a web token status = %d, want 200 (should reach upstream)", rec.Code)
	}

	// A web user NOT in team-a is denied by the coarse group gate (403, not a
	// 401): authentication succeeded, but the groups don't grant access. This is
	// what proves the user's groups actually drive authorization.
	otherTok, _, _ := sessions.Issue(webauth.User{Username: "bob", Groups: []string{"team-b"}})
	if rec := get(g, grafanaSearch, otherTok); rec.Code != http.StatusForbidden {
		t.Errorf("team-b web token status = %d, want 403 (group gate)", rec.Code)
	}
}

func TestStaticClientStillAuthenticates(t *testing.T) {
	g, _, _ := buildWebAuthGateway(t)
	if rec := get(g, grafanaSearch, "static-tok"); rec.Code != http.StatusOK {
		t.Errorf("static client status = %d, want 200", rec.Code)
	}
}

func TestExpiredRevokedUnknownTokensRejected(t *testing.T) {
	now := time.Unix(0, 0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)
	cfg := &config.Config{
		Groups:  []string{"team-a"},
		Clients: []config.Client{{ID: "static-a", Token: "static-tok", Groups: []string{"team-a"}, RateLimit: config.RateLimit{RPS: 1000, Burst: 1000}}},
		Backends: config.Backends{HTTPProxy: []httpproxy.Config{{
			Name: "grafana-main", Type: "grafana", BaseURL: upstream.URL,
			AllowedGroups: []string{"team-a"},
			Grants:        []httpproxy.Grant{{Group: "team-a", Endpoints: []string{"grafana.search"}}},
		}}},
	}
	g, err := gateway.Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	sessions := webauth.NewSessionStore(time.Hour, func() time.Time { return now })
	g.SetTokenResolver(sessions)

	expired, _, _ := sessions.Issue(webauth.User{Username: "alice", Groups: []string{"team-a"}})
	revoked, _, _ := sessions.Issue(webauth.User{Username: "carol", Groups: []string{"team-a"}})
	sessions.Revoke(revoked)
	now = now.Add(2 * time.Hour) // push past the expired token's TTL

	cases := map[string]string{
		"unknown": "no-such-token",
		"expired": expired,
		"revoked": revoked,
	}
	for name, tok := range cases {
		if rec := get(g, grafanaSearch, tok); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s token status = %d, want 401", name, rec.Code)
		}
	}
}
