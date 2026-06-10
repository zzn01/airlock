package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
)

// recordingUpstream is an httptest server that captures the last request it saw
// and counts hits, returning a fixed body.
type recordingUpstream struct {
	server  *httptest.Server
	hits    atomic.Int64
	query   string
	account string
	project string
	auth    string
	apiKey  string
	body    string
}

func newUpstream(t *testing.T, body string) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{body: body}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.query = r.URL.Query().Get("query")
		u.account = r.Header.Get("AccountID")
		u.project = r.Header.Get("ProjectID")
		u.auth = r.Header.Get("Authorization")
		u.apiKey = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte(u.body))
	}))
	t.Cleanup(u.server.Close)
	return u
}

// fixture wires a gateway with two VictoriaLogs instances (a, b) and one
// Grafana instance, two clients in different groups, via Build.
type fixture struct {
	g     *Gateway
	vlA   *recordingUpstream
	vlB   *recordingUpstream
	graf  *recordingUpstream
	close func()
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	vlA := newUpstream(t, "result-a")
	vlB := newUpstream(t, "result-b")
	graf := newUpstream(t, strings.Repeat("g", 10000))

	cfg := &config.Config{
		Groups: []string{"team-a", "team-b", "sre"},
		Clients: []config.Client{
			{ID: "client-a", Token: "tok-a", Groups: []string{"team-a"}, RateLimit: config.RateLimit{RPS: 1000, Burst: 1000}},
			{ID: "client-b", Token: "tok-b", Groups: []string{"team-b"}, RateLimit: config.RateLimit{RPS: 1000, Burst: 1000}},
			{ID: "client-sre", Token: "tok-sre", Groups: []string{"sre"}, RateLimit: config.RateLimit{RPS: 1000, Burst: 1000}},
		},
		Backends: config.Backends{
			HTTPProxy: []httpproxy.Config{
				{
					Name: "victorialogs-a", Type: "victorialogs", BaseURL: vlA.server.URL,
					AllowedGroups:    []string{"team-a"},
					MaxResultLimit:   1000,
					ResultLimitParam: "limit",
					Grants: []httpproxy.Grant{{
						Group: "team-a", Endpoints: []string{"vl.query"},
						Scope: httpproxy.Scope{VictoriaLogs: &httpproxy.VLScope{AccountID: "1", ProjectID: "10", MandatoryFilter: `app:"a"`}},
					}},
				},
				{
					Name: "victorialogs-b", Type: "victorialogs", BaseURL: vlB.server.URL,
					AllowedGroups: []string{"team-b"},
					Grants: []httpproxy.Grant{{
						Group: "team-b", Endpoints: []string{"vl.query"},
						Scope: httpproxy.Scope{VictoriaLogs: &httpproxy.VLScope{AccountID: "2", ProjectID: "20", MandatoryFilter: `app:"b"`}},
					}},
				},
				{
					Name: "grafana-main", Type: "grafana", BaseURL: graf.server.URL,
					AllowedGroups:    []string{"sre"},
					UpstreamAuth:     map[string]string{"Authorization": "Bearer service-token"},
					MaxResponseBytes: 100,
					Grants: []httpproxy.Grant{{
						Group: "sre", Endpoints: []string{"grafana.search"},
					}},
				},
			},
		},
	}
	g, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return &fixture{g: g, vlA: vlA, vlB: vlB, graf: graf}
}

func TestProxyCoarseGateDeniesForeignGroup(t *testing.T) {
	f := newFixture(t)
	// client-b is in team-b, not in victorialogs-a's allowed_groups (team-a).
	rec := do(f.g, "GET", "/b/victorialogs-a/select/logsql/query?query=x", "tok-b")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (coarse gate)", rec.Code)
	}
	if f.vlA.hits.Load() != 0 {
		t.Error("denied request must never reach the upstream")
	}
}

func TestProxyUnknownInstanceReturns404(t *testing.T) {
	f := newFixture(t)
	rec := do(f.g, "GET", "/b/does-not-exist/select/logsql/query?query=x", "tok-a")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (unknown backend)", rec.Code)
	}
}

func TestProxyGrantAllowsOnlyItsEndpoints(t *testing.T) {
	f := newFixture(t)
	// vl.query is granted to team-a.
	if rec := do(f.g, "GET", "/b/victorialogs-a/select/logsql/query?query=x", "tok-a"); rec.Code != http.StatusOK {
		t.Errorf("granted endpoint status = %d, want 200", rec.Code)
	}
	// vl.hits is in the preset allowlist but NOT granted to team-a => 403.
	if rec := do(f.g, "GET", "/b/victorialogs-a/select/logsql/hits?query=x", "tok-a"); rec.Code != http.StatusForbidden {
		t.Errorf("ungranted endpoint status = %d, want 403", rec.Code)
	}
}

func TestProxyStrictInstanceBoundary(t *testing.T) {
	f := newFixture(t)
	// A request under victorialogs-a's prefix must hit ONLY upstream A.
	if rec := do(f.g, "GET", "/b/victorialogs-a/select/logsql/query?query=x", "tok-a"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if f.vlA.hits.Load() != 1 || f.vlB.hits.Load() != 0 {
		t.Errorf("hits a=%d b=%d, want a=1 b=0 (no shared/merged routing)", f.vlA.hits.Load(), f.vlB.hits.Load())
	}
	// client-a cannot reach instance B's prefix at all (coarse gate).
	if rec := do(f.g, "GET", "/b/victorialogs-b/select/logsql/query?query=x", "tok-a"); rec.Code != http.StatusForbidden {
		t.Errorf("cross-instance status = %d, want 403", rec.Code)
	}
	if f.vlB.hits.Load() != 0 {
		t.Error("instance B upstream must never be reached via a denied request")
	}
}

func TestProxyWriteEndpointBlocked(t *testing.T) {
	f := newFixture(t)
	// /delete/* is not in the victorialogs preset allowlist => 403, never proxied.
	for _, method := range []string{"GET", "POST", "DELETE"} {
		rec := do(f.g, method, "/b/victorialogs-a/delete/logsql?query=x", "tok-a")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s /delete/logsql status = %d, want 403", method, rec.Code)
		}
	}
	if f.vlA.hits.Load() != 0 {
		t.Error("blocked write must never reach the upstream")
	}
}

func TestProxyVLTenancyAndFilterAlwaysAppliedClientCannotWiden(t *testing.T) {
	f := newFixture(t)
	// Client tries to widen: forge another tenant and an open query.
	req := httptest.NewRequest("GET", "/b/victorialogs-a/select/logsql/query?query=*", nil)
	req.Header.Set("Authorization", "Bearer tok-a")
	req.Header.Set("AccountID", "999")
	req.Header.Set("ProjectID", "999")
	rec := httptest.NewRecorder()
	f.g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if f.vlA.account != "1" || f.vlA.project != "10" {
		t.Errorf("upstream tenancy = %q/%q, want 1/10 (client override defeated)", f.vlA.account, f.vlA.project)
	}
	if !strings.Contains(f.vlA.query, `app:"a"`) {
		t.Errorf("upstream query %q must always carry the mandatory filter", f.vlA.query)
	}
}

func TestProxyResponseSizeCap(t *testing.T) {
	f := newFixture(t)
	// grafana-main caps responses at 100 bytes; upstream returns 10000.
	rec := do(f.g, "GET", "/b/grafana-main/api/search", "tok-sre")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() > 100 {
		t.Errorf("response body = %d bytes, want capped at 100", rec.Body.Len())
	}
}

func TestProxyInjectsUpstreamAuth(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", "/b/grafana-main/api/search", nil)
	req.Header.Set("Authorization", "Bearer tok-sre") // gateway credential
	req.Header.Set("X-API-Key", "client-secret")
	rec := httptest.NewRecorder()
	f.g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if f.graf.auth != "Bearer service-token" {
		t.Errorf("upstream Authorization = %q, want injected service token", f.graf.auth)
	}
	if f.graf.apiKey != "" {
		t.Errorf("client credential leaked upstream: %q", f.graf.apiKey)
	}
}

func TestProxyUnauthenticatedReturns401(t *testing.T) {
	f := newFixture(t)
	rec := do(f.g, "GET", "/b/victorialogs-a/select/logsql/query?query=x", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
