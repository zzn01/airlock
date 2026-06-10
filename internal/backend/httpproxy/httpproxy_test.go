package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpointMatch(t *testing.T) {
	cases := []struct {
		pattern, method, reqMethod, path string
		want                             bool
	}{
		{"/api/v1/query", "GET", "GET", "/api/v1/query", true},
		{"/api/v1/query", "GET", "POST", "/api/v1/query", false}, // method mismatch
		{"/api/v1/query", "GET", "GET", "/api/v1/query_range", false},
		{"/api/v1/label/*/values", "GET", "GET", "/api/v1/label/job/values", true},
		{"/api/v1/label/*/values", "GET", "GET", "/api/v1/label/values", false}, // missing segment
		{"/api/dashboards/*", "GET", "GET", "/api/dashboards/uid/abc", true},    // trailing tail
		{"/api/dashboards/*", "GET", "GET", "/api/dashboards", false},           // tail needs >=1
		{"/api/search", "GET", "GET", "/api/search/extra", false},               // too long
	}
	for _, c := range cases {
		ep := Endpoint{Method: c.method, Path: c.pattern}
		if got := ep.Match(c.reqMethod, c.path); got != c.want {
			t.Errorf("Match(%s %s) pattern %s %s = %v, want %v", c.reqMethod, c.path, c.method, c.pattern, got, c.want)
		}
	}
}

func TestPresetsAreReadOnly(t *testing.T) {
	// VictoriaLogs preset exposes select/query endpoints but no delete/write.
	vl, err := Preset("victorialogs")
	if err != nil {
		t.Fatalf("Preset(victorialogs): %v", err)
	}
	if !anyMatch(vl, "GET", "/select/logsql/query") {
		t.Error("victorialogs preset must allow GET /select/logsql/query")
	}
	if anyMatch(vl, "GET", "/delete/logsql") || anyMatch(vl, "POST", "/delete/logsql") {
		t.Error("victorialogs preset must NOT allow any /delete endpoint")
	}

	// Prometheus preset is GET-only reads; admin/tsdb delete must be absent.
	prom, err := Preset("prometheus")
	if err != nil {
		t.Fatalf("Preset(prometheus): %v", err)
	}
	if !anyMatch(prom, "GET", "/api/v1/query") || !anyMatch(prom, "GET", "/api/v1/label/job/values") {
		t.Error("prometheus preset must allow query and label values")
	}
	if anyMatch(prom, "POST", "/api/v1/admin/tsdb/delete_series") || anyMatch(prom, "PUT", "/api/v1/admin/tsdb/delete_series") {
		t.Error("prometheus preset must NOT allow admin/tsdb delete")
	}

	// Grafana exposes read search/dashboards and POST ds/query, but no
	// datasource secrets or dashboard mutation.
	graf, err := Preset("grafana")
	if err != nil {
		t.Fatalf("Preset(grafana): %v", err)
	}
	if !anyMatch(graf, "GET", "/api/search") || !anyMatch(graf, "POST", "/api/ds/query") {
		t.Error("grafana preset must allow search and ds/query")
	}
	if anyMatch(graf, "GET", "/api/datasources") || anyMatch(graf, "DELETE", "/api/dashboards/uid/x") {
		t.Error("grafana preset must NOT expose datasources or dashboard deletion")
	}

	if _, err := Preset("nope"); err == nil {
		t.Error("unknown preset type should error")
	}
}

func anyMatch(eps []Endpoint, method, path string) bool {
	for _, e := range eps {
		if e.Match(method, path) {
			return true
		}
	}
	return false
}

// newInstance builds an instance whose base_url points at upstream.
func newInstance(t *testing.T, cfg Config, upstreamURL string) *Instance {
	t.Helper()
	cfg.BaseURL = upstreamURL
	in, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func TestEffectiveAndGrant(t *testing.T) {
	in := newInstance(t, Config{
		Name: "vl-a", Type: "victorialogs", AllowedGroups: []string{"team-a"},
		Grants: []Grant{{Group: "team-a", Endpoints: []string{"vl.query"}}},
	}, "http://example.invalid")

	if eff := in.Effective([]string{"team-b", "sre"}); len(eff) != 0 {
		t.Errorf("Effective with no intersection = %v, want empty", eff)
	}
	eff := in.Effective([]string{"team-a", "team-b"})
	if len(eff) != 1 || eff[0] != "team-a" {
		t.Fatalf("Effective = %v, want [team-a]", eff)
	}
	if _, ok := in.Grant(eff, "vl.query"); !ok {
		t.Error("grant should authorize vl.query for team-a")
	}
	if _, ok := in.Grant(eff, "vl.hits"); ok {
		t.Error("grant must NOT authorize an endpoint not listed (default deny)")
	}
}

func TestProxyInjectsVLTenancyAndMandatoryFilterAndStripsClient(t *testing.T) {
	var gotQuery, gotAccount, gotProject string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotAccount = r.Header.Get("AccountID")
		gotProject = r.Header.Get("ProjectID")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	in := newInstance(t, Config{
		Name: "vl-a", Type: "victorialogs", AllowedGroups: []string{"team-a"},
		Grants: []Grant{{Group: "team-a", Endpoints: []string{"vl.query"}, Scope: Scope{
			VictoriaLogs: &VLScope{AccountID: "1", ProjectID: "10", MandatoryFilter: `app:"checkout"`},
		}}},
	}, upstream.URL)

	ep, _ := in.MatchEndpoint("GET", "/select/logsql/query")
	g, _ := in.Grant(in.Effective([]string{"team-a"}), "vl.query")

	// Client tries to widen: picks another tenant and a wide-open query.
	req := httptest.NewRequest("GET", "/b/vl-a/select/logsql/query?query=*", nil)
	req.Header.Set("AccountID", "999")
	req.Header.Set("ProjectID", "999")
	rec := httptest.NewRecorder()
	in.Proxy(rec, req, "/select/logsql/query", ep, g)

	if gotAccount != "1" || gotProject != "10" {
		t.Errorf("upstream tenancy = %q/%q, want 1/10 (client values must be overridden)", gotAccount, gotProject)
	}
	if !strings.Contains(gotQuery, `app:"checkout"`) {
		t.Errorf("upstream query %q must contain the mandatory filter", gotQuery)
	}
	if !strings.Contains(gotQuery, "*") {
		t.Errorf("upstream query %q should still AND-in the client's term", gotQuery)
	}
}

func TestProxyInjectsUpstreamAuthAndStripsClientCredential(t *testing.T) {
	var gotAuth, gotAPIKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	in := newInstance(t, Config{
		Name: "graf", Type: "grafana", AllowedGroups: []string{"sre"},
		UpstreamAuth: map[string]string{"Authorization": "Bearer service-token"},
		Grants:       []Grant{{Group: "sre", Endpoints: []string{"grafana.search"}}},
	}, upstream.URL)

	ep, _ := in.MatchEndpoint("GET", "/api/search")
	g, _ := in.Grant(in.Effective([]string{"sre"}), "grafana.search")

	req := httptest.NewRequest("GET", "/b/graf/api/search", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("X-API-Key", "client-key")
	rec := httptest.NewRecorder()
	in.Proxy(rec, req, "/api/search", ep, g)

	if gotAuth != "Bearer service-token" {
		t.Errorf("upstream Authorization = %q, want injected service token", gotAuth)
	}
	if gotAPIKey != "" {
		t.Errorf("client X-API-Key leaked upstream: %q", gotAPIKey)
	}
}

func TestProxyCapsResponseBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer upstream.Close()

	in := newInstance(t, Config{
		Name: "prom", Type: "prometheus", AllowedGroups: []string{"sre"},
		MaxResponseBytes: 100,
		Grants:           []Grant{{Group: "sre", Endpoints: []string{"prom.query"}}},
	}, upstream.URL)

	ep, _ := in.MatchEndpoint("GET", "/api/v1/query")
	g, _ := in.Grant(in.Effective([]string{"sre"}), "prom.query")

	req := httptest.NewRequest("GET", "/b/prom/api/v1/query?query=up", nil)
	rec := httptest.NewRecorder()
	in.Proxy(rec, req, "/api/v1/query", ep, g)

	if got := rec.Body.Len(); got > 100 {
		t.Errorf("response body = %d bytes, want capped at 100", got)
	}
	if rec.Header().Get("X-Airlock-Truncated") != "true" {
		t.Error("truncation must be flagged with X-Airlock-Truncated")
	}
}

func TestProxyClampsResultLimit(t *testing.T) {
	var gotLimit string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	in := newInstance(t, Config{
		Name: "vl", Type: "victorialogs", AllowedGroups: []string{"a"},
		MaxResultLimit: 1000, ResultLimitParam: "limit",
		Grants: []Grant{{Group: "a", Endpoints: []string{"vl.query"}}},
	}, upstream.URL)
	ep, _ := in.MatchEndpoint("GET", "/select/logsql/query")
	g, _ := in.Grant(in.Effective([]string{"a"}), "vl.query")

	req := httptest.NewRequest("GET", "/b/vl/select/logsql/query?query=x&limit=999999", nil)
	in.Proxy(httptest.NewRecorder(), req, "/select/logsql/query", ep, g)
	if gotLimit != "1000" {
		t.Errorf("upstream limit = %q, want clamped to 1000", gotLimit)
	}
}

func TestManagerLookup(t *testing.T) {
	m := NewManager()
	in := newInstance(t, Config{Name: "vl-a", Type: "victorialogs"}, "http://example.invalid")
	if err := m.Add(in); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Add(in); err == nil {
		t.Error("duplicate instance name should error")
	}
	if _, ok := m.Instance("vl-a"); !ok {
		t.Error("vl-a should resolve")
	}
	if _, ok := m.Instance("missing"); ok {
		t.Error("missing instance must not resolve")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{Name: "", Type: "prometheus", BaseURL: "http://x"}); err == nil {
		t.Error("empty name should error")
	}
	if _, err := New(Config{Name: "x", Type: "bogus", BaseURL: "http://x"}); err == nil {
		t.Error("unknown type should error")
	}
	if _, err := New(Config{Name: "x", Type: "prometheus", BaseURL: ""}); err == nil {
		t.Error("empty base_url should error")
	}
	if _, err := New(Config{Name: "x", Type: "prometheus", BaseURL: "://bad"}); err == nil {
		t.Error("unparseable base_url should error")
	}
}
