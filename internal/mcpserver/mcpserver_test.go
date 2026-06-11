package mcpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zzn01/airlock/internal/backend/httpproxy"
	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/gateway"
)

// --- test fixtures -----------------------------------------------------------

const (
	checkoutToken = "checkout-secret"
	sreToken      = "sre-secret"
)

// baseConfig wires three clients across redis + httpproxy backends:
//   - checkout: group team-checkout, redis.get allowed, reaches victorialogs-a.
//   - payments: group team-payments, reaches victorialogs-b.
//   - sre:      group sre, reaches grafana-main and prometheus-main.
//
// vlBaseURL, if non-empty, overrides victorialogs-a's base URL (for the scope
// enforcement test pointing at a fake upstream).
func baseConfig(vlBaseURL string) *config.Config {
	if vlBaseURL == "" {
		vlBaseURL = "http://victorialogs-a.internal:9428"
	}
	return &config.Config{
		Groups: []string{"team-checkout", "team-payments", "sre"},
		Clients: []config.Client{
			{ID: "checkout", Token: checkoutToken, Groups: []string{"team-checkout"}, Allow: []string{"redis.get"}},
			{ID: "payments", Token: "payments-secret", Groups: []string{"team-payments"}},
			{ID: "sre", Token: sreToken, Groups: []string{"sre"}},
		},
		Backends: config.Backends{
			Redis: &config.RedisBackend{Addr: "127.0.0.1:6379"},
			HTTPProxy: []httpproxy.Config{
				{
					Name: "victorialogs-a", Type: "victorialogs", BaseURL: vlBaseURL,
					AllowedGroups: []string{"team-checkout"},
					Grants: []httpproxy.Grant{{
						Group: "team-checkout", Endpoints: []string{"vl.query"},
						Scope: httpproxy.Scope{VictoriaLogs: &httpproxy.VLScope{
							AccountID: "7", ProjectID: "70", MandatoryFilter: `app:"checkout"`,
						}},
					}},
				},
				{
					Name: "victorialogs-b", Type: "victorialogs", BaseURL: "http://victorialogs-b.internal:9428",
					AllowedGroups: []string{"team-payments"},
					Grants: []httpproxy.Grant{{
						Group: "team-payments", Endpoints: []string{"vl.query"},
						Scope: httpproxy.Scope{VictoriaLogs: &httpproxy.VLScope{AccountID: "2", ProjectID: "20"}},
					}},
				},
				{
					Name: "grafana-main", Type: "grafana", BaseURL: "http://grafana.internal:3000",
					AllowedGroups: []string{"sre"},
					Grants: []httpproxy.Grant{{
						Group: "sre", Endpoints: []string{"grafana.search", "grafana.ds_query"},
					}},
				},
				{
					Name: "prometheus-main", Type: "prometheus", BaseURL: "http://prometheus.internal:9090",
					AllowedGroups: []string{"sre"},
					Grants: []httpproxy.Grant{{
						Group: "sre", Endpoints: []string{"prom.query", "prom.query_range"},
					}},
				},
			},
		},
	}
}

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}
	g, err := gateway.Build(cfg, nil)
	if err != nil {
		t.Fatalf("build gateway: %v", err)
	}
	return New(g, nil)
}

// connect serves srv over an in-memory transport and returns a connected client
// session, exercising the real MCP list/call code paths without a network.
func connect(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	serverT, clientT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func listToolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// --- criterion: tool list is filtered to the client's granted operations -----

func TestToolListFilteredByClient(t *testing.T) {
	s := newTestServer(t, baseConfig(""))

	checkout := listToolNames(t, connect(t, s.serverForToken(checkoutToken)))
	wantCheckout := []string{"redis_get", "victorialogs_query"}
	if !equalStrings(checkout, wantCheckout) {
		t.Errorf("checkout tools = %v, want %v", checkout, wantCheckout)
	}

	sre := listToolNames(t, connect(t, s.serverForToken(sreToken)))
	wantSRE := []string{"grafana_ds_query", "grafana_search", "prometheus_query", "prometheus_query_range"}
	if !equalStrings(sre, wantSRE) {
		t.Errorf("sre tools = %v, want %v", sre, wantSRE)
	}
}

// The instance enum on a listed httpproxy tool must contain only the instances
// the client can actually reach — not every instance of that type.
func TestInstanceEnumFilteredToReachable(t *testing.T) {
	s := newTestServer(t, baseConfig(""))
	cs := connect(t, s.serverForToken(checkoutToken))

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var enum []string
	for _, tool := range res.Tools {
		if tool.Name != "victorialogs_query" {
			continue
		}
		enum = instanceEnum(t, tool)
	}
	want := []string{"victorialogs-a"} // not victorialogs-b (team-payments only)
	if !equalStrings(enum, want) {
		t.Errorf("victorialogs_query instance enum = %v, want %v", enum, want)
	}
}

// --- criterion: an unauthorized tool call is denied --------------------------

// checkout may list victorialogs_query (via victorialogs-a) but must not be able
// to reach victorialogs-b. Calling with that instance is denied by the gateway
// coarse group gate (403), surfaced as an MCP tool error — the adapter adds no
// policy of its own.
func TestUnauthorizedInstanceCallDenied(t *testing.T) {
	s := newTestServer(t, baseConfig(""))
	cs := connect(t, s.serverForToken(checkoutToken))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "victorialogs_query",
		Arguments: map[string]any{"instance": "victorialogs-b", "query": "*"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected denied call to be an error result, got success: %s", resultText(t, res))
	}
	if got := resultText(t, res); !strings.Contains(got, "403") {
		t.Errorf("expected 403 in error result, got %q", got)
	}
}

// --- criterion: VictoriaLogs tenancy + mandatory filter applied; no widening --

func TestVictoriaLogsScopeEnforcedOnMCPCall(t *testing.T) {
	var mu sync.Mutex
	var gotQuery, gotAccount, gotProject string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotQuery = r.URL.Query().Get("query")
		gotAccount = r.Header.Get("AccountID")
		gotProject = r.Header.Get("ProjectID")
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	s := newTestServer(t, baseConfig(upstream.URL))
	cs := connect(t, s.serverForToken(checkoutToken))

	// A client query that tries to OR its way out of the tenancy slice must be
	// parenthesized and AND-combined with the mandatory filter — it cannot widen.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "victorialogs_query",
		Arguments: map[string]any{"instance": "victorialogs-a", "query": `* OR app:"other"`},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", resultText(t, res))
	}

	mu.Lock()
	defer mu.Unlock()
	if want := `(app:"checkout") AND (* OR app:"other")`; gotQuery != want {
		t.Errorf("upstream query = %q, want %q", gotQuery, want)
	}
	if gotAccount != "7" || gotProject != "70" {
		t.Errorf("tenancy headers = AccountID:%q ProjectID:%q, want 7/70", gotAccount, gotProject)
	}
}

// --- criterion: unauthenticated connection exposes no tools / errors ---------

func TestUnauthenticatedExposesNoTools(t *testing.T) {
	s := newTestServer(t, baseConfig(""))

	// An unknown/empty token yields a server with zero tools.
	names := listToolNames(t, connect(t, s.serverForToken("")))
	if len(names) != 0 {
		t.Errorf("unauthenticated tool list = %v, want empty", names)
	}
}

func TestUnauthenticatedHTTPRejected(t *testing.T) {
	s := newTestServer(t, baseConfig(""))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	for _, tc := range []struct {
		name, auth string
	}{
		{"missing token", ""},
		{"unknown token", "Bearer nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// A valid token reaches the streamable handler (not a 401).
func TestAuthenticatedHTTPAccepted(t *testing.T) {
	s := newTestServer(t, baseConfig(""))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+checkoutToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("authenticated request was rejected with 401")
	}
}

// --- helpers -----------------------------------------------------------------

func instanceEnum(t *testing.T, tool *mcp.Tool) []string {
	t.Helper()
	schema, ok := tool.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("input schema is %T, want map", tool.InputSchema)
	}
	props, _ := schema["properties"].(map[string]any)
	inst, _ := props["instance"].(map[string]any)
	rawEnum, _ := inst["enum"].([]any)
	var out []string
	for _, e := range rawEnum {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
