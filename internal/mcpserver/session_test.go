package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/webauth"
)

// rawMCP performs one JSON-RPC POST against the MCP endpoint with the given
// bearer token and optional session id, returning the HTTP status, the
// Mcp-Session-Id response header (set on initialize), and the decoded JSON-RPC
// response parsed out of the SSE "data:" line (nil for notifications).
func rawMCP(t *testing.T, url, token, sessionID string, payload any) (int, string, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	sid := resp.Header.Get("Mcp-Session-Id")

	var msg map[string]any
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
			_ = json.Unmarshal([]byte(strings.TrimSpace(data)), &msg)
			break
		}
	}
	return resp.StatusCode, sid, msg
}

func toolNamesFromList(msg map[string]any) []string {
	result, _ := msg["result"].(map[string]any)
	rawTools, _ := result["tools"].([]any)
	var names []string
	for _, rt := range rawTools {
		if tm, ok := rt.(map[string]any); ok {
			if n, ok := tm["name"].(string); ok {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

func initPayload(id int) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "0"},
		},
	}
}

func containsAny(haystack []string, needles ...string) bool {
	set := map[string]bool{}
	for _, h := range haystack {
		set[h] = true
	}
	for _, n := range needles {
		if set[n] {
			return true
		}
	}
	return false
}

// handshake initializes an MCP session for token over ts and returns the
// session id, completing the initialized notification so the session is live.
func handshake(t *testing.T, ts *httptest.Server, token string, initID int) string {
	t.Helper()
	status, sid, msg := rawMCP(t, ts.URL, token, "", initPayload(initID))
	if status != http.StatusOK {
		t.Fatalf("initialize status = %d, body=%v", status, msg)
	}
	if sid == "" {
		t.Fatalf("no session id returned on initialize")
	}
	if st, _, _ := rawMCP(t, ts.URL, token, sid, map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	}); st != http.StatusOK && st != http.StatusAccepted {
		t.Fatalf("initialized notification status = %d", st)
	}
	return sid
}

// --- criterion 4(a): cross-client tools/list on a borrowed session is denied --
//
// An MCP session is bound to the client that created it. A request that
// authenticates as a *different* valid client and presents the first client's
// session id must be rejected (403) before reaching the session's tool handlers,
// and must never receive the creator's tool list.
func TestSessionBoundToAuthenticatedClient(t *testing.T) {
	s := newTestServer(t, baseConfig(""))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// checkout creates a session and completes the handshake.
	sid := handshake(t, ts, checkoutToken, 1)

	// Sanity: checkout, on its own session, sees its own tools.
	_, _, ownMsg := rawMCP(t, ts.URL, checkoutToken, sid, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	})
	if own := toolNamesFromList(ownMsg); !equalStrings(own, []string{"redis_get", "victorialogs_query"}) {
		t.Fatalf("checkout own tools = %v, want [redis_get victorialogs_query]", own)
	}

	// ATTACK: authenticate as sre (a different valid client) but present
	// checkout's session id. Must be rejected with 403 and leak no tools.
	attackStatus, _, attackMsg := rawMCP(t, ts.URL, sreToken, sid, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/list",
	})
	if attackStatus != http.StatusForbidden {
		t.Fatalf("cross-client tools/list status = %d, want 403 (session not bound to its client)", attackStatus)
	}
	if leaked := toolNamesFromList(attackMsg); containsAny(leaked, "redis_get", "victorialogs_query") {
		t.Fatalf("SECURITY: sre-authenticated request on checkout's session leaked checkout's tools %v", leaked)
	}
}

// --- criterion 4(b): cross-session tool dispatch (and tenancy) is denied -------
//
// Beyond listing, a borrowed session must not let another client *dispatch* a
// tool with the creator's identity, instance reachability, or pinned tenancy. We
// point victorialogs-a at a fake upstream and assert that an sre request riding
// checkout's session is rejected (403) and that the upstream is never reached —
// so checkout's pinned AccountID can never leak.
func TestCrossSessionDispatchDenied(t *testing.T) {
	var mu sync.Mutex
	var upstreamHits int
	var gotAccount string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits++
		gotAccount = r.Header.Get("AccountID")
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	s := newTestServer(t, baseConfig(upstream.URL))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// checkout creates a session reachable to victorialogs-a (AccountID 7).
	sid := handshake(t, ts, checkoutToken, 1)

	// ATTACK: sre presents checkout's session id and tries to query
	// victorialogs-a — an instance sre cannot reach — via checkout's session.
	attackStatus, _, _ := rawMCP(t, ts.URL, sreToken, sid, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{
			"name":      "victorialogs_query",
			"arguments": map[string]any{"instance": "victorialogs-a", "query": "*"},
		},
	})
	if attackStatus != http.StatusForbidden {
		t.Fatalf("cross-session dispatch status = %d, want 403", attackStatus)
	}

	mu.Lock()
	defer mu.Unlock()
	if upstreamHits != 0 {
		t.Fatalf("SECURITY: borrowed-session dispatch reached the upstream %d time(s) "+
			"(AccountID=%q) — cross-principal tenancy leak", upstreamHits, gotAccount)
	}
}

// --- criterion 3: both static and web-issued tokens bind to their own sessions -
//
// A token issued by the web-login session store resolves through the same
// identity seam as a static config client; each must bind to the session it
// creates. A web token cannot ride a static client's session, and a static
// client cannot ride a web token's session.
func TestStaticAndWebTokensBindToOwnSessions(t *testing.T) {
	s := newTestServer(t, baseConfig(""))

	store := webauth.NewSessionStore(time.Hour, nil)
	webToken, _, err := store.Issue(webauth.User{Username: "alice", Groups: []string{"team-checkout"}})
	if err != nil {
		t.Fatalf("issue web token: %v", err)
	}
	s.g.SetTokenResolver(store)

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	staticSID := handshake(t, ts, checkoutToken, 1)
	webSID := handshake(t, ts, webToken, 2)

	// The web token cannot ride the static client's session.
	if st, _, _ := rawMCP(t, ts.URL, webToken, staticSID, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/list",
	}); st != http.StatusForbidden {
		t.Errorf("web token on static session status = %d, want 403", st)
	}

	// The static client cannot ride the web token's session.
	if st, _, _ := rawMCP(t, ts.URL, checkoutToken, webSID, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/list",
	}); st != http.StatusForbidden {
		t.Errorf("static token on web session status = %d, want 403", st)
	}

	// Sanity: each token still operates normally on its own session.
	if st, _, _ := rawMCP(t, ts.URL, webToken, webSID, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/list",
	}); st != http.StatusOK {
		t.Errorf("web token on its own session status = %d, want 200", st)
	}
}

// sessionUserID must never return an empty string: an empty user id silently
// disables the SDK's session-hijack guard, leaving sessions unbound.
func TestSessionUserIDNeverEmpty(t *testing.T) {
	if got := sessionUserID(config.Client{ID: "checkout"}, "tok"); got != "checkout" {
		t.Errorf("sessionUserID(id=checkout) = %q, want checkout", got)
	}
	if got := sessionUserID(config.Client{ID: ""}, "tok"); got == "" {
		t.Error("sessionUserID(id=\"\") returned empty — hijack guard would be inert")
	}
	// Distinct tokens with empty ids must not collide onto the same binding.
	a := sessionUserID(config.Client{ID: ""}, "token-a")
	b := sessionUserID(config.Client{ID: ""}, "token-b")
	if a == b {
		t.Errorf("empty-id fallback collided across tokens: %q == %q", a, b)
	}
}
