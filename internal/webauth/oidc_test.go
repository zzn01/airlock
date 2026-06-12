package webauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zzn01/airlock/internal/config"
)

// fakeAuth is an Authenticator with no live IdP: AuthCodeURL records the state
// and nonce it was handed, and Verify returns canned claims (or an injected
// error) while recording the code and nonce the callback handler passed it.
type fakeAuth struct {
	claims    Claims
	verifyErr error

	gotCode  string
	gotNonce string
	called   bool
}

func (f *fakeAuth) AuthCodeURL(state, nonce string) string {
	return "https://idp.example.com/authorize?state=" + state + "&nonce=" + nonce
}

func (f *fakeAuth) Verify(_ context.Context, code, nonce string) (Claims, error) {
	f.called = true
	f.gotCode, f.gotNonce = code, nonce
	if f.verifyErr != nil {
		return Claims{}, f.verifyErr
	}
	return f.claims, nil
}

// --- claim -> group mapping (pure) ---

func TestDeriveGroupsMapsAndDedupes(t *testing.T) {
	oidc := &config.OIDC{GroupMapping: map[string][]string{
		"oncall": {"sre"},
		"dev":    {"team-a", "team-b"},
		"extra":  {"sre"}, // overlaps "oncall" -> must de-duplicate
	}}
	c := Claims{Groups: []string{"oncall", "dev", "extra", "unmapped"}}

	got := DeriveGroups(c, oidc)
	want := []string{"sre", "team-a", "team-b"}
	if !equalStrings(got, want) {
		t.Errorf("DeriveGroups = %v, want %v", got, want)
	}
}

func TestDeriveGroupsUnmappedYieldsNothing(t *testing.T) {
	oidc := &config.OIDC{GroupMapping: map[string][]string{"dev": {"team-a"}}}
	if got := DeriveGroups(Claims{Groups: []string{"nope", "other"}}, oidc); len(got) != 0 {
		t.Errorf("DeriveGroups = %v, want empty (default-deny on unmapped claims)", got)
	}
}

func TestDeriveGroupsOverrideBySubjectWins(t *testing.T) {
	oidc := &config.OIDC{
		GroupMapping: map[string][]string{"dev": {"team-a"}},
		Overrides:    []config.OIDCOverride{{Subject: "user-1", Groups: []string{"sre"}}},
	}
	// The user's claim maps to team-a, but the subject override pins sre instead.
	c := Claims{Subject: "user-1", Email: "u1@example.com", Groups: []string{"dev"}}
	if got := DeriveGroups(c, oidc); !equalStrings(got, []string{"sre"}) {
		t.Errorf("DeriveGroups = %v, want [sre] (subject override wins)", got)
	}
}

func TestDeriveGroupsOverrideByEmailWins(t *testing.T) {
	oidc := &config.OIDC{
		GroupMapping: map[string][]string{"dev": {"team-a"}},
		Overrides:    []config.OIDCOverride{{Email: "lead@example.com", Groups: []string{"sre", "team-b"}}},
	}
	c := Claims{Subject: "user-2", Email: "lead@example.com", Groups: []string{"dev"}}
	if got := DeriveGroups(c, oidc); !equalStrings(got, []string{"sre", "team-b"}) {
		t.Errorf("DeriveGroups = %v, want [sre team-b] (email override wins)", got)
	}
}

func TestDeriveGroupsNonMatchingOverrideFallsBackToMapping(t *testing.T) {
	oidc := &config.OIDC{
		GroupMapping: map[string][]string{"dev": {"team-a"}},
		Overrides:    []config.OIDCOverride{{Subject: "someone-else", Groups: []string{"sre"}}},
	}
	c := Claims{Subject: "user-3", Groups: []string{"dev"}}
	if got := DeriveGroups(c, oidc); !equalStrings(got, []string{"team-a"}) {
		t.Errorf("DeriveGroups = %v, want [team-a] (no override match -> mapping)", got)
	}
}

// --- OIDC HTTP flow (state/nonce CSRF, token issuance) ---

// oidcTestServer builds a login server with OIDC enabled over the given fake
// authenticator and a dev->team-a mapping.
func oidcTestServer(t *testing.T, auth Authenticator) (*Server, *SessionStore) {
	t.Helper()
	srv, sessions := newTestServer(t)
	srv.EnableOIDC(auth, &config.OIDC{GroupMapping: map[string][]string{"dev": {"team-a"}}})
	return srv, sessions
}

func getReq(srv *Server, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestOIDCLoginSetsStateNonceAndRedirects(t *testing.T) {
	srv, _ := oidcTestServer(t, &fakeAuth{})
	rec := getReq(srv, "/oidc/login")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	state := cookieNamed(rec, oidcStateCookie)
	nonce := cookieNamed(rec, oidcNonceCookie)
	if state == nil || state.Value == "" || nonce == nil || nonce.Value == "" {
		t.Fatal("login must set non-empty state and nonce cookies")
	}
	if !state.HttpOnly || !nonce.HttpOnly {
		t.Error("state and nonce cookies must be HttpOnly")
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "state="+state.Value) {
		t.Errorf("redirect %q must carry the state value", loc)
	}
}

func TestOIDCCallbackIssuesGroupMappedToken(t *testing.T) {
	auth := &fakeAuth{claims: Claims{Subject: "user-1", Email: "u1@example.com", Groups: []string{"dev"}}}
	srv, sessions := oidcTestServer(t, auth)

	login := getReq(srv, "/oidc/login")
	state := cookieNamed(login, oidcStateCookie)
	nonce := cookieNamed(login, oidcNonceCookie)

	rec := getReq(srv, "/oidc/callback?code=auth-code&state="+state.Value, state, nonce)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", rec.Code)
	}
	// The nonce set at /oidc/login must be the one checked at the callback.
	if auth.gotNonce != nonce.Value {
		t.Errorf("Verify nonce = %q, want the login nonce %q", auth.gotNonce, nonce.Value)
	}
	if auth.gotCode != "auth-code" {
		t.Errorf("Verify code = %q, want auth-code", auth.gotCode)
	}
	sc := sessionCookieFrom(t, rec)
	if sc == nil || sc.Value == "" {
		t.Fatal("callback must issue a session token")
	}
	client, ok := sessions.ClientByToken(sc.Value)
	if !ok {
		t.Fatal("issued OIDC token must resolve")
	}
	if client.ID != "user-1" || !equalStrings(client.Groups, []string{"team-a"}) {
		t.Errorf("resolved client = %+v, want user-1/[team-a]", client)
	}
	// The single-use flow cookies must be cleared once consumed.
	for _, name := range []string{oidcStateCookie, oidcNonceCookie} {
		c := cookieNamed(rec, name)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("flow cookie %q must be cleared (MaxAge<0) after the callback, got %+v", name, c)
		}
	}
}

func TestOIDCCallbackRejectsStateMismatch(t *testing.T) {
	auth := &fakeAuth{claims: Claims{Subject: "user-1", Groups: []string{"dev"}}}
	srv, _ := oidcTestServer(t, auth)

	login := getReq(srv, "/oidc/login")
	state := cookieNamed(login, oidcStateCookie)
	nonce := cookieNamed(login, oidcNonceCookie)

	// Query state does not match the state cookie -> CSRF rejection.
	rec := getReq(srv, "/oidc/callback?code=auth-code&state=forged", state, nonce)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on state mismatch", rec.Code)
	}
	if auth.called {
		t.Error("Verify must not be called when state does not match")
	}
	if sessionCookieFrom(t, rec) != nil {
		t.Error("no session token may be issued on a CSRF failure")
	}
}

func TestOIDCCallbackVerifyFailureIssuesNoToken(t *testing.T) {
	auth := &fakeAuth{verifyErr: context.Canceled} // stands in for a bad nonce / verify failure
	srv, _ := oidcTestServer(t, auth)

	login := getReq(srv, "/oidc/login")
	state := cookieNamed(login, oidcStateCookie)
	nonce := cookieNamed(login, oidcNonceCookie)

	rec := getReq(srv, "/oidc/callback?code=auth-code&state="+state.Value, state, nonce)
	if rec.Code == http.StatusOK {
		t.Error("verify failure must not yield 200")
	}
	if sc := sessionCookieFrom(t, rec); sc != nil && sc.Value != "" {
		t.Error("verify failure must not issue a session token")
	}
}

// --- local login is unaffected by OIDC being off/misconfigured ---

func TestLocalLoginWorksWithoutOIDC(t *testing.T) {
	srv, sessions := newTestServer(t) // OIDC never enabled
	// The login page must not advertise OIDC.
	page := getReq(srv, "/login")
	if strings.Contains(page.Body.String(), "/oidc/login") {
		t.Error("login page must not show OIDC when it is disabled")
	}
	// OIDC routes must not be served.
	if rec := getReq(srv, "/oidc/login"); rec.Code != http.StatusNotFound {
		t.Errorf("/oidc/login status = %d, want 404 when OIDC disabled", rec.Code)
	}
	// Local login still issues a working token.
	rec := postForm(srv, "/login", map[string][]string{"username": {"alice"}, "password": {"pw"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("local login status = %d, want 200", rec.Code)
	}
	sc := sessionCookieFrom(t, rec)
	if sc == nil {
		t.Fatal("local login must still issue a token")
	}
	if _, ok := sessions.ClientByToken(sc.Value); !ok {
		t.Error("local token must resolve")
	}
}

func TestLoginPageShowsOIDCWhenEnabled(t *testing.T) {
	srv, _ := oidcTestServer(t, &fakeAuth{})
	page := getReq(srv, "/login")
	if !strings.Contains(page.Body.String(), "/oidc/login") {
		t.Error("login page must offer the OIDC option when enabled")
	}
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
