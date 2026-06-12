package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zzn01/airlock/internal/config"
	"github.com/zzn01/airlock/internal/webauth"
)

// This file proves the end-to-end OIDC path: an OIDC login derives a user's
// groups from a configurable claim mapping and issues a token that, used against
// the EXISTING proxy pipeline, is authorized exactly by those derived groups —
// reaching a backend gated to the mapped group, denied for a foreign one. No
// live IdP: the Authenticator is faked with injected ID-token claims.

// fakeOIDC is a webauth.Authenticator returning canned claims (no IdP).
type fakeOIDC struct{ claims webauth.Claims }

func (f fakeOIDC) AuthCodeURL(state, nonce string) string {
	return "/oidc/callback?state=" + state + "&nonce=" + nonce
}
func (f fakeOIDC) Verify(_ context.Context, _, _ string) (webauth.Claims, error) {
	return f.claims, nil
}

// webLogin builds a web front-end sharing the gateway's session store, with
// OIDC enabled over the given claims and a dev->team-a / ops->team-b mapping.
func webLogin(t *testing.T, sessions *webauth.SessionStore, claims webauth.Claims) *webauth.Server {
	t.Helper()
	users, err := webauth.LoadUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("LoadUserStore: %v", err)
	}
	srv := webauth.NewServer(users, sessions, nil)
	srv.EnableOIDC(fakeOIDC{claims: claims}, &config.OIDC{
		GroupMapping: map[string][]string{"dev": {"team-a"}, "ops": {"team-b"}},
	})
	return srv
}

// runOIDCFlow drives /oidc/login then /oidc/callback through srv and returns the
// issued session token (the value of the airlock_session cookie).
func runOIDCFlow(t *testing.T, srv *webauth.Server) string {
	t.Helper()
	h := srv.Handler()

	loginReq := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	var state string
	cbReq := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	for _, c := range loginRec.Result().Cookies() {
		cbReq.AddCookie(c)
		if c.Name == "airlock_oidc_state" {
			state = c.Value
		}
	}
	cbReq.URL.RawQuery = "code=auth-code&state=" + state
	cbRec := httptest.NewRecorder()
	h.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("oidc callback status = %d, want 200", cbRec.Code)
	}
	for _, c := range cbRec.Result().Cookies() {
		if c.Name == "airlock_session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("oidc callback issued no session token")
	return ""
}

func TestOIDCMappedTokenReachesGatedBackend(t *testing.T) {
	g, sessions, _ := buildWebAuthGateway(t)

	// The IdP asserts group "dev", which the config maps to airlock group
	// "team-a" — the group gating the backend. The derived token must reach it.
	srv := webLogin(t, sessions, webauth.Claims{Subject: "alice", Groups: []string{"dev"}})
	token := runOIDCFlow(t, srv)

	if rec := get(g, grafanaSearch, token); rec.Code != http.StatusOK {
		t.Fatalf("OIDC team-a token status = %d, want 200 (groups must drive access)", rec.Code)
	}
}

func TestOIDCForeignGroupTokenDenied(t *testing.T) {
	g, sessions, _ := buildWebAuthGateway(t)

	// The IdP asserts "ops" -> team-b, which does NOT gate the backend; the
	// coarse group gate must deny (403, not 401: authenticated, not authorized).
	srv := webLogin(t, sessions, webauth.Claims{Subject: "bob", Groups: []string{"ops"}})
	token := runOIDCFlow(t, srv)

	if rec := get(g, grafanaSearch, token); rec.Code != http.StatusForbidden {
		t.Errorf("OIDC team-b token status = %d, want 403 (group gate)", rec.Code)
	}
}
