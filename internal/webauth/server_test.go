package webauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestServer builds a login server with one user "alice"/"pw" in team-a.
func newTestServer(t *testing.T) (*Server, *SessionStore) {
	t.Helper()
	users, err := LoadUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("LoadUserStore: %v", err)
	}
	if _, err := users.EnsureUser("alice", "pw", []string{"team-a"}); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	sessions := NewSessionStore(time.Hour, func() time.Time { return time.Unix(0, 0) })
	return NewServer(users, sessions, nil), sessions
}

func postForm(srv *Server, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func TestLoginPageRenders(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Structural contract: the form must expose the fields the POST handler reads.
	if !strings.Contains(body, `name="username"`) || !strings.Contains(body, `name="password"`) {
		t.Error("login page must contain username and password fields")
	}
}

func TestLoginSuccessIssuesWorkingToken(t *testing.T) {
	srv, sessions := newTestServer(t)
	rec := postForm(srv, "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	cookie := sessionCookieFrom(t, rec)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("successful login must set a session cookie carrying the token")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	// The issued token must be displayed for pasting into a client...
	if !strings.Contains(rec.Body.String(), cookie.Value) {
		t.Error("post-login page must display the issued token")
	}
	// ...and it must actually resolve to the user's groups.
	client, ok := sessions.ClientByToken(cookie.Value)
	if !ok {
		t.Fatal("issued token must resolve in the session store")
	}
	if client.ID != "alice" || len(client.Groups) != 1 || client.Groups[0] != "team-a" {
		t.Errorf("resolved client = %+v, want alice/[team-a]", client)
	}
}

func TestLoginFailureIssuesNoToken(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postForm(srv, "/login", url.Values{"username": {"alice"}, "password": {"wrong"}}, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if c := sessionCookieFrom(t, rec); c != nil && c.Value != "" {
		t.Error("a failed login must not set a session token")
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	srv, sessions := newTestServer(t)
	login := postForm(srv, "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, nil)
	cookie := sessionCookieFrom(t, login)
	if cookie == nil {
		t.Fatal("login should have set a cookie")
	}
	if _, ok := sessions.ClientByToken(cookie.Value); !ok {
		t.Fatal("token should resolve before logout")
	}

	rec := postForm(srv, "/logout", url.Values{}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", rec.Code)
	}
	if _, ok := sessions.ClientByToken(cookie.Value); ok {
		t.Error("token must not resolve after logout")
	}
}
