package webauth

import (
	"crypto/subtle"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/zzn01/airlock/internal/config"
)

// sessionCookie carries the issued token in the browser so logout can revoke it
// server-side. It is HttpOnly; the token is also displayed for pasting into
// gateway/MCP clients.
const sessionCookie = "airlock_session"

// oidcStateCookie and oidcNonceCookie carry the short-lived CSRF state and
// replay-defeating nonce across the OIDC authorization-code round trip. Both are
// HttpOnly and cleared once the callback consumes them.
const (
	oidcStateCookie = "airlock_oidc_state"
	oidcNonceCookie = "airlock_oidc_nonce"
)

// oidcCookieMaxAge bounds how long a login attempt's state/nonce stay valid.
const oidcCookieMaxAge = 10 * 60 // seconds

//go:embed templates/*.html
var templatesFS embed.FS

// Server renders the login flow: the local-account form, a post-login page
// showing the issued token, logout, and — when OIDC is enabled — the OIDC
// authorization-code round trip. It owns no authorization logic; it only
// authenticates an identity and issues/revokes session tokens.
type Server struct {
	users    *UserStore
	sessions *SessionStore
	logger   *slog.Logger
	tmpl     *template.Template

	// oidc is the OIDC authenticator; nil disables OIDC, leaving local login
	// fully functional. oidcCfg holds the claim->group mapping and overrides.
	oidc    Authenticator
	oidcCfg *config.OIDC
}

// NewServer builds the login front-end over the given user and session stores.
// OIDC is off until EnableOIDC is called.
func NewServer(users *UserStore, sessions *SessionStore, logger *slog.Logger) *Server {
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html"))
	return &Server{users: users, sessions: sessions, logger: logger, tmpl: tmpl}
}

// EnableOIDC turns on the OIDC login option, served alongside local accounts.
// It must be called before Handler. A nil authenticator leaves OIDC disabled,
// so a failed provider setup degrades to local-only login.
func (s *Server) EnableOIDC(auth Authenticator, cfg *config.OIDC) {
	s.oidc = auth
	s.oidcCfg = cfg
}

func (s *Server) oidcEnabled() bool { return s.oidc != nil && s.oidcCfg != nil }

// Handler returns the login front-end's HTTP handler. It is mounted on its own
// listener, fully separated from the gated backend routes and health probes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	if s.oidcEnabled() {
		mux.HandleFunc("/oidc/login", s.handleOIDCLogin)
		mux.HandleFunc("/oidc/callback", s.handleOIDCCallback)
	}
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "login", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.render(w, "login", http.StatusOK, map[string]any{"Title": "login", "OIDCEnabled": s.oidcEnabled()})
	case http.MethodPost:
		s.handleLoginPost(w, r)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	user, ok := s.users.Authenticate(username, password)
	if !ok {
		s.log("warn", "login failed", "username", username, "remote_addr", r.RemoteAddr)
		s.render(w, "login", http.StatusUnauthorized, map[string]any{
			"Title":       "login",
			"Error":       "Invalid username or password.",
			"OIDCEnabled": s.oidcEnabled(),
		})
		return
	}

	s.log("info", "login ok", "username", username)
	s.issueSession(w, r, user)
}

// issueSession mints a session token for an authenticated user, sets the
// HttpOnly session cookie, and renders the token page. Both the local-account
// and OIDC paths converge here, so there is exactly one token model.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, user User) {
	token, expires, err := s.sessions.Issue(user)
	if err != nil {
		s.log("error", "issue token", "username", user.Username, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	s.render(w, "token", http.StatusOK, map[string]any{
		"Title":   "token",
		"Token":   token,
		"Expires": expires.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	s.render(w, "loggedout", http.StatusOK, map[string]any{"Title": "logged out"})
}

// handleOIDCLogin starts the authorization-code flow: it mints a fresh state and
// nonce, stores them in short-lived HttpOnly cookies, and redirects the browser
// to the provider's authorization endpoint carrying both.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	state, err := randomToken()
	if err != nil {
		s.log("error", "oidc state", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		s.log("error", "oidc nonce", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	s.setFlowCookie(w, r, oidcStateCookie, state, oidcCookieMaxAge)
	s.setFlowCookie(w, r, oidcNonceCookie, nonce, oidcCookieMaxAge)
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce), http.StatusSeeOther)
}

// handleOIDCCallback completes the flow: it enforces the state CSRF check, then
// exchanges and verifies the code (signature, audience, nonce) and issues the
// same session token local login issues, with groups derived from the claims.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	// Read the flow cookies, then clear them up front: this attempt consumes
	// them either way, and the clearing Set-Cookie headers must be written
	// before any response body, which the branches below emit.
	stateVal, nonce := "", ""
	if c, err := r.Cookie(oidcStateCookie); err == nil {
		stateVal = c.Value
	}
	if c, err := r.Cookie(oidcNonceCookie); err == nil {
		nonce = c.Value
	}
	s.clearFlowCookie(w, r, oidcStateCookie)
	s.clearFlowCookie(w, r, oidcNonceCookie)

	if stateVal == "" ||
		subtle.ConstantTimeCompare([]byte(stateVal), []byte(r.URL.Query().Get("state"))) != 1 {
		s.log("warn", "oidc state mismatch", "remote_addr", r.RemoteAddr)
		s.render(w, "login", http.StatusBadRequest, map[string]any{
			"Title": "login", "Error": "Login session expired or invalid. Please try again.", "OIDCEnabled": true,
		})
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		s.log("warn", "oidc provider error", "error", errParam)
		s.oidcError(w)
		return
	}

	claims, err := s.oidc.Verify(r.Context(), r.URL.Query().Get("code"), nonce)
	if err != nil {
		s.log("warn", "oidc verify failed", "error", err)
		s.oidcError(w)
		return
	}

	identity := claims.Subject
	if identity == "" {
		identity = claims.Email
	}
	groups := DeriveGroups(claims, s.oidcCfg)
	s.log("info", "oidc login ok", "subject", claims.Subject, "groups", groups)
	s.issueSession(w, r, User{Username: identity, Groups: groups})
}

// oidcError renders the login page with a generic OIDC failure message and a
// 401, issuing no token.
func (s *Server) oidcError(w http.ResponseWriter) {
	s.render(w, "login", http.StatusUnauthorized, map[string]any{
		"Title": "login", "Error": "OIDC login failed. Please try again.", "OIDCEnabled": true,
	})
}

func (s *Server) setFlowCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *Server) clearFlowCookie(w http.ResponseWriter, r *http.Request, name string) {
	s.setFlowCookie(w, r, name, "", -1)
}

func (s *Server) render(w http.ResponseWriter, name string, status int, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log("error", "render template", "template", name, "error", err)
	}
}

func (s *Server) log(level, msg string, args ...any) {
	if s.logger == nil {
		return
	}
	switch level {
	case "error":
		s.logger.Error(msg, args...)
	case "warn":
		s.logger.Warn(msg, args...)
	default:
		s.logger.Info(msg, args...)
	}
}
