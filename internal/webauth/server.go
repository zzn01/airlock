package webauth

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

// sessionCookie carries the issued token in the browser so logout can revoke it
// server-side. It is HttpOnly; the token is also displayed for pasting into
// gateway/MCP clients.
const sessionCookie = "airlock_session"

//go:embed templates/*.html
var templatesFS embed.FS

// Server renders the local-account login flow: a login form, a post-login page
// showing the issued token, and logout. It owns no authorization logic — it
// only authenticates against the user store and issues/revokes session tokens.
type Server struct {
	users    *UserStore
	sessions *SessionStore
	logger   *slog.Logger
	tmpl     *template.Template
}

// NewServer builds the login front-end over the given user and session stores.
func NewServer(users *UserStore, sessions *SessionStore, logger *slog.Logger) *Server {
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html"))
	return &Server{users: users, sessions: sessions, logger: logger, tmpl: tmpl}
}

// Handler returns the login front-end's HTTP handler. It is mounted on its own
// listener, fully separated from the gated backend routes and health probes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
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
		s.render(w, "login", http.StatusOK, map[string]any{"Title": "login"})
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
			"Title": "login",
			"Error": "Invalid username or password.",
		})
		return
	}

	token, expires, err := s.sessions.Issue(user)
	if err != nil {
		s.log("error", "issue token", "username", username, "error", err)
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
	s.log("info", "login ok", "username", username)
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
