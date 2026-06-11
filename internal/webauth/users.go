// Package webauth is airlock's optional local-account web login front-end.
//
// It is an identity + token-issuance layer only: it authenticates a local user
// (username + bcrypt-hashed password) and issues a short-lived opaque bearer
// token bound to that user's groups. The token resolves to a client identity
// through the gateway's existing token-resolution path, so all authorization,
// tenancy, rate limiting, and audit continue to happen in the one place they
// already live (internal/gateway). webauth holds no authorization logic.
//
// Persistence: the user store (usernames, bcrypt hashes, groups) is persisted
// to a JSON file. Sessions (issued tokens) are kept in memory only and do not
// survive a restart, which keeps token revocation trivial (delete the entry).
package webauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// User is one local account. The password is never stored in plaintext; only
// its bcrypt hash is persisted.
type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Groups       []string `json:"groups"`
}

// userFile is the on-disk JSON shape of the user store.
type userFile struct {
	Users []User `json:"users"`
}

// UserStore is a persisted set of local accounts, keyed by username. It is safe
// for concurrent use.
type UserStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]User
}

// LoadUserStore reads the user store at path. A missing file yields an empty
// store (the file is created on the first save), so a fresh deployment can be
// bootstrapped without pre-creating it.
func LoadUserStore(path string) (*UserStore, error) {
	s := &UserStore{path: path, users: make(map[string]User)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read user store: %w", err)
	}
	var uf userFile
	if err := json.Unmarshal(raw, &uf); err != nil {
		return nil, fmt.Errorf("parse user store: %w", err)
	}
	for _, u := range uf.Users {
		s.users[u.Username] = u
	}
	return s, nil
}

// Authenticate verifies username/password against the store, returning the
// matched user (with its groups) on success. An unknown username fails without
// a bcrypt comparison; a known user's password is checked with bcrypt's
// constant-time comparison.
func (s *UserStore) Authenticate(username, password string) (User, bool) {
	s.mu.RLock()
	u, ok := s.users[username]
	s.mu.RUnlock()
	if !ok {
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return User{}, false
	}
	return u, true
}

// EnsureUser creates the account if it does not already exist, hashing the
// password with bcrypt and persisting the store. It reports whether a new user
// was created; an existing user is left untouched (idempotent bootstrap).
func (s *UserStore) EnsureUser(username, password string, groups []string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username must not be empty")
	}
	if password == "" {
		return false, fmt.Errorf("password must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return false, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("hash password: %w", err)
	}
	s.users[username] = User{Username: username, PasswordHash: string(hash), Groups: append([]string(nil), groups...)}
	if err := s.saveLocked(); err != nil {
		delete(s.users, username)
		return false, err
	}
	return true, nil
}

// saveLocked writes the store to its file atomically (write to a temp file in
// the same directory, then rename) with 0600 permissions, since the file holds
// password hashes. The caller must hold s.mu.
func (s *UserStore) saveLocked() error {
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	raw, err := json.MarshalIndent(userFile{Users: users}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal user store: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".users-*.json")
	if err != nil {
		return fmt.Errorf("create temp user store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp user store: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp user store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp user store: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace user store: %w", err)
	}
	return nil
}
