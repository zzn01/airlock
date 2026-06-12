package webauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/zzn01/airlock/internal/config"
)

// tokenBytes is the entropy of an issued session token before base64 encoding.
const tokenBytes = 32

// session is an issued token's server-side record.
type session struct {
	clientID string
	groups   []string
	expires  time.Time
}

// SessionStore holds the in-memory set of issued web-login tokens. Each token
// is an opaque random string bound to a user identity, the user's groups, and
// an expiry. It is safe for concurrent use.
//
// SessionStore satisfies the gateway's token-resolver seam: ClientByToken maps
// a live token to a config.Client carrying the user's groups, which the gateway
// then runs through the same access-control core as a static config client.
type SessionStore struct {
	mu       sync.Mutex
	now      func() time.Time
	ttl      time.Duration
	sessions map[string]session
}

// NewSessionStore returns a store issuing tokens that live for ttl. If now is
// nil, time.Now is used; tests inject a deterministic clock.
func NewSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	if now == nil {
		now = time.Now
	}
	return &SessionStore{now: now, ttl: ttl, sessions: make(map[string]session)}
}

// Issue mints a new opaque token for user, records it with the user's groups
// and an expiry of now+ttl, and returns the token and its expiry time.
func (s *SessionStore) Issue(user User) (string, time.Time, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	expires := s.now().Add(s.ttl)

	s.mu.Lock()
	s.sessions[token] = session{
		clientID: user.Username,
		groups:   append([]string(nil), user.Groups...),
		expires:  expires,
	}
	s.mu.Unlock()
	return token, expires, nil
}

// ClientByToken resolves a live token to a client identity carrying the user's
// groups. An unknown or expired token does not resolve; an expired entry is
// dropped on access. This is the gateway's token-resolver seam.
func (s *SessionStore) ClientByToken(token string) (config.Client, bool) {
	if token == "" {
		return config.Client{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return config.Client{}, false
	}
	if !s.now().Before(sess.expires) {
		delete(s.sessions, token)
		return config.Client{}, false
	}
	return config.Client{ID: sess.clientID, Groups: sess.groups}, true
}

// Revoke deletes a token, returning whether it was present. Logout uses it so a
// token stops resolving immediately.
func (s *SessionStore) Revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[token]; !ok {
		return false
	}
	delete(s.sessions, token)
	return true
}
