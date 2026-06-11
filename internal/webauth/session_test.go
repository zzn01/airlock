package webauth

import (
	"testing"
	"time"
)

func TestSessionIssueAndResolve(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewSessionStore(time.Hour, func() time.Time { return now })

	token, expires, err := store.Issue(User{Username: "alice", Groups: []string{"team-a", "sre"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("Issue must return a non-empty token")
	}
	if !expires.Equal(now.Add(time.Hour)) {
		t.Errorf("expires = %v, want %v", expires, now.Add(time.Hour))
	}

	client, ok := store.ClientByToken(token)
	if !ok {
		t.Fatal("a freshly issued token must resolve")
	}
	if client.ID != "alice" {
		t.Errorf("client ID = %q, want alice", client.ID)
	}
	if len(client.Groups) != 2 || client.Groups[0] != "team-a" || client.Groups[1] != "sre" {
		t.Errorf("client groups = %v, want [team-a sre]", client.Groups)
	}
}

func TestSessionIssueTokensAreUnique(t *testing.T) {
	store := NewSessionStore(time.Hour, func() time.Time { return time.Unix(0, 0) })
	t1, _, _ := store.Issue(User{Username: "a"})
	t2, _, _ := store.Issue(User{Username: "b"})
	if t1 == t2 {
		t.Fatal("distinct sessions must get distinct tokens")
	}
}

func TestSessionExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewSessionStore(time.Hour, func() time.Time { return now })
	token, _, _ := store.Issue(User{Username: "alice", Groups: []string{"team-a"}})

	now = now.Add(time.Hour - time.Second)
	if _, ok := store.ClientByToken(token); !ok {
		t.Fatal("token should still resolve just before expiry")
	}

	now = now.Add(2 * time.Second) // now past the TTL
	if _, ok := store.ClientByToken(token); ok {
		t.Fatal("an expired token must not resolve")
	}
}

func TestSessionRevoke(t *testing.T) {
	store := NewSessionStore(time.Hour, func() time.Time { return time.Unix(0, 0) })
	token, _, _ := store.Issue(User{Username: "alice", Groups: []string{"team-a"}})

	if !store.Revoke(token) {
		t.Fatal("Revoke should report the token was present")
	}
	if _, ok := store.ClientByToken(token); ok {
		t.Fatal("a revoked token must not resolve")
	}
	if store.Revoke(token) {
		t.Error("revoking an already-revoked token should report absent")
	}
}

func TestSessionUnknownToken(t *testing.T) {
	store := NewSessionStore(time.Hour, func() time.Time { return time.Unix(0, 0) })
	if _, ok := store.ClientByToken("bogus"); ok {
		t.Error("an unknown token must not resolve")
	}
	if _, ok := store.ClientByToken(""); ok {
		t.Error("an empty token must not resolve")
	}
}
