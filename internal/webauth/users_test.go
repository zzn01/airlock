package webauth

import (
	"path/filepath"
	"testing"
)

func TestEnsureUserAndAuthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	store, err := LoadUserStore(path)
	if err != nil {
		t.Fatalf("LoadUserStore: %v", err)
	}

	created, err := store.EnsureUser("alice", "correct horse", []string{"team-a"})
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if !created {
		t.Fatal("EnsureUser should report the user was created")
	}

	user, ok := store.Authenticate("alice", "correct horse")
	if !ok {
		t.Fatal("Authenticate with the correct password should succeed")
	}
	if len(user.Groups) != 1 || user.Groups[0] != "team-a" {
		t.Errorf("groups = %v, want [team-a]", user.Groups)
	}

	if _, ok := store.Authenticate("alice", "wrong"); ok {
		t.Error("Authenticate with a wrong password must fail")
	}
	if _, ok := store.Authenticate("nobody", "correct horse"); ok {
		t.Error("Authenticate for an unknown user must fail")
	}
}

func TestEnsureUserIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	store, _ := LoadUserStore(path)
	if _, err := store.EnsureUser("alice", "pw1", []string{"team-a"}); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	created, err := store.EnsureUser("alice", "pw2", []string{"team-b"})
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if created {
		t.Fatal("re-ensuring an existing user must not recreate or overwrite it")
	}
	// The original password and groups must be preserved.
	if _, ok := store.Authenticate("alice", "pw1"); !ok {
		t.Error("original password should still authenticate")
	}
	if _, ok := store.Authenticate("alice", "pw2"); ok {
		t.Error("the second EnsureUser must not change the password")
	}
}

func TestUserStorePersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	store, _ := LoadUserStore(path)
	if _, err := store.EnsureUser("bob", "hunter2", []string{"sre"}); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	// A fresh store loaded from the same file must authenticate the user.
	reloaded, err := LoadUserStore(path)
	if err != nil {
		t.Fatalf("reload LoadUserStore: %v", err)
	}
	user, ok := reloaded.Authenticate("bob", "hunter2")
	if !ok {
		t.Fatal("reloaded store should authenticate the persisted user")
	}
	if len(user.Groups) != 1 || user.Groups[0] != "sre" {
		t.Errorf("groups = %v, want [sre]", user.Groups)
	}
}

func TestLoadUserStoreMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	store, err := LoadUserStore(path)
	if err != nil {
		t.Fatalf("LoadUserStore on missing file should succeed: %v", err)
	}
	if _, ok := store.Authenticate("anyone", "anything"); ok {
		t.Error("empty store must not authenticate anyone")
	}
}
