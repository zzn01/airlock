# Airlock web login & token issuance (local accounts)

Status: implemented (Phase 2, first slice)
Date: 2026-06-11

## Motivation

Airlock authenticates callers by mapping a bearer token to a configured client
that carries the groups driving all downstream authorization (groups → backend
`allowed_groups` → `(group, backend)` grants → data scope). Today every token is
a static string baked into the config file. That is fine for machine clients but
gives humans no self-service way to obtain a credential.

This slice adds a **local-account web login**: a user logs in through a minimal
web page and receives a short-lived bearer token that, used against the existing
HTTP gateway and MCP server, resolves to *that user's groups* — running through
the **same access-control core, unchanged**. It adds identity + token issuance
only; it does **not** add or reinterpret any authorization or tenancy policy.

Explicitly out of scope for this slice (deferred to later PRs): OIDC/SSO login
and claim→group mapping, and an admin console for CRUD of users/groups/grants.

## Design overview

```
browser --(POST /login: username+password)--> web front-end (:8082)
                                                     |
                          (1) authenticate against the local user store (bcrypt)
                          (2) issue an opaque token, store {identity, groups, expiry}
                          (3) display the token; set an HttpOnly session cookie
                                                     |
LLM/MCP client --(Bearer <token>)--> gateway (:8080) / MCP (:8081)
                                                     |
                          gateway.ResolveClient(token):
                            config clients first, then the session store
                                                     |
                                                     v
                          EXISTING pipeline: groups → allowed_groups →
                          grants → data scope → rate limit → audit
```

The web front-end runs **alongside** the gateway and MCP server, on its own
listen address (`:8082` by default), fully separated from the gated backend
routes and the health probes. All three share one `gateway.Gateway`, hence one
access-control core and one audit stream.

## Identity & token model

**User store** (`internal/webauth/UserStore`). A set of local accounts —
`{username, bcrypt password hash, groups}` — persisted to a JSON file
(`web.users_file`). Saves are atomic (temp file + rename) with `0600`
permissions because the file holds password hashes. A missing file loads as an
empty store and is created on first write. An optional `web.bootstrap` user is
created at startup if absent, so a fresh deployment has a way in without
hardcoded credentials; its password is a secret reference (`env:`/`file:`/plain)
resolved by the same loader that resolves client tokens and upstream auth.

**Session store** (`internal/webauth/SessionStore`). On a successful login the
server mints an **opaque random token** (256 bits, base64url) and records it
in-memory with the user's identity, a copy of the user's groups, and an expiry
of `now + token_ttl`. Tokens are kept in memory only.

### Why opaque tokens (not signed/JWT)

Opaque server-side tokens were chosen over signed tokens because this slice
needs **immediate revocation** (logout, and the implicit revoke-all on restart)
and a small, auditable surface:

- Revocation is a map delete — no denylist to carry alongside a stateless token.
- No signing key to generate, store, rotate, or leak.
- The token reveals nothing and means nothing without the server's state.

The cost is that sessions do not survive a process restart (a restart revokes
all issued tokens) and do not share across replicas. For a single-instance,
human-facing login that is an acceptable, clearly-documented trade-off; the user
store *is* persisted, so accounts survive restarts even though sessions do not.

## How an issued token plugs into the existing core

The gateway gains one seam, `resolver.go`:

```go
type TokenResolver interface { ClientByToken(token string) (config.Client, bool) }

func (g *Gateway) SetTokenResolver(r TokenResolver)            // register the session store
func (g *Gateway) ResolveClient(token string) (config.Client, bool)
```

`ResolveClient` checks **static config clients first**, then the registered
dynamic resolver. Both the HTTP pipeline (`ServeHTTP`) and the MCP front-end now
resolve identity through this one method, so:

- Static config clients resolve exactly as before (config wins on any overlap).
- A web-issued token resolves to a `config.Client{ID: username, Groups: …}` —
  an ordinary client identity. From that point on it is indistinguishable to the
  authorization, scoping, rate-limiting, and audit code from a config client.
- Unknown, expired, or revoked tokens resolve to nothing ⇒ `401`, identical to
  an unknown static token.

`SessionStore` satisfies `TokenResolver` structurally (it returns a
`config.Client`), so `internal/webauth` does **not** import `internal/gateway`;
`cmd/airlock` wires them together.

## Web UI

Minimal server-rendered HTML (`html/template`, embedded; no JS framework):

- `GET /login` — the login form.
- `POST /login` — on success, issue a token, set an `HttpOnly` `airlock_session`
  cookie (`Secure` under TLS, `SameSite=Lax`), and render a page that displays
  the token with a copy button for pasting into a gateway/MCP client. On failure
  it re-renders the form with an error and HTTP `401` — and issues no token.
- `POST /logout` — revokes the token carried in the session cookie and clears it.
- `GET /` — redirects to `/login`.

## Configuration

```jsonc
"web": {
  "enable": true,
  "listen": ":8082",                       // default :8082
  "users_file": "/var/lib/airlock/users.json",
  "token_ttl": "12h",                       // Go duration; default 12h
  "bootstrap": {                            // optional; created at startup if absent
    "username": "admin",
    "password": "env:AIRLOCK_ADMIN_PASSWORD",
    "groups": ["sre"]
  }
}
```

`Config.Validate` fails fast when web login is enabled without `users_file`, on
an unparseable/non-positive `token_ttl`, on a bootstrap user with an empty
username, or on a bootstrap user referencing an undefined group.

## Testing

Deterministic, table/httptest-style, no network or wall-clock dependence
(`SessionStore` takes an injectable clock):

- user store: bootstrap/authenticate, wrong password and unknown user fail,
  `EnsureUser` is idempotent, persistence round-trips across a reload;
- session store: issue→resolve carries the right groups, tokens are unique,
  expiry (clock advance) and revoke and unknown all fail to resolve;
- web server: login page renders the credential fields, success issues a working
  token that resolves to the user's groups, failure issues none (`401`), logout
  revokes;
- gateway integration: a web token for a team reaches that team's gated backend
  through the real proxy pipeline while a foreign-group token is denied at the
  coarse gate (proving groups drive authorization); static config clients still
  authenticate; expired/revoked/unknown tokens are rejected `401`.
