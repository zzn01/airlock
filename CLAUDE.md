# airlock

Authenticating L7 gateway that safely exposes infrastructure to LLMs. A single
HTTP server is the sole entry point for the untrusted LLM side; the trusted side
is never reached directly.

## Build & test

- `make ci` — runs `go vet`, `go test`, and `go build` over the whole module.
  Keep it green at every commit. The core is stdlib; external dependencies are
  the MCP SDK (`github.com/modelcontextprotocol/go-sdk`, used by
  `internal/mcpserver`), `golang.org/x/crypto/bcrypt` (password hashing in
  `internal/webauth`), and `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`
  (OIDC/SSO login in `internal/webauth`).

## Request pipeline (`internal/gateway`)

After authentication, requests split into two pipelines by path. The legacy
**op pipeline** (Redis, `/redis/*`) and the **proxy pipeline** (`httpproxy`
instances, `/b/<instance>/...`).

Authenticate first (both): `Authorization: Bearer <token>` or
`X-API-Key: <token>` resolves to a client identity via `Gateway.ResolveClient`
— static config clients first, then any dynamic `TokenResolver` (the web-login
session store). Missing/invalid/expired/revoked => `401`.

Op pipeline (`/redis/*`):

1. **Route** — `(method, path)` resolves to a registered operation. No match =>
   `404`. There is no wildcard forwarding.
2. **Authorize** — default-deny: the client's explicit `allow[]` must contain
   the operation id, else `403`.
3. **Rate limit** — per-client token bucket; over limit => `429`.
4. **Execute** — the operation handler runs.

Proxy pipeline (`/b/<instance>/...`, see design doc):

1. **Resolve instance** — the first path segment names exactly one `httpproxy`
   instance (strict per-instance boundary; no merged global path table).
   Unknown instance => `404`.
2. **Coarse group gate** — `client.groups ∩ instance.allowed_groups`; empty =>
   `403`.
3. **Endpoint allowlist** — `(method, upstream-path)` must match the instance's
   read-only preset/extra allowlist, else `403`.
4. **Grant** — some `(group, backend)` grant for an effective group must list
   the endpoint id (default-deny), else `403`.
5. **Rate limit** — per-client token bucket; over limit => `429`.
6. **Scoped proxy** — the gateway strips client-supplied widening inputs, then
   injects forced params/headers, VictoriaLogs tenancy + mandatory LogsQL
   filter, and upstream auth, caps the response body, and proxies upstream.

**Audit** (both): one structured `log/slog` record per request (allow=INFO,
deny=WARN) with client id, operation, decision, reason, and status.

## Packages

- `cmd/airlock` — entry point; loads config, serves the gateway via
  `Gateway.Handler()`, optionally serves the MCP and web-login front-ends on
  their own listeners, and shuts down gracefully (drains in-flight requests
  within a bounded timeout) on SIGINT/SIGTERM.
- `internal/config` — JSON config model + loader. `AIRLOCK_CONFIG` selects the
  file (default `airlock.json`); `AIRLOCK_LISTEN` overrides the listen address.
  `Config.Validate` fails fast at startup on a malformed config (`config.go`);
  `resolve.go` resolves `env:`/`file:` secret references before validation.
- `internal/gateway` — the request pipeline (`Gateway`) and the composition root
  (`Build`) that wires config + backends into an `http.Handler`. `Handler()`
  (`health.go`) serves the unauthenticated `/healthz` (liveness) and `/readyz`
  (readiness) probes outside the auth pipeline, falling through to the gated
  pipeline for everything else. `mcpaccess.go` exposes read-only seams
  (`Config`, `Proxies`, `HasOperation`, `BearerToken`) the MCP front-end uses to
  introspect identity/instances and re-dispatch tool calls through `ServeHTTP`.
  `resolver.go` defines the `TokenResolver` seam and `ResolveClient`
  (config clients first, then any registered dynamic resolver); both the HTTP
  pipeline and the MCP front-end resolve identity through it.
- `internal/webauth` — the optional web-login front-end (Phase 2). A persisted
  `UserStore` (username + bcrypt hash + groups, atomic `0600` JSON file)
  authenticates a local user; a `SessionStore` (in-memory, injectable clock)
  issues an opaque bearer token bound to the user's identity+groups+expiry and
  satisfies `gateway.TokenResolver` so the token resolves through the existing
  access-control core. `server.go` serves the minimal server-rendered
  login/token/logout pages (embedded `html/template`) on its own listener.
  `oidc.go` adds **OIDC/SSO login** (slice 2b) as a second identity source: the
  `Authenticator` seam (real `OIDCProvider` over go-oidc + oauth2; faked in
  tests) runs the authorization-code flow with `state`/`nonce` CSRF protection,
  and the pure `DeriveGroups` maps a configurable ID-token claim to airlock
  groups (admin per-user override first, else the config `group_mapping`).
  Both paths converge on `SessionStore.Issue`, so OIDC yields the same token
  model. Identity + token issuance only — no authorization logic.
- `internal/mcpserver` — the MCP (Model Context Protocol) front-end: a
  streamable-HTTP MCP server served alongside the gateway that maps the curated
  operations to MCP tools. It is a protocol adapter only — it holds no
  authorization/tenancy logic. It resolves the bearer token to a client with the
  same mechanism the gateway uses, filters the tool list to the client's grants
  (default-deny; each httpproxy tool's `instance` arg is an enum of reachable
  instances), and re-dispatches every call through `gateway.Gateway.ServeHTTP`
  so authz, scoping, rate limiting, and audit happen in the one existing place.
  **Each MCP session is bound to the client that authenticated its
  `initialize`**: auth goes through the SDK's `auth.RequireBearerToken`, which
  stamps a stable per-client user id (`sessionUserID`) into the request context,
  and the streamable transport rejects (`403`) any later request that presents a
  session's `Mcp-Session-Id` while authenticated as a different client — so a
  client cannot ride another's session with the creator's identity/grants/token/
  tenancy. Static config clients and web-issued tokens bind identically.
- `internal/backend` — the `Operation`/`Backend` model and a route `Registry`.
- `internal/backend/httpproxy` — read-only HTTP reverse-proxy backend type.
  Multiple named `Instance`s (via a `Manager`), each with its own `base_url`,
  read-only endpoint allowlist (Prometheus/VictoriaLogs/Grafana `Preset` plus
  optional extras), `allowed_groups` (coarse gate), per-`Grant` endpoints +
  data `Scope` (forced/stripped params & headers, VictoriaLogs tenancy +
  mandatory LogsQL filter), upstream auth, and response/result guardrails.
- `internal/backend/redisro` — read-only Redis tool. `ReadClient` is the only
  seam to Redis and exposes GET/SCAN/EXISTS/TTL only; `resp.go` is a minimal
  pure-stdlib RESP client that emits read commands exclusively. A
  reflection-based test guards that no write method can appear on the surface.
- `internal/ratelimit` — per-client token-bucket limiter with an injectable
  clock (deterministic under test).
- `internal/audit` — structured slog audit event + emitter.

## Configuration

JSON file; see `airlock.example.json`. Fields: `listen`, optional
`mcp{enable,listen,path}` (the MCP front-end; off unless `enable`, defaults
`:8081` / `/mcp`), optional `web{enable,listen,users_file,token_ttl,bootstrap,oidc}`
(the web login; off unless `enable`, default listen `:8082`,
`token_ttl` default `12h`; `bootstrap{username,password,groups}` creates an
initial local user at startup if absent, `password` being a secret reference;
`oidc{enable,issuer,client_id,client_secret,redirect_url,scopes,groups_claim,
group_mapping,overrides}` adds OIDC/SSO login — claim→group mapping with admin
per-user overrides, `client_secret` a secret reference; a disabled or
unreachable provider never breaks local login),
`groups[]` (named groups), `clients[]` (`id`, `token`,
`groups[]`, `allow[]` of operation ids for Redis, `rate_limit{rps,burst}`), and
`backends`:

- `backends.redis.addr` — read-only Redis tool (optional).
- `backends.httpproxy[]` — proxy instances, each: `name`, `type`
  (`prometheus`|`victorialogs`|`grafana`), `base_url`, `allowed_groups[]`,
  optional `upstream_auth{header:value}`, `max_response_bytes`,
  `max_result_limit`+`result_limit_param`, `extra_endpoints[]`, and `grants[]`
  (`group`, `endpoints[]` of endpoint ids, `scope`). `scope` supports
  `forced_query_params`, `forced_headers`, `strip_query_params`,
  `strip_headers`, and `victorialogs{account_id,project_id,mandatory_filter,
  query_param}`.

At least one backend (redis or httpproxy) must be configured.

Secret-bearing values (client `token`s, `upstream_auth` values, the web
`bootstrap.password`, the web `oidc.client_secret`) may be given as `env:NAME`
or `file:/path` references, resolved at load (plaintext still works). See the
README for the scheme.

## Design

`docs/design/2026-06-11-airlock.md` (MVP),
`docs/design/2026-06-11-airlock-group-access.md` (groups, httpproxy backends,
strict per-instance routing, multi-tenant scoping), and
`docs/design/2026-06-11-airlock-mcp-server.md` (MCP front-end as a protocol
adapter reusing the same security core), and
`docs/design/2026-06-11-airlock-web-auth.md` (local-account web login + opaque
token issuance feeding the existing identity/groups resolution), and
`docs/design/2026-06-12-airlock-oidc-login.md` (OIDC/SSO login as a second
identity source with configurable claim→group mapping and admin overrides).

## Scope

Implemented: gateway pipeline, read-only Redis tool, group-based access control,
multi-instance HTTP reverse-proxy backends (Prometheus/VictoriaLogs/Grafana
read-only presets) with per-`(group,backend)` grants and server-side data
scoping, an MCP front-end exposing the curated operations as MCP tools over the
same security core, a local-account web login that issues short-lived bearer
tokens resolving to a user's groups through that same core, and OIDC/SSO login
(authorization-code flow) deriving those groups from a configurable ID-token
claim with admin per-user overrides. Not yet: an admin console (user/group/grant
CRUD), Postgres tool, gateway metrics.
