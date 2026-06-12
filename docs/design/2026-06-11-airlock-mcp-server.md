# Airlock MCP server front-end

Status: implemented
Date: 2026-06-11

## Motivation

Airlock's HTTP gateway is the sole entry point that safely exposes internal
infrastructure to LLM-side callers. Many AI clients, however, do not speak the
gateway's bespoke HTTP surface — they speak the **Model Context Protocol
(MCP)**, discovering and invoking *tools*. This design adds an MCP server
front-end so MCP-native clients reach the same backends through MCP tools,
**without** introducing a second access-control implementation.

The hard requirement: the MCP front-end is a *protocol adapter only*. It reuses
the existing security core (client identity, groups, backend `allowed_groups`,
`(group, backend)` grants, data-scope/tenancy enforcement, per-client rate
limiting, and structured audit). It does not duplicate, fork, or re-interpret
any authorization or tenancy policy.

## Design overview

```
MCP client --(streamable HTTP, Bearer token)--> MCP front-end
                                                     |
                                 (1) auth: token -> client (config.ClientByToken)
                                 (2) list tools: filter by groups+grants
                                 (3) call tool: synthesize *http.Request
                                                     |
                                                     v
                                          gateway.Gateway.ServeHTTP
                                  (authenticate -> route -> authorize ->
                                   rate limit -> scoped execute -> audit)
                                                     |
                                                     v
                                              internal backend
```

The front-end runs **alongside** the existing HTTP gateway, on its own
configurable listen address and path. The two share one `gateway.Gateway`
instance, so they share one access-control core and one audit stream.

### The key idea: re-dispatch through the gateway

Rather than re-implement the pipeline, every MCP tool invocation is translated
into the exact HTTP request the gateway already understands and is run through
`gateway.Gateway.ServeHTTP` using an in-memory `httptest.ResponseRecorder`.

For example, the MCP call

```
prometheus_query(instance="prom-main", query="up", time="...")
```

becomes the in-process request

```
GET /b/prom-main/api/v1/query?query=up&time=...
Authorization: Bearer <client token>
```

dispatched through `ServeHTTP`. The recorded status and body become the MCP tool
result. Because the request flows through the unmodified pipeline, **all**
enforcement happens exactly once, in exactly one place:

- authentication (token -> client),
- coarse group gate (`client.groups ∩ instance.allowed_groups`),
- endpoint allowlist (read-only preset/extras),
- `(group, backend)` grant check (default-deny),
- per-client token-bucket rate limit (shared bucket with the HTTP path),
- server-side data scoping: forced/stripped params & headers, VictoriaLogs
  tenancy headers and the AND-injected mandatory LogsQL filter,
- one structured audit record (allow=INFO, deny=WARN).

The MCP layer adds no policy. A denied call surfaces to the model as an MCP tool
error (`isError: true`) carrying the gateway's status, so the model learns the
call was refused without the adapter making any authorization decision itself.

## Authentication

The streamable HTTP transport carries the client credential in the standard
`Authorization: Bearer <token>` header (the gateway's `X-API-Key` form is also
accepted, via the same `BearerToken` extraction the HTTP path uses). The token
is resolved to an airlock client with `config.Config.ClientByToken` — the same
mechanism the gateway uses.

- A request with a missing or unknown token is rejected at the HTTP layer with
  `401` (an MCP-level authentication error): **no tools are exposed**.
- A request with a valid token gets a per-connection MCP server whose tool list
  is filtered to that client's identity (below).

### Sessions are bound to the authenticating client

The streamable transport is stateful: an `initialize` call mints an
`Mcp-Session-Id`, and the per-session tool handlers close over the **session
creator's** token (the identity used to dispatch every subsequent call on that
session). Authenticating each request against *some* valid client is therefore
not enough — if a session were reusable by any valid token, a client that
learned another client's `Mcp-Session-Id` could ride that session with the
creator's identity, grants, token, and pinned tenancy (a cross-principal authz +
multi-tenant isolation break).

To prevent this, **every MCP session is bound to the client that created it**.
Authentication is the SDK's `auth.RequireBearerToken` middleware, whose verifier
resolves the token (via `Gateway.ResolveClient`, so static config clients and
web-issued tokens bind identically) and records a `TokenInfo` carrying a stable
per-client user id — the resolved client identity (never empty; it falls back to
a token-derived id so the binding guard can never sit inert). The streamable
transport captures that user id when the session is created and rejects with
`403` any later request on the same session whose user id differs. A new session
authenticated as a different client still initializes normally; only reuse of an
*existing* session by a different principal is denied, before any tool handler
runs.

## Tool generation and authorization filtering

Tools are generated from a static **catalog** that maps each curated operation
to one MCP tool:

| MCP tool | Backend | Method + path | Notes |
|---|---|---|---|
| `redis_get` | redis | `GET /redis/get` | `key` |
| `redis_scan` | redis | `GET /redis/scan` | `pattern?`, `cursor?`, `count?` |
| `redis_exists` | redis | `GET /redis/exists` | `key` |
| `redis_ttl` | redis | `GET /redis/ttl` | `key` |
| `prometheus_query` | prometheus | `GET /api/v1/query` | `instance`, `query`, `time?` |
| `prometheus_query_range` | prometheus | `GET /api/v1/query_range` | `instance`, `query`, `start`, `end`, `step` |
| `victorialogs_query` | victorialogs | `GET /select/logsql/query` | `instance`, `query`, `limit?`, `start?`, `end?` |
| `grafana_search` | grafana | `GET /api/search` | `instance`, `query?`, `tag?`, `type?` |
| `grafana_ds_query` | grafana | `POST /api/ds/query` | `instance`, `body` (JSON) |

Redis is a single backend (no instance selector). httpproxy tools select the
target instance with an `instance` argument.

**The tool list returned to a client is filtered so the model only ever sees
tools it may actually call.** Filtering is read-only introspection over the same
data the pipeline enforces against — it is a visibility hint, not a second
enforcement point (the gateway still enforces on every call):

- A redis tool is listed only if `client.Allowed(<op id>)`.
- An httpproxy tool is listed only if at least one configured instance of the
  matching type is *reachable* for the client, where reachable means:
  `instance.Effective(client.groups)` is non-empty (coarse gate), the endpoint
  is in the instance's allowlist (`instance.MatchEndpoint`), **and** some grant
  for an effective group lists the endpoint id (`instance.Grant`).
- For a listed httpproxy tool, the `instance` argument is constrained to a JSON
  Schema `enum` of exactly the reachable instances, so the model cannot even
  name an instance it may not reach.

This reuses `Instance.Effective`, `Instance.MatchEndpoint`, and `Instance.Grant`
— the very functions the gateway calls — so visibility can never drift from
enforcement.

## Configuration

A new optional `mcp` config section:

```json
"mcp": { "enable": true, "listen": ":8081", "path": "/mcp" }
```

- `enable` — turn the MCP front-end on (default off; the HTTP gateway is
  unaffected when off).
- `listen` — listen address for the MCP server (default `:8081`).
- `path` — URL path the streamable HTTP handler is mounted at (default `/mcp`).

When enabled, `cmd/airlock` serves the MCP handler on a second `http.Server`
that participates in the same graceful-shutdown drain as the gateway server.

## Components

- `internal/mcpserver` — the protocol adapter: the streamable HTTP server, the
  per-connection authenticated/filtered MCP server, the tool catalog, and the
  re-dispatch into `gateway.Gateway.ServeHTTP`. This package contains **no**
  authorization or tenancy logic of its own.
- `internal/gateway` — gains small read-only accessors (`Config`, `Proxies`,
  and the `BearerToken` helper) so the adapter can introspect identity and
  instances for tool filtering. The pipeline itself is unchanged.
- `internal/backend/httpproxy` — gains `Instance.Type()` and
  `Manager.Instances()` read-only accessors used by tool filtering.

## Security notes

- The adapter never makes an allow/deny decision. Visibility filtering is
  fail-closed (default-deny: not listed unless explicitly granted) and is
  backed by the gateway's own enforcement on every call.
- A client cannot widen scope through MCP: the tool surface does not expose
  tenancy headers, mandatory-filter overrides, or result-limit widening, and the
  gateway strips/forces those regardless on the re-dispatched request.
- The MCP rate-limit bucket is the *same* per-client bucket as the HTTP path, so
  a client cannot multiply its budget by using both front-ends.

## Out of scope (future phases)

- The web login/authorization UI.
- Gateway Prometheus metrics.
- The Postgres tool.
