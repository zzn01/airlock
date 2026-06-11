# airlock — group-based access, HTTP reverse-proxy backends, multi-tenant scoping

**Status:** Implemented
**Date:** 2026-06-11
**Extends:** `2026-06-11-airlock.md` (MVP)

## Problem

The MVP exposed a single read-only Redis tool behind an op-id allowlist attached
to each client. We now need to expose real HTTP infrastructure — read-only
observability services (Prometheus, VictoriaLogs, Grafana) — to LLM clients,
while keeping the same hard guarantees: no destructive operations, no open
egress, full accountability, and now **multi-tenant data isolation** so a client
can only ever see the slice of data it is entitled to.

Three new requirements drive this design:

1. **Many backend instances, including several of the same type.** A fleet has
   more than one VictoriaLogs cluster (`victorialogs-a`, `victorialogs-b`), each
   with its own URL, allowlist, tenancy, and audience. They must be addressable
   independently with no chance of one bleeding into another.
2. **Policy that scales with teams, not keys.** Access is granted to *groups*
   (e.g. `team-checkout`, `sre`), and clients (API keys) belong to groups.
   Re-keying a client or onboarding a new one must not require re-authoring
   policy.
3. **Server-side data scoping the client cannot widen.** It is not enough to
   allow an endpoint; the gateway must force tenancy and inject mandatory query
   filters so a crafted request cannot escape its slice.

## Access-control model

### Groups

Configuration defines a set of named **groups**. Each **client** (API key)
declares the groups it belongs to (`client.groups`). Policy attaches to groups,
never to individual clients — a client's reach is entirely a function of its
group membership.

### Per-backend `allowed_groups` (coarse gate)

Each backend instance declares `allowed_groups`. For a request, the gateway
computes the **effective groups**:

```
effective = client.groups ∩ backend.allowed_groups
```

If `effective` is empty the client cannot touch the backend at all — a flat
**403**, before any endpoint matching. This is the coarse, backend-level gate.

### `(group, backend)` grants (fine gate + data scope)

Each backend instance carries a list of **grants**, each keyed by a `group`. A
grant declares, for that group on that backend:

- `endpoints`: the set of allowlisted endpoint **ids** the group may call.
- `scope`: the server-side data scope to enforce (forced params/headers,
  stripped params/headers, and — for VictoriaLogs — tenancy + a mandatory
  LogsQL filter).

### Effective access

For an authenticated request to instance `B` from client `C`:

1. `effective = C.groups ∩ B.allowed_groups`; empty ⇒ **403** (coarse gate).
2. Match `(method, upstream-path)` against `B`'s endpoint allowlist; no match ⇒
   **403** (`endpoint_not_allowed`).
3. The request is authorized iff **some** grant whose `group ∈ effective` lists
   the matched endpoint id (union over the client's effective groups). No such
   grant ⇒ **403** (`not_granted`).
4. The data scope applied is that of the first matching grant in group order.

**Default-deny everywhere:** a new client, a new group with no grant, a new
endpoint not yet granted, or any gap is denied. There is no allow-all escape
hatch.

## HTTP reverse-proxy backends

A new backend type, `httpproxy`, supports **multiple named instances**, including
several of the same service type. Each instance owns, in its own config struct:
a `base_url`, an endpoint allowlist (from a read-only **preset** plus optional
`extra_endpoints`), upstream auth, response/result guardrails, tenancy config,
`allowed_groups`, and `grants`.

### Strict per-instance routing boundary

Each instance is addressed under a **unique path prefix**:

```
/b/<instance-name>/<upstream-path...>
```

Routing is purely by instance name:

- The first path segment after `/b/` selects **exactly one** instance.
- Unknown instance ⇒ **404** (`unknown_backend`).
- The remaining path is matched **only** against that instance's own allowlist.

There is **no shared/merged global path table**. `victorialogs-a` and
`victorialogs-b` can expose identical upstream paths with no collision, because
each path is interpreted solely within the addressed instance. A request to
`/b/victorialogs-a/...` can never reach `victorialogs-b`'s upstream, regardless
of what path follows. This is what "strict per-instance boundary" means: the
instance is chosen by name, then — and only then — its private allowlist
applies.

The legacy Redis tool keeps its own explicit `/redis/*` op routes and op-id
allowlist (`client.allow`); it is unchanged. The `/b/` prefix is the proxy
namespace and is dispatched separately.

### Read-only endpoint presets

Each preset is a curated, read-only allowlist. Anything not listed (including all
write/admin/delete paths) is unreachable by construction — default-deny, not a
blocklist.

- **prometheus** — `GET` only:
  `/api/v1/query`, `/api/v1/query_range`, `/api/v1/series`, `/api/v1/labels`,
  `/api/v1/label/*/values`, `/api/v1/metadata`, `/api/v1/targets`. Admin / TSDB
  endpoints (`/api/v1/admin/tsdb/*`, delete_series) are simply absent.
- **victorialogs** — query/select endpoints only:
  `/select/logsql/query`, `/select/logsql/hits`, `/select/logsql/field_names`,
  `/select/logsql/field_values`. `/delete/*` and any write/admin path are absent.
- **grafana** —
  `GET /api/search`, `GET /api/dashboards/*`, `POST /api/ds/query`. Dashboard /
  datasource create/update/delete are absent, and `/api/datasources` (which can
  expose datasource secrets) is **not** allowlisted.

Path patterns use `*` to match a single path segment; a trailing `*` matches one
or more remaining segments (e.g. `/api/dashboards/*`).

## Multi-tenant data scoping (server-side, non-widenable)

All scoping is applied by the gateway when it constructs the upstream request.
The client can supply inputs, but cannot override or widen what the gateway
forces, because the gateway **strips** any client-supplied value that could widen
scope **before** injecting the grant's value.

### Generic mechanism (any preset)

A grant's `scope` may declare:

- `strip_query_params` / `strip_headers`: removed from the client request first.
- `forced_query_params`: set after stripping, overriding any client value.
- `forced_headers`: set after stripping, overriding any client value.

The client's gateway credential (`Authorization` / `X-API-Key`) is never
forwarded upstream.

### VictoriaLogs tenancy + mandatory filter

VictoriaLogs multitenancy is keyed by the `AccountID` and `ProjectID` HTTP
headers. For a VictoriaLogs grant the gateway:

1. **Strips** any client-supplied `AccountID` / `ProjectID` headers and **sets**
   them from the grant. The client cannot pin itself to another tenant.
2. **AND-injects** the grant's mandatory LogsQL filter into the client's query.
   The client's query `Q` becomes:

   ```
   (<mandatory_filter>) AND (<Q>)
   ```

   Both sides are parenthesized, so the mandatory filter is always evaluated and
   the client's expression cannot break out of its parentheses to disjoin
   (`OR`) away the constraint. If `Q` is empty the query is just
   `(<mandatory_filter>)`.

**Why a client cannot escape it.** Tenancy is decided by headers the gateway
controls and the client's own headers are discarded before injection, so there
is no header the client can send to change tenant. The query filter is composed
by string-combining a parenthesized mandatory term with a parenthesized client
term under `AND`; there is no code path that emits the client's query without the
mandatory term, and the parentheses prevent operator-precedence escapes. The
narrowest the client can make its view is its own slice; it can never widen
beyond `mandatory_filter` for its forced tenant.

### Upstream auth injection

Each instance may hold upstream credentials (`upstream_auth`: a map of header →
value) that the gateway injects on every upstream request — e.g. a Grafana
read-only service-account token. Prometheus/VictoriaLogs are assumed authless
unless configured. Upstream credentials live only in the gateway; they are never
exposed to or settable by the client.

### LLM guardrails

- **Response size cap** (`max_response_bytes`): the upstream response body is
  truncated to the cap before being returned, with `X-Airlock-Truncated: true`
  set when truncation occurs. This bounds tokens fed back to the model.
- **Result-count clamp** (`max_result_limit` + `result_limit_param`): the named
  result-count parameter is clamped to the cap (and set to the cap when the
  client omits it or asks for more). Applies to Prometheus/VictoriaLogs result
  sizes.
- **Time range**: bounded via `forced_query_params` (e.g. pinning `start`) — the
  same non-widenable forced-param mechanism, no separate code path.

## Pipeline

```
request
  │
  ▼
[1] authenticate ── Bearer / API key ─► unknown => 401
  │
  ├─ path starts with /b/<name>/ ──────────────► proxy dispatch
  │      [2p] resolve instance by name           unknown instance => 404
  │      [3p] coarse gate: groups ∩ allowed       empty            => 403
  │      [4p] match endpoint in instance allowlist no match        => 403
  │      [5p] grant for effective group lists ep?  no              => 403
  │      [6p] rate limit (per client)              over            => 429
  │      [7p] scope + proxy upstream (strip→force→inject→cap)
  │      [8p] audit
  │
  └─ else ─────────────────────────────────────► legacy registry (redis)
         [2] route op ─► 404   [3] allowlist ─► 403   [4] limit ─► 429
         [5] execute            [6] audit
```

## Configuration

`backends` becomes a struct with an optional `redis` object and an optional
`httpproxy` array. Top-level `groups` lists the named groups; each client gets a
`groups` array. See `airlock.example.json` for two VictoriaLogs instances and two
clients in different groups with different data scopes.

```jsonc
{
  "groups": ["team-checkout", "team-payments", "sre"],
  "clients": [
    { "id": "...", "token": "...", "groups": ["team-checkout"], "rate_limit": {...} }
  ],
  "backends": {
    "redis": { "addr": "..." },
    "httpproxy": [
      {
        "name": "victorialogs-a",
        "type": "victorialogs",
        "base_url": "http://vl-a:9428",
        "allowed_groups": ["team-checkout"],
        "max_response_bytes": 1048576,
        "max_result_limit": 1000,
        "result_limit_param": "limit",
        "grants": [
          {
            "group": "team-checkout",
            "endpoints": ["vl.query"],
            "scope": {
              "victorialogs": {
                "account_id": "1",
                "project_id": "10",
                "mandatory_filter": "app:\"checkout\""
              }
            }
          }
        ]
      }
    ]
  }
}
```

## Out of scope

Unchanged from the MVP: Postgres tool; web UI; multi-tenancy beyond the
group/tenancy model described here. Redis behavior is unchanged.
