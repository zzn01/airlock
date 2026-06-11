# airlock

Authenticating L7 gateway that safely exposes infrastructure to LLMs. A single
HTTP server is the sole entry point for the untrusted LLM side; the trusted side
is never reached directly.

## Build & test

- `make ci` — runs `go vet`, `go test`, and `go build` over the whole module.
  Keep it green at every commit. Module is pure stdlib (no external deps).

## Request pipeline (`internal/gateway`)

After authentication, requests split into two pipelines by path. The legacy
**op pipeline** (Redis, `/redis/*`) and the **proxy pipeline** (`httpproxy`
instances, `/b/<instance>/...`).

Authenticate first (both): `Authorization: Bearer <token>` or
`X-API-Key: <token>` maps to a configured client. Missing/invalid => `401`.

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
  `Gateway.Handler()`, and shuts down gracefully (drains in-flight requests
  within a bounded timeout) on SIGINT/SIGTERM.
- `internal/config` — JSON config model + loader. `AIRLOCK_CONFIG` selects the
  file (default `airlock.json`); `AIRLOCK_LISTEN` overrides the listen address.
  `Config.Validate` fails fast at startup on a malformed config (`config.go`);
  `resolve.go` resolves `env:`/`file:` secret references before validation.
- `internal/gateway` — the request pipeline (`Gateway`) and the composition root
  (`Build`) that wires config + backends into an `http.Handler`. `Handler()`
  (`health.go`) serves the unauthenticated `/healthz` (liveness) and `/readyz`
  (readiness) probes outside the auth pipeline, falling through to the gated
  pipeline for everything else.
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

JSON file; see `airlock.example.json`. Fields: `listen`, `groups[]` (named
groups), `clients[]` (`id`, `token`, `groups[]`, `allow[]` of operation ids for
Redis, `rate_limit{rps,burst}`), and `backends`:

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

Secret-bearing values (client `token`s, `upstream_auth` values) may be given as
`env:NAME` or `file:/path` references, resolved at load (plaintext still works).
See the README for the scheme.

## Design

`docs/design/2026-06-11-airlock.md` (MVP) and
`docs/design/2026-06-11-airlock-group-access.md` (groups, httpproxy backends,
strict per-instance routing, multi-tenant scoping).

## Scope

Implemented: gateway pipeline, read-only Redis tool, group-based access control,
multi-instance HTTP reverse-proxy backends (Prometheus/VictoriaLogs/Grafana
read-only presets) with per-`(group,backend)` grants and server-side data
scoping. Not yet: Postgres tool, web UI.
