# airlock

Authenticating L7 gateway that safely exposes infrastructure to LLMs. A single
HTTP server is the sole entry point for the untrusted LLM side; the trusted side
is never reached directly.

## Build & test

- `make ci` — runs `go vet`, `go test`, and `go build` over the whole module.
  Keep it green at every commit. Module is pure stdlib (no external deps).

## Request pipeline (`internal/gateway`)

Every request flows through, in order:

1. **Authenticate** — `Authorization: Bearer <token>` or `X-API-Key: <token>`
   maps to a configured client. Missing/invalid => `401`.
2. **Route** — `(method, path)` resolves to a registered operation. No match =>
   `404`. There is no wildcard forwarding.
3. **Authorize** — default-deny: the client's explicit allowlist must contain
   the operation id, else `403`.
4. **Rate limit** — per-client token bucket; over limit => `429`.
5. **Execute** — the operation handler runs.
6. **Audit** — one structured `log/slog` record per request (allow=INFO,
   deny=WARN) with client id, operation, decision, reason, and status.

## Packages

- `cmd/airlock` — entry point; loads config and serves the gateway.
- `internal/config` — JSON config model + loader. `AIRLOCK_CONFIG` selects the
  file (default `airlock.json`); `AIRLOCK_LISTEN` overrides the listen address.
- `internal/gateway` — the request pipeline (`Gateway`) and the composition root
  (`Build`) that wires config + backends into an `http.Handler`.
- `internal/backend` — the `Operation`/`Backend` model and a route `Registry`.
- `internal/backend/redisro` — read-only Redis tool. `ReadClient` is the only
  seam to Redis and exposes GET/SCAN/EXISTS/TTL only; `resp.go` is a minimal
  pure-stdlib RESP client that emits read commands exclusively. A
  reflection-based test guards that no write method can appear on the surface.
- `internal/ratelimit` — per-client token-bucket limiter with an injectable
  clock (deterministic under test).
- `internal/audit` — structured slog audit event + emitter.

## Configuration

JSON file; see `airlock.example.json`. Fields: `listen`, `clients[]`
(`id`, `token`, `allow[]` of operation ids, `rate_limit{rps,burst}`), and
`backends.redis.addr`.

## Design

`docs/design/2026-06-11-airlock.md`.

## Scope (MVP)

Implemented: gateway pipeline, read-only Redis tool. Not yet: Postgres tool,
real HTTP reverse-proxy upstreams (registry seam only), multi-tenancy, web UI.
