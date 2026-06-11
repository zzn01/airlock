# airlock

Authenticating L7 gateway that safely exposes infrastructure (HTTP services, and
DB/Redis via curated read-only operations) to LLMs. A sealed, controlled passage
between the untrusted LLM side and the trusted infrastructure side: only
authorized operations pass, and the two sides never connect directly.

See `docs/design/2026-06-11-airlock.md`.

## Configuration

airlock reads a JSON config (see `airlock.example.json`). The path is set by
`AIRLOCK_CONFIG` (default `./airlock.json`); `AIRLOCK_LISTEN` overrides the
listen address. The config is validated at startup and the process **fails
fast** with an actionable error on a malformed config (unknown backend type,
duplicate instance names, missing `base_url`, references to undefined groups,
empty/duplicate client tokens).

### Secret references

Any secret-bearing value — client `token`s and `upstream_auth` header values —
may be given indirectly so plaintext credentials need not live in the config
file or version control:

| Form          | Resolves to                                            |
| ------------- | ------------------------------------------------------ |
| `env:NAME`    | the value of environment variable `NAME` (must be set) |
| `file:/path`  | the contents of `/path` (trailing whitespace trimmed)  |
| anything else | the value verbatim (plaintext, backward-compatible)    |

References are resolved at config load; an unset env var or unreadable file
fails startup. For example, `airlock.example.json` sources the Grafana upstream
token via `"Authorization": "env:GRAFANA_TOKEN"`.

## MCP front-end

airlock can additionally expose the curated operations as **MCP (Model Context
Protocol) tools** for MCP-native AI clients, served over a streamable-HTTP
transport alongside the HTTP gateway. Enable it with an `mcp` config section:

```json
"mcp": { "enable": true, "listen": ":8081", "path": "/mcp" }
```

- `enable` — turn the MCP front-end on (default off).
- `listen` — its own listen address (default `:8081`).
- `path` — the streamable-HTTP mount path (default `/mcp`).

The MCP front-end is a protocol adapter only — it reuses the **same** security
core as the HTTP gateway:

- **Auth** — the MCP client presents `Authorization: Bearer <token>` on the
  transport; it is resolved to a client with the same mechanism the gateway
  uses. A missing/invalid token is a `401` (auth error) and exposes no tools.
- **Tool filtering** — the tool list is filtered to what the client's groups are
  actually granted (default-deny), and each httpproxy tool's `instance` argument
  is constrained to the instances the client may reach, so the model only sees
  tools it may call.
- **Enforcement** — every tool call is re-dispatched through the gateway
  pipeline, so the coarse group gate, endpoint allowlist, `(group, backend)`
  grant check, per-client rate limit, server-side data scoping (VictoriaLogs
  tenancy + mandatory LogsQL filter, forced/stripped params & headers), and the
  structured audit record all apply exactly as on the HTTP path.

Tools include `redis_get`/`redis_scan`/`redis_exists`/`redis_ttl`,
`prometheus_query`/`prometheus_query_range`, `victorialogs_query`,
`grafana_search`, and `grafana_ds_query`. See
`docs/design/2026-06-11-airlock-mcp-server.md`.

## Deployment

A multi-stage `Dockerfile` builds a static binary onto a minimal non-root
distroless image:

```sh
docker build -t airlock .
docker run --rm -p 8080:8080 \
  -v "$PWD/airlock.json:/etc/airlock/airlock.json:ro" \
  -e GRAFANA_TOKEN="Bearer <grafana-readonly-service-account-token>" \
  airlock
```

Mount the config read-only and pass secrets as environment variables (or mount
them as files and reference with `file:`); keep plaintext credentials out of the
image and the config file.

### Health endpoints

Two **unauthenticated** probes are served outside the auth pipeline and backend
routing:

- `GET /healthz` — liveness: `200` whenever the process is up.
- `GET /readyz` — readiness: `200` once config is loaded and the server is
  ready; `503` while draining during graceful shutdown.

On `SIGINT`/`SIGTERM` the server stops accepting new connections, fails
`/readyz`, and drains in-flight requests within a bounded timeout before
exiting.
