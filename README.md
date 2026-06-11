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
