# Airlock OIDC/SSO web login & claim→group mapping

Status: implemented (Phase 2, second slice — 2b)
Date: 2026-06-12

## Motivation

The first web-login slice (`2026-06-11-airlock-web-auth.md`) lets a human log in
with a **local account** and receive a short-lived bearer token bound to that
user's groups, resolving through the same access-control core as a static config
client. Local accounts are self-contained but still require airlock to store
credentials and an operator to provision every user.

This slice adds **OIDC/SSO login** as a *second identity source next to local
accounts*. A user authenticates against an external identity provider
(Keycloak, Okta, Entra ID, Google, …) via the standard OAuth2
**authorization-code flow**; airlock derives the user's airlock groups from a
configurable ID-token claim and issues **the same** opaque session token local
login issues. From the gateway's and MCP server's point of view nothing changes:
a token still resolves to a `config.Client{ID, Groups}` through the existing
`TokenResolver` seam.

It adds an alternative way to *obtain* a token and a way to *derive groups from
external identity*; it does **not** add or reinterpret any authorization or
tenancy policy. OIDC being disabled or misconfigured never breaks local login.

Explicitly out of scope for this slice (deferred to 2c): an admin console for
CRUD of users / groups / grants. Only the per-user OIDC group **override**
storage (read from config) is included here, not a management UI.

## Design overview

```
browser --(GET /oidc/login)--> web front-end (:8082)
              | (1) generate state + nonce, set short-lived HttpOnly cookies
              | (2) 303 redirect to the IdP authorization endpoint (state, nonce)
              v
          identity provider  --(user authenticates)-->
              |
              v
browser --(GET /oidc/callback?code&state)--> web front-end
              | (3) verify state cookie == query state (CSRF)
              | (4) exchange code -> ID token; verify signature, audience, nonce
              | (5) read the configured groups claim from the ID token
              | (6) derive airlock groups: admin override (by sub/email) wins,
              |     else claim values mapped through config rules
              | (7) issue the SAME opaque session token local login issues
              v
LLM/MCP client --(Bearer <token>)--> gateway (:8080) / MCP (:8081)
              |
              v
          EXISTING pipeline, unchanged: groups -> allowed_groups ->
          grants -> data scope -> rate limit -> audit
```

The OIDC flow runs on the same web front-end (`:8082`) as local login. The
login page shows the local username/password form and, when OIDC is enabled, a
"Log in with OIDC" link. Both paths converge on `SessionStore.Issue`, so there
is exactly one token model, one resolver seam, and one audit stream.

## Identity-source layering

OIDC is *additive* and lives **inside** the existing `web` config section as a
nested `oidc` object. The relationship is deliberately asymmetric:

- `web.enable` turns on the front-end and local login.
- `web.oidc.enable` turns on the OIDC option *within* that front-end.
- Local login always works when the front-end is on. OIDC is the optional extra.
- If the OIDC provider cannot be reached at startup (bad issuer, network), the
  front-end logs a warning and serves **local login only** — startup does not
  fail and local login is unaffected. "Misconfigured OIDC" degrades to "no OIDC
  button", never to "no login".

This keeps the failure surface of an external dependency from taking down the
self-contained local path.

## Claim → group mapping

The ID token carries the user's identity at the IdP. airlock must translate that
into *airlock* group names, because airlock's entire authorization model is
group-driven and those group names are airlock's, not the IdP's.

Two layers, override-first:

1. **Admin manual override** (`web.oidc.overrides[]`). A list of
   `{subject?, email?, groups[]}`. If an override matches the authenticated
   user by OIDC `sub` **or** `email`, its `groups` are used verbatim and the
   claim mapping is skipped. This is the operator's escape hatch — pin a
   specific person to specific groups regardless of what the IdP asserts (e.g.
   grant `sre` to an on-call engineer the IdP doesn't tag, or strip groups from
   a departing user faster than the directory propagates).
2. **Claim mapping** (`web.oidc.groups_claim` + `web.oidc.group_mapping`). Read
   the named claim (default `groups`) from the ID token — a string or array of
   strings — and map each value through `group_mapping` (IdP value → list of
   airlock groups). The union (de-duplicated, order-preserving) is the user's
   airlock groups. A claim value with no mapping entry contributes nothing
   (default-deny: unmapped IdP groups grant no airlock access).

`DeriveGroups(claims, oidc)` is a pure function — the unit of the mapping/
override tests. Group names produced by mapping and overrides are validated at
config load to reference defined `groups`, exactly like static-client groups, so
a typo fails fast rather than silently granting nothing.

The derived groups are handed to `SessionStore.Issue` as an ordinary
`webauth.User{Username: sub, Groups: derived}`; from there the token is
indistinguishable from a local-login or static-config token.

## CSRF: state and nonce

The authorization-code flow uses the two standard, independent protections:

- **`state`** defends the *redirect back to airlock*. A random value is set in a
  short-lived `HttpOnly` cookie and echoed in the authorization URL; the
  callback rejects (`400`) any request whose `state` query parameter does not
  constant-time-match the cookie. This stops a forged/cross-site callback.
- **`nonce`** binds the *ID token* to this login. A random value is set in a
  cookie and embedded in the authorization request; after verifying the ID
  token's signature and audience, the callback requires the token's `nonce`
  claim to constant-time-match the cookie, defeating token replay.

Both cookies are `HttpOnly`, `SameSite=Lax` (so the top-level GET redirect from
the IdP still carries them), `Secure` under TLS, and short-lived; they are
cleared once consumed.

## Components (`internal/webauth`)

`internal/webauth` keeps holding **no authorization logic** and does **not**
import `internal/gateway`:

- `Claims{Subject, Email, Groups}` — the identity fields read from a verified ID
  token.
- `Authenticator` interface — `AuthCodeURL(state, nonce)` and
  `Verify(ctx, code, nonce) (Claims, error)`. This is the seam that isolates the
  network/crypto from the HTTP flow, so the handlers are tested with a fake and
  **no live IdP**.
- `OIDCProvider` — the real `Authenticator`, built on
  `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`: OIDC discovery against
  the issuer, code exchange, ID-token signature/audience verification, nonce
  check, and configured-claim extraction.
- `DeriveGroups(Claims, *config.OIDC)` — the pure override-first mapping above.
- OIDC HTTP handlers on the existing `Server`: `GET /oidc/login` and
  `GET /oidc/callback`, registered only when an `Authenticator` is wired in.

`cmd/airlock` constructs the `OIDCProvider` (best-effort; logs and continues on
failure) and wires it into the `Server`; the issued token resolves through the
same `SessionStore`/`TokenResolver` seam as slice 1.

## Configuration

```jsonc
"web": {
  "enable": true,
  "listen": ":8082",
  "users_file": "/var/lib/airlock/users.json",
  "token_ttl": "12h",
  "oidc": {
    "enable": true,
    "issuer": "https://idp.example.com/realms/airlock",
    "client_id": "airlock",
    "client_secret": "env:AIRLOCK_OIDC_CLIENT_SECRET",   // secret reference
    "redirect_url": "https://airlock.example.com:8082/oidc/callback",
    "scopes": ["openid", "profile", "email", "groups"],  // default openid+profile+email
    "groups_claim": "groups",                            // default "groups"
    "group_mapping": {                                   // IdP value -> airlock groups
      "platform-oncall": ["sre"],
      "checkout-devs":   ["team-checkout"]
    },
    "overrides": [                                        // optional, override-first
      { "email": "lead@example.com", "groups": ["sre", "team-payments"] }
    ]
  }
}
```

`Config.Validate` fails fast when OIDC is enabled without `issuer`, `client_id`,
`client_secret`, or `redirect_url`, and when any `group_mapping` target or
`overrides[].groups` entry references an undefined group. `client_secret` is a
secret reference (`env:`/`file:`/plain) resolved by the same loader that handles
client tokens, upstream auth, and the bootstrap password.

## Testing

Deterministic, no network and no real provider — the `Authenticator` seam is
faked and ID-token claims are injected:

- **mapping** — `DeriveGroups` unions mapped claim values, de-duplicates,
  preserves order, and drops unmapped values;
- **override precedence** — an override matching by `sub` or `email` wins over
  the claim-derived groups;
- **gateway integration** — running the full OIDC callback flow with a fake
  authenticator mints a token that, used against the real proxy pipeline,
  reaches a backend gated to the derived group, while a user mapped to a foreign
  group is denied at the coarse gate (proving the derived groups drive
  authorization);
- **local unaffected** — with OIDC disabled (or its provider absent) the login
  page renders without the OIDC option, local login still issues a working
  token, and `/oidc/*` is not served;
- **CSRF** — a callback whose `state` does not match the cookie is rejected and
  issues no token; the `nonce` set at `/oidc/login` is the one checked at the
  callback, and a verification failure issues no token.
```
