# airlock

Authenticating L7 gateway that safely exposes infrastructure (HTTP services, and
DB/Redis via curated read-only operations) to LLMs. A sealed, controlled passage
between the untrusted LLM side and the trusted infrastructure side: only
authorized operations pass, and the two sides never connect directly.

See `docs/design/2026-06-11-airlock.md`.
