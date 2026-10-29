**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-server

The composition root and the only binary in the workspace. Reads the config,
builds the adapters (`auth-postgres`, `auth-crypto`) behind the `auth-core`
ports, starts `auth-api` on axum and serves JWKS and health checks.

## Config

`config/default.toml` (+ `config/{AUTH_ENV}.toml`, `AUTH_ENV=dev` by default) +
environment variables `AUTH__SECTION__KEY` (a double underscore is the
separator). `.env` in the repository root is loaded with `dotenvy`; the template
is `.env.example`.

Required secrets (environment only, never in a file):

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<base64url 32-byte Ed25519 seed>
AUTH__CRYPTO__JWT__KID=<key id>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
AUTH__SETUP__TOKEN=<at least 32 characters, only for the initial setup>
```

Other sections (`config/default.toml`):

| Section | Keys | Notes |
|---|---|---|
| `server` | `bind` | `0.0.0.0:8080` in Docker |
| `api` | `request_timeout_secs`, `allowed_origins` | an empty `allowed_origins` forbids cross-origin browser requests; only `http(s)://host[:port]` is allowed, an invalid origin stops the server from starting |
| `api.rate_limit` | `per_second`, `burst_size`, `trusted_proxies` | limit on `/auth/login`, `/auth/register`, `/auth/me/password` and `/setup` by connection IP; `X-Forwarded-For` counts only from proxies in `trusted_proxies` |
| `auth` | `access_ttl_secs`, `refresh_ttl_secs` | 15 minutes / 30 days |
| `crypto.argon2` | `m_cost_kib`, `t_cost`, `p_cost`, `max_concurrent` | defaults are the OWASP minimum; `max_concurrent` (number of cores by default) limits simultaneous hashes, peak memory ≈ `max_concurrent × m_cost_kib` |
| `setup` | `token` | only via `AUTH__SETUP__TOKEN`; unset — `/setup` is off; shorter than 32 characters — the server does not start |
| `crypto.jwt` | `extra_verification_keys` | old public keys during key rotation |
| `postgres` | `max_connections`, `min_connections`, `acquire_timeout_secs` | |
| `maintenance` | `session_cleanup_interval_secs`, `session_retention_secs` | background cleanup of dead sessions |
| `telemetry` | `enabled`, `service_name`, `otlp_endpoint`, `sample_ratio`, `log_level` | |

## CLI

```powershell
cargo run -p auth-server                                    # run the server
cargo run -p auth-server -- jwt-keygen
```

`jwt-keygen` prints a new Ed25519 key (`SIGNING_KEY`) and its public part. It
needs neither the config nor the DB. On rotation the old public key goes into
`crypto.jwt.extra_verification_keys` under the old `kid`, so tokens already
issued live out their TTL.

## Initial setup

The first administrator is created by `POST /setup` (the secret from
`AUTH__SETUP__TOKEN`) exactly once: in one transaction it creates the `admin`
role with all permissions, the user and the assignment, sets the
`app_settings.setup_completed_at` flag and writes `setup.complete` to the audit
log. Parallel requests are serialized by a lock on the settings row — exactly one
passes. Databases that already had an admin are marked as set up by the `setup`
migration. More in the root README.

## Service endpoints

- `GET /.well-known/jwks.json` — public keys for JWT verification, no auth.
- `GET /health/live` — the process is alive (no DB calls).
- `GET /health/ready` — Postgres is reachable, otherwise `503`.

## Lifecycle

- Migrations are applied on start.
- A background worker deletes expired and revoked sessions older than
  `session_retention_secs` — right on start and then every
  `session_cleanup_interval_secs`. A failed run is logged as an error; the worker
  keeps going.
- Ctrl+C and SIGTERM (`docker stop`, Kubernetes) — graceful shutdown: the server
  finishes current requests, the cleanup worker stops.

## Docker

`Dockerfile` in the repository root, two targets:

- `dev` — `cargo watch` over mounted sources, rebuilt on save;
- `runtime` — the production image on `debian:bookworm-slim`, an unprivileged
  user, `AUTH_ENV=prod`.

Run it through `docker-compose.yml` (profiles `dev` / `prod`), see the root README.
