**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# Auth Workspace

A hexagonal authentication/authorization service in Rust: users, roles (global
and scoped), permissions, sessions with refresh-token rotation, an audit log and
runtime settings (e.g. enabling self-registration) without a redeploy.

It is a library first: embed it into any Rust + Axum service, implement the ports
for your own storage, or just run the ready-made HTTP server.

## Three ways to use it

| Way | What you take | When |
|---|---|---|
| **Library, own storage** | `auth-core` + your implementation of its ports | you already have a database layer and want only the rules |
| **Library, ready storage** | `auth-core` + `auth-postgres` + `auth-crypto` | embed auth into your Rust service, no HTTP in between |
| **Server** | `auth-server` (Docker image) | any language; talk to it over HTTP, verify JWTs by JWKS |

## Architecture

```
                     ┌─────────────┐
                     │  auth-core  │  domain, ports (traits), use cases
                     └──────┬──────┘  no sqlx, axum or argon2 — domain only
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐  ┌────────▼───────┐  ┌────────▼───────┐
│ auth-postgres │  │  auth-crypto   │  │ auth-telemetry │
│  (DB adapter) │  │ Argon2/JWT/RT  │  │ tracing→Jaeger │
└───────┬───────┘  └────────┬───────┘  └────────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                     ┌──────▼──────┐
                     │  auth-api   │  axum router over core (DTOs, HTTP errors)
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ auth-server │  composition root: config → wiring → run
                     └─────────────┘
```

Dependencies point inwards only; `auth-postgres`, `auth-crypto` and
`auth-telemetry` know nothing about each other. Any adapter can be replaced
without touching the rest — e.g. SQLite instead of Postgres, by implementing the
same ports (`crates/auth-core/src/ports.rs`).

## Crates

| Crate | What it does | README |
|---|---|---|
| `auth-core` | Domain, ports, use cases (`AuthService`, `UserService`, `RoleService`, `AccessService`, `SettingsService`, `AuditService`, `SetupService`) | [crates/auth-core](crates/auth-core/README.md) |
| `auth-postgres` | Ports on sqlx/Postgres, transactions, migrations | [crates/auth-postgres](crates/auth-postgres/README.md) |
| `auth-crypto` | Argon2id, JWT (EdDSA/Ed25519) + JWKS, refresh tokens | [crates/auth-crypto](crates/auth-crypto/README.md) |
| `auth-telemetry` | tracing → OTLP/HTTP → Jaeger | [crates/auth-telemetry](crates/auth-telemetry/README.md) |
| `auth-api` | axum router over core, DTOs, HTTP error codes, rate limit, CORS, a light JWT extractor for other services | [crates/auth-api](crates/auth-api/README.md) |
| `auth-server` | Wires everything, runs HTTP, CLI (`jwt-keygen`) | [crates/auth-server](crates/auth-server/README.md) |

`apps/admin-ui` is an admin front end on Leptos (CSR). It is not part of the
workspace, is built separately with `trunk` and is still a stub.

## Quick start (Docker)

Only Docker is needed — no Rust or C++ build tools on the machine.

```powershell
copy .env.example .env

# generate a JWT signing key and put the output into .env
docker compose --profile dev run --rm auth-dev cargo run -p auth-server -- jwt-keygen

# put AUTH__SETUP__TOKEN (at least 32 characters) into .env, e.g. the output of:
#   openssl rand -base64 32

# Postgres + Jaeger + the server, rebuilt on every save
docker compose --profile dev up
```

Server: `http://localhost:8080`, Jaeger UI: `http://localhost:16686`.

### First administrator

Created once over the API, no CLI needed:

```powershell
Invoke-RestMethod http://localhost:8080/setup        # {"required": true}

Invoke-RestMethod -Method Post -Uri http://localhost:8080/setup -ContentType "application/json" `
  -Body (@{ setup_token = "<AUTH__SETUP__TOKEN>"; email = "admin@example.com"; password = "super-secret-1";
            first_name = "Admin"; second_name = "Root" } | ConvertTo-Json)    # 201
```

After that `/setup` is closed for good (a flag in the DB): repeated and parallel
requests get `404`, `GET /setup` returns `{"required": false}`. Without
`AUTH__SETUP__TOKEN` the endpoint is off. The variable can be removed afterwards.

| Command | What it starts |
|---|---|
| `docker compose up -d` | only Postgres (port 2134) and Jaeger |
| `docker compose --profile dev up` | + `auth-dev`: sources mounted from the host, `cargo watch` rebuilds and restarts on save |
| `docker compose --profile prod up -d --build` | + `auth`: the production image (`Dockerfile`, target `runtime`) |

The production image caches dependencies in a separate layer (`cargo-chef`):
editing your own code rebuilds only the workspace crates. Migrations are
embedded into the binary and applied on start.

## Running without Docker

Requires Rust 1.98.1+ and (on Windows) Visual Studio C++ build tools.

```powershell
docker compose up -d                                   # Postgres + Jaeger
copy .env.example .env                                 # fill in the JWT key and AUTH__SETUP__TOKEN
cargo run -p auth-server -- jwt-keygen                 # output goes into .env
cargo run -p auth-server                               # listens on 127.0.0.1:8080
```

The first administrator is created with `POST /setup`, as above.

## Configuration

`config/default.toml` → `config/{AUTH_ENV}.toml` (`AUTH_ENV=dev` by default,
`prod` in the production image) → environment variables `AUTH__SECTION__KEY`.
Secrets go only through the environment (`.env`), never into config files:

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<base64url Ed25519 seed, from jwt-keygen>
AUTH__CRYPTO__JWT__KID=<key id, e.g. a date>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
AUTH__SETUP__TOKEN=<only for the initial setup>
```

Every section is described in [crates/auth-server](crates/auth-server/README.md).

## Example requests

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body (@{ email = "admin@example.com"; password = "super-secret-1" } | ConvertTo-Json)).access_token
$auth = @{ Authorization = "Bearer $token" }

Invoke-RestMethod -Uri http://localhost:8080/users -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/auth/me/permissions?scope=space:wiki" -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/audit?action=role.assign" -Headers $auth
```

The full route list is in [crates/auth-api](crates/auth-api/README.md).

## Permission model

- **Global role** (`RoleScope::Global`) — its permissions apply everywhere.
- **Scoped role** (`RoleScope::Scoped`) — its permissions apply only inside a
  specific `scope` (an opaque string such as `space:wiki` or `project:42`; what
  it means is up to the consuming service, auth does not care).
- Effective permissions in a scope are **global ones plus those assigned in that
  exact scope**. The matching rule (`RoleScope::check_assignment`) lives in the
  domain, not in the handlers.
- **Scope administrators**: `roles.assign` granted inside `space:wiki` lets a user
  hand out roles only in `space:wiki` — not in other scopes and not global ones.
- A logged-in user needs no permission to see their own permissions:
  `GET /auth/me/permissions?scope=...`. A client (e.g. a wiki) uses it to decide
  which buttons to show.

### Your own permissions

Consuming services register their permissions with a migration in the auth
database:

```sql
select register_permission('wiki.article.delete', 'Delete any article');
```

The function validates the code and is idempotent. The new permission is granted
to `admin` automatically by a trigger; to anyone else — through a role.

### Escalation protection

- **You cannot grant more than you have.** Assigning, removing, editing or
  deleting a role requires holding all of its permissions; setting a role's
  permissions requires holding both the old and the new ones.
- **You cannot manage a stronger user.** Changing a password, deactivating,
  editing or deleting is allowed only for users whose global permissions are a
  subset of yours.
- **`admin` is a system role**: it always has all permissions (new ones too, via
  a trigger); it cannot be deleted, its code cannot be changed and its permission
  set cannot be edited.
- **The last administrator is untouchable**: their role cannot be removed, they
  cannot be deactivated or deleted — checked inside a transaction under a shared
  lock, so parallel requests cannot leave the system without an admin either.

## Transactions

Every use case is one transaction (`UnitOfWork::begin` → repository calls →
`commit`). An error anywhere means no `commit`, and the transaction rolls back on
drop. Checks that must stay true until commit (the role's permissions, "this is
not admin") run under a row lock (`RoleRepository::lock`), so concurrent edits of
the same role are serialized.

## Audit log

Every change of access is written to `audit_events` **in the same transaction**
as the change: no change — no record; the record failed — the change is rolled
back. The table is append-only (`UPDATE`, `DELETE` and `TRUNCATE` are blocked by
a trigger).

- Admin actions: roles (create, update, delete, permissions, assign/unassign with
  scope), users (create, update, password, activate/deactivate, delete), settings,
  initial setup.
- The user's own actions: registration, login, logout, logout everywhere, own
  password change, reuse of a revoked refresh token (`actor` is empty — it is
  the system's reaction).
- Not recorded: failed logins (rate limit and WARN logs cover them), plain token
  refresh, rejected requests.
- Details are flat strings chosen by the service — passwords, hashes and tokens
  never get there.

Read it with `GET /audit?actor_id=&action=&target_type=&target_id=&page=&per_page=`
(permission `audit.view`), newest first.

## Runtime settings

Part of the behaviour (currently `allow_self_registration`) lives in the DB, not
in the config, and is changed with `GET/PUT /settings` (permission
`settings.manage`) without a redeploy or restart.

## For other services

- **Full integration**: use `auth-core` + `auth-postgres` + `auth-crypto` as
  libraries right inside your Rust service (no HTTP at all).
- **Light token check without the DB**: `auth_api::extract::{JwtVerifier,
  RemoteAuthCtx}` + `auth_crypto::Ed25519Verifier` — verifies the JWT signature
  and expiry against public keys from `GET /.well-known/jwks.json`, no private key
  needed. Instant session revocation is not seen this way — a token lives until
  its `exp` (15 minutes by default).
- **Over HTTP**: plain requests to `auth-server` with `Authorization: Bearer`;
  permissions for the UI come from `GET /auth/me/permissions?scope=...`.

## Development

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # auth-postgres integration tests need Docker
```

The same runs in CI (`.github/workflows/ci.yml`) on every push to `main` and on
PRs, plus `cargo audit` and a production image build.

Without a local Rust toolchain the tests run in Docker (Git Bash):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src:ro" -v //var/run/docker.sock:/var/run/docker.sock -e CARGO_TARGET_DIR=/tmp/target -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway -w /src rust:1.98-slim-bookworm cargo test --workspace
```

## Status

Version 0.2.0, pre-1.0: the API of the crates may still change between minor
versions; every breaking change is listed in [CHANGELOG.md](CHANGELOG.md). Unit
tests on in-memory fakes and integration tests on a real Postgres
(`testcontainers`) cover the core and the storage; the HTTP layer has no tests
of its own yet. `apps/admin-ui` is a stub.

Not done yet: email verification and password reset, per-account lockout after
failed logins, a list of own sessions, an OpenAPI description, audit retention.

## License

Dual-licensed: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
