**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-api

An axum router over `auth-core`. No sqlx, argon2 or jwt here — only the core
use cases and the HTTP layer around them.

## Routes

```
POST   /auth/register        (if enabled in /settings)
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
POST   /auth/logout-all
GET    /auth/me
GET    /auth/me/permissions?scope=...     own permissions: global, plus the scope's
POST   /auth/me/password
GET    /users            POST /users
GET    /users/{id}       PUT /users/{id}       DELETE /users/{id}
POST   /users/{id}/password
PATCH  /users/{id}/active
GET    /roles            POST /roles
GET    /roles/{id}       PUT /roles/{id}       DELETE /roles/{id}
GET    /roles/{id}/permissions     PUT /roles/{id}/permissions
POST   /roles/{user}/{role}?scope=...    DELETE /roles/{user}/{role}?scope=...
GET    /permissions
GET    /settings          PUT /settings
GET    /audit?actor_id=&action=&target_type=&target_id=&page=&per_page=
GET    /setup             POST /setup      (initial setup, once)
```

`/.well-known/jwks.json` and `/health/*` are served by `auth-server`.

Every admin route checks its permission inside the core use case
(`users.*`, `roles.*`, `permissions.view`, `settings.manage`, `audit.view`), so a
forgotten check in a handler cannot open access.

## Errors

`AuthError` → HTTP: `Validation` → 400, `InvalidCredentials` / `Unauthorized` →
401, `Forbidden` / `AccountDisabled` → 403, `NotFound` → 404, `Conflict` → 409,
`Internal` → 500 (details go to the log, not to the client).

## Protection

- **Rate limit** (`api.rate_limit`) — on `/auth/login`, `/auth/register`,
  `/auth/me/password` and `/setup` (one quota per IP). The key is the connection
  IP (`ConnectInfo`, so the server runs with
  `into_make_service_with_connect_info`). `X-Forwarded-For` is accepted only from
  proxies listed in `trusted_proxies`: the chain is read right to left, the first
  untrusted address is the client.
- **CORS** (`api.allowed_origins`) — an empty list forbids cross-origin browser
  requests. Only `http(s)://host[:port]` values are allowed; an invalid origin is
  a configuration error: `router()` returns `Err` and the server does not start.

## Extractors

- `AuthCtx` — a full check through `ApiState` (DB: session revocation and
  deactivation take effect immediately). Used inside `auth-server` itself.
- `JwtVerifier` + `RemoteAuthCtx` — a light check without the DB, only the JWT
  signature and expiry against the public keys from `GET /.well-known/jwks.json`
  (`auth_crypto::Ed25519Verifier`); no private key needed. Instant session
  revocation is not seen. For other microservices that do not need the whole
  auth database:

```rust
#[derive(Clone)]
struct AppState { verifier: auth_api::extract::JwtVerifier, /* ...yours */ }
impl axum::extract::FromRef<AppState> for auth_api::extract::JwtVerifier {
    fn from_ref(s: &AppState) -> Self { s.verifier.clone() }
}

async fn handler(RemoteAuthCtx(claims): RemoteAuthCtx) -> impl IntoResponse { /* claims.user_id */ }
```

To decide what a user may do in a scope, such a service asks
`GET /auth/me/permissions?scope=...` with the user's token and caches the answer
for a short time.

```powershell
cargo build -p auth-api
cargo clippy -p auth-api -- -D warnings
```

There are no HTTP-layer tests yet — it is checked end to end through `auth-server`.
