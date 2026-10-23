# auth-api

axum-роутер поверх `auth-core`. Ни sqlx, ни argon2, ни jwt здесь нет — только
use-case'ы core и HTTP-обвязка.

## Маршруты

```
POST   /auth/register        (если включено в /settings)
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
POST   /auth/logout-all
GET    /auth/me
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
```

## Защита

- **Rate-limit** (`api.rate_limit`) — на `/auth/login`, `/auth/register`,
  `/auth/me/password`. Ключ — IP соединения (`ConnectInfo`, поэтому сервер
  запускается через `into_make_service_with_connect_info`). `X-Forwarded-For`
  принимается только от прокси из `trusted_proxies`: цепочка разбирается
  справа налево, первый недоверенный адрес считается клиентом.
- **CORS** (`api.allowed_origins`) — пустой список запрещает кросс-доменные
  запросы из браузера. Значения — только `http(s)://хост[:порт]`; невалидный
  origin — ошибка конфигурации, `router()` возвращает `Err` и сервер не стартует.

## Экстракторы

- `AuthCtx` — полная проверка через `ApiState` (БД: отзыв сессии/деактивация
  учитываются мгновенно). Используется внутри самого `auth-server`.
- `JwtVerifier` + `RemoteAuthCtx` — лёгкая проверка без БД, только
  подпись/срок JWT по публичным ключам из `GET /.well-known/jwks.json`
  (`auth_crypto::Ed25519Verifier`), приватный ключ не нужен. Мгновенный отзыв
  сессии не учитывается. Для сторонних микросервисов, которым не нужна вся
  база auth:

```rust
#[derive(Clone)]
struct AppState { verifier: auth_api::extract::JwtVerifier, /* ...своё */ }
impl axum::extract::FromRef<AppState> for auth_api::extract::JwtVerifier {
    fn from_ref(s: &AppState) -> Self { s.verifier.clone() }
}

async fn handler(RemoteAuthCtx(claims): RemoteAuthCtx) -> impl IntoResponse { /* claims.user_id */ }
```

```powershell
cargo build -p auth-api
cargo clippy -p auth-api -- -D warnings
```

Тестов на HTTP-слой нет — он проверяется через `auth-server` end-to-end.
