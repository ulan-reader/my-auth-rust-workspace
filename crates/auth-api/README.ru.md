[English](README.md) | **Русский** | [Қазақша](README.kk.md)

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
GET    /auth/me/permissions?scope=...     свои права: глобальные плюс в scope
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
GET    /setup             POST /setup      (первоначальная настройка, один раз)
```

`/.well-known/jwks.json` и `/health/*` отдаёт `auth-server`.

Каждый админский маршрут проверяет своё право внутри use-case'а core
(`users.*`, `roles.*`, `permissions.view`, `settings.manage`, `audit.view`),
поэтому забытая проверка в хендлере доступ не откроет.

## Ошибки

`AuthError` → HTTP: `Validation` → 400, `InvalidCredentials` / `Unauthorized` →
401, `Forbidden` / `AccountDisabled` → 403, `NotFound` → 404, `Conflict` → 409,
`Internal` → 500 (подробности — в лог, не клиенту).

## Защита

- **Rate-limit** (`api.rate_limit`) — на `/auth/login`, `/auth/register`,
  `/auth/me/password` и `/setup` (общая квота на IP). Ключ — IP соединения
  (`ConnectInfo`, поэтому сервер запускается через
  `into_make_service_with_connect_info`). `X-Forwarded-For` принимается только
  от прокси из `trusted_proxies`: цепочка разбирается справа налево, первый
  недоверенный адрес считается клиентом.
- **CORS** (`api.allowed_origins`) — пустой список запрещает кросс-доменные
  запросы из браузера. Значения — только `http(s)://хост[:порт]`; невалидный
  origin — ошибка конфигурации, `router()` возвращает `Err` и сервер не стартует.

## Экстракторы

- `AuthCtx` — полная проверка через `ApiState` (БД: отзыв сессии и деактивация
  учитываются мгновенно). Используется внутри самого `auth-server`.
- `JwtVerifier` + `RemoteAuthCtx` — лёгкая проверка без БД, только подпись и
  срок JWT по публичным ключам из `GET /.well-known/jwks.json`
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

Чтобы понять, что пользователю можно в scope, такой сервис спрашивает
`GET /auth/me/permissions?scope=...` с токеном пользователя и ненадолго кеширует
ответ.

```powershell
cargo build -p auth-api
cargo clippy -p auth-api -- -D warnings
```

Тестов на HTTP-слой пока нет — он проверяется через `auth-server` end-to-end.
