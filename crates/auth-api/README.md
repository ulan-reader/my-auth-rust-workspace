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

## Экстракторы

- `AuthCtx` — полная проверка через `ApiState` (БД: отзыв сессии/деактивация
  учитываются мгновенно). Используется внутри самого `auth-server`.
- `JwtVerifier` + `RemoteAuthCtx` — лёгкая проверка без БД, только
  подпись/срок JWT по общему секрету. Для сторонних микросервисов, которым не
  нужна вся база auth:

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
