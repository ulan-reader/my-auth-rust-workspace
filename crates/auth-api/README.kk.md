[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# auth-api

`auth-core` үстіндегі axum-роутер. Мұнда sqlx, argon2 немесе jwt жоқ — тек
core use-case'тері және олардың HTTP-қабаты.

## Маршруттар

```
POST   /auth/register        (/settings ішінде қосылған болса)
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
POST   /auth/logout-all
GET    /auth/me
GET    /auth/me/permissions?scope=...     өз рұқсаттары: жаһандық плюс scope ішіндегі
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
GET    /setup             POST /setup      (бастапқы баптау, бір рет)
```

`/.well-known/jwks.json` және `/health/*` маршруттарын `auth-server` береді.

Әр әкімші маршруты өз рұқсатын core use-case'інің ішінде тексереді
(`users.*`, `roles.*`, `permissions.view`, `settings.manage`, `audit.view`),
сондықтан хендлерде ұмытылған тексеру қол жеткізуді ашпайды.

## Қателер

`AuthError` → HTTP: `Validation` → 400, `InvalidCredentials` / `Unauthorized` →
401, `Forbidden` / `AccountDisabled` → 403, `NotFound` → 404, `Conflict` → 409,
`Internal` → 500 (толығырақ — клиентке емес, логқа).

## Қорғау

- **Rate-limit** (`api.rate_limit`) — `/auth/login`, `/auth/register`,
  `/auth/me/password` және `/setup` үшін (IP-ге ортақ квота). Кілт — қосылыстың
  IP-і (`ConnectInfo`, сондықтан сервер `into_make_service_with_connect_info`
  арқылы іске қосылады). `X-Forwarded-For` тек `trusted_proxies` тізіміндегі
  проксиден қабылданады: тізбек оңнан солға қарай талданады, алғашқы сенімсіз
  мекенжай клиент деп саналады.
- **CORS** (`api.allowed_origins`) — бос тізім браузерден басқа доменге жіберілетін
  сұраныстарға тыйым салады. Мәндер — тек `http(s)://хост[:порт]`; жарамсыз
  origin — конфигурация қатесі, `router()` `Err` қайтарады және сервер іске қосылмайды.

## Экстракторлар

- `AuthCtx` — `ApiState` арқылы толық тексеру (дерекқор: сессияны кері шақыру
  мен өшіру лезде ескеріледі). `auth-server`-дің өз ішінде қолданылады.
- `JwtVerifier` + `RemoteAuthCtx` — дерекқорсыз жеңіл тексеру, тек JWT
  қолтаңбасы мен мерзімі `GET /.well-known/jwks.json` ашық кілттері бойынша
  (`auth_crypto::Ed25519Verifier`), жеке кілт керек емес. Сессияны лезде кері
  шақыру ескерілмейді. Бүкіл auth дерекқоры керек емес басқа микросервистерге:

```rust
#[derive(Clone)]
struct AppState { verifier: auth_api::extract::JwtVerifier, /* ...өзіңіздікі */ }
impl axum::extract::FromRef<AppState> for auth_api::extract::JwtVerifier {
    fn from_ref(s: &AppState) -> Self { s.verifier.clone() }
}

async fn handler(RemoteAuthCtx(claims): RemoteAuthCtx) -> impl IntoResponse { /* claims.user_id */ }
```

Пайдаланушыға scope ішінде не рұқсат етілгенін білу үшін мұндай сервис
пайдаланушы токенімен `GET /auth/me/permissions?scope=...` сұрайды және жауапты
қысқа уақытқа кэштейді.

```powershell
cargo build -p auth-api
cargo clippy -p auth-api -- -D warnings
```

HTTP-қабатына арналған тесттер әзірге жоқ — ол `auth-server` арқылы басынан
аяғына дейін тексеріледі.
