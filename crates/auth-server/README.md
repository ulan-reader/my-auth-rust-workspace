# auth-server

Composition root: единственный бинарь в workspace. Читает конфиг, собирает
адаптеры (`auth-postgres`/`auth-crypto`) за портами `auth-core`, поднимает
`auth-api` через axum, отдаёт JWKS и health-check'и.

## Конфиг

`config/default.toml` (+ `config/{AUTH_ENV}.toml`, дефолт `AUTH_ENV=dev`) +
переменные окружения `AUTH__SECTION__KEY` (двойное подчёркивание —
разделитель). `.env` в корне репо подхватывается через `dotenvy`; шаблон —
`.env.example`.

Обязательные секреты (только через env, не в файл):

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<base64url 32-байтного seed Ed25519>
AUTH__CRYPTO__JWT__KID=<идентификатор ключа>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
```

Остальные секции (`config/default.toml`):

| Секция | Ключи | Заметки |
|---|---|---|
| `server` | `bind` | в Docker — `0.0.0.0:8080` |
| `api` | `request_timeout_secs`, `allowed_origins` | пустой `allowed_origins` — кросс-доменные запросы из браузера запрещены; разрешены только `http(s)://хост[:порт]`, невалидный origin не даёт серверу стартовать |
| `api.rate_limit` | `per_second`, `burst_size`, `trusted_proxies` | лимит на `/auth/login`, `/auth/register`, `/auth/me/password` по IP соединения; `X-Forwarded-For` учитывается только от прокси из `trusted_proxies` |
| `auth` | `access_ttl_secs`, `refresh_ttl_secs` | 15 минут / 30 дней |
| `crypto.argon2` | `m_cost_kib`, `t_cost`, `p_cost` | дефолты — минимум OWASP |
| `crypto.jwt` | `extra_verification_keys` | старые публичные ключи на время ротации |
| `postgres` | `max_connections`, `min_connections`, `acquire_timeout_secs` | |
| `maintenance` | `session_cleanup_interval_secs`, `session_retention_secs` | фоновая очистка мёртвых сессий |
| `telemetry` | `enabled`, `service_name`, `otlp_endpoint`, `sample_ratio`, `log_level` | |

## CLI

```powershell
cargo run -p auth-server                                    # запуск сервера
cargo run -p auth-server -- bootstrap-admin --email .. --password ..
cargo run -p auth-server -- jwt-keygen
```

`bootstrap-admin` создаёт первого администратора в обход проверки прав
(иначе создать первого пользователя некому — `POST /users` сам требует уже
залогиненного админа). Идемпотентна, безопасно перезапускать.

`jwt-keygen` печатает новый ключ Ed25519 (`SIGNING_KEY`) и его публичную часть.
Ни конфиг, ни БД не нужны. При ротации старый публичный ключ кладётся в
`crypto.jwt.extra_verification_keys` под старым `kid`, чтобы уже выданные
токены доживали свой TTL.

## Служебные эндпоинты

- `GET /.well-known/jwks.json` — публичные ключи проверки JWT, без аутентификации.
- `GET /health/live` — процесс жив (без походов в БД).
- `GET /health/ready` — Postgres доступен, иначе `503`.

## Жизненный цикл

- Миграции применяются при старте.
- Фоновый воркер чистит просроченные и отозванные сессии старше
  `session_retention_secs` — сразу при старте и далее каждые
  `session_cleanup_interval_secs`.
- Ctrl+C и SIGTERM (`docker stop`, Kubernetes) — graceful shutdown: сервер
  дорабатывает текущие запросы, воркер очистки останавливается.

## Docker

`Dockerfile` в корне репо, две цели:

- `dev` — `cargo watch` поверх смонтированных исходников, пересборка при сохранении;
- `runtime` — прод-образ на `debian:bookworm-slim`, непривилегированный
  пользователь, `AUTH_ENV=prod`.

Запуск — через `docker-compose.yml` (профили `dev` / `prod`), см. корневой README.
