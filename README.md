# Auth Workspace

Гексагональный auth/authz-сервис на Rust: пользователи, роли (глобальные и с
областью действия — `scope`), права, сессии с ротацией refresh-токенов,
runtime-настройки (например, включение саморегистрации) без передеплоя.
Библиотека в первую очередь — можно встроить в любой Rust+Axum-сервис, а не
только гонять как отдельный HTTP-сервис.

## Архитектура

```
                     ┌─────────────┐
                     │  auth-core  │  домен, порты (трейты), use-case'ы
                     └──────┬──────┘  ни sqlx, ни axum, ни argon2 — только домен
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐  ┌────────▼───────┐  ┌────────▼───────┐
│ auth-postgres │  │  auth-crypto   │  │ auth-telemetry │
│ (адаптер БД)  │  │ Argon2/JWT/RT  │  │ tracing→Jaeger │
└───────┬───────┘  └────────┬───────┘  └────────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                     ┌──────▼──────┐
                     │  auth-api   │  axum-роутер поверх core (DTO, HTTP-ошибки)
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ auth-server │  composition root: конфиг → сборка → запуск
                     └─────────────┘
```

Зависимости идут только внутрь; `auth-postgres`/`auth-crypto`/`auth-telemetry`
друг про друга не знают. Любой из адаптеров можно заменить, не трогая
остальное — например, подставить SQLite вместо Postgres, реализовав те же
порты (`crates/auth-core/src/ports.rs`).

## Крейты

| Крейт | Что делает | README |
|---|---|---|
| `auth-core` | Домен, порты, use-case'ы (`AuthService`, `UserService`, `RoleService`, `AccessService`, `SettingsService`) | [crates/auth-core](crates/auth-core/README.md) |
| `auth-postgres` | Реализация портов на sqlx/Postgres, миграции | [crates/auth-postgres](crates/auth-postgres/README.md) |
| `auth-crypto` | Argon2id, JWT (EdDSA/Ed25519) + JWKS, refresh-токены | [crates/auth-crypto](crates/auth-crypto/README.md) |
| `auth-telemetry` | tracing → OTLP/HTTP → Jaeger | [crates/auth-telemetry](crates/auth-telemetry/README.md) |
| `auth-api` | axum-роутер поверх core, DTO, HTTP-коды ошибок, rate-limit, CORS, лёгкий JWT-экстрактор для сторонних сервисов | [crates/auth-api](crates/auth-api/README.md) |
| `auth-server` | Собирает всё вместе, запускает HTTP, CLI (`jwt-keygen`) | [crates/auth-server](crates/auth-server/README.md) |

`apps/admin-ui` — фронт админки на Leptos (CSR), в workspace не входит,
собирается отдельно через `trunk`.

## Быстрый старт (Docker)

Нужен только Docker — Rust и C++ build tools на машине не требуются.

```powershell
copy .env.example .env

# сгенерировать ключ подписи JWT и вписать вывод в .env
docker compose --profile dev run --rm auth-dev cargo run -p auth-server -- jwt-keygen

# вписать в .env AUTH__SETUP__TOKEN (минимум 32 символа), например вывод:
#   openssl rand -base64 32

# Postgres + Jaeger + сервер с автопересборкой при сохранении файлов
docker compose --profile dev up
```

Сервер — `http://localhost:8080`, Jaeger UI — `http://localhost:16686`.

### Первый администратор

Создаётся один раз через API — CLI не нужен:

```powershell
Invoke-RestMethod http://localhost:8080/setup        # {"required": true}

Invoke-RestMethod -Method Post -Uri http://localhost:8080/setup -ContentType "application/json" `
  -Body (@{ setup_token = "<AUTH__SETUP__TOKEN>"; email = "admin@example.com"; password = "super-secret-1";
            first_name = "Admin"; second_name = "Root" } | ConvertTo-Json)    # 201
```

После этого `/setup` закрыт навсегда (флаг в БД): повторные и параллельные
запросы получают `404`, `GET /setup` отдаёт `{"required": false}`. Без
`AUTH__SETUP__TOKEN` эндпоинт выключен. Переменную после настройки можно удалить.

| Команда | Что поднимает |
|---|---|
| `docker compose up -d` | только Postgres (порт 2134) и Jaeger |
| `docker compose --profile dev up` | + `auth-dev`: исходники монтируются с хоста, `cargo watch` пересобирает и перезапускает сервер при сохранении |
| `docker compose --profile prod up -d --build` | + `auth`: прод-образ (`Dockerfile`, цель `runtime`) |

Прод-образ кеширует зависимости отдельным слоем (`cargo-chef`): правка своего
кода пересобирает только крейты workspace. Миграции зашиты в бинарь и
применяются при старте.

## Запуск без Docker

Нужны Rust 1.96+ и (на Windows) Visual Studio C++ build tools.

```powershell
docker compose up -d                                   # Postgres + Jaeger
copy .env.example .env                                 # заполнить ключ JWT и AUTH__SETUP__TOKEN
cargo run -p auth-server -- jwt-keygen                 # вывод — в .env
cargo run -p auth-server                               # слушает 127.0.0.1:8080
```

Первый администратор — через `POST /setup`, как выше.

## Конфиг

`config/default.toml` → `config/{AUTH_ENV}.toml` (по умолчанию `AUTH_ENV=dev`,
в прод-образе `prod`) → переменные окружения `AUTH__СЕКЦИЯ__КЛЮЧ`. Секреты —
только через окружение (`.env`), не в файлы конфига:

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<base64url seed Ed25519, из jwt-keygen>
AUTH__CRYPTO__JWT__KID=<идентификатор ключа, например дата>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
AUTH__SETUP__TOKEN=<только для первоначальной настройки>
```

Подробности по каждой секции — в [crates/auth-server](crates/auth-server/README.md).

## Пример запросов

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body (@{ email = "admin@example.com"; password = "super-secret-1" } | ConvertTo-Json)).access_token

Invoke-RestMethod -Uri http://localhost:8080/users -Headers @{ Authorization = "Bearer $token" }
```

## Модель прав

- **Глобальная роль** (`RoleScope::Global`) — права действуют везде.
- **Роль с областью действия** (`RoleScope::Scoped`) — права действуют только
  внутри конкретного `scope` (непрозрачная строка вида `department:17`,
  `project:42` — что она значит, решает сервис-потребитель, auth это не
  интересует).
- Правило соответствия (`RoleScope::check_assignment`) живёт в домене, а не
  размазано по хендлерам.

### Защита от эскалации прав

- **Нельзя выдать больше, чем имеешь сам.** Назначить, снять, изменить или
  удалить роль может только тот, у кого есть все её права; задать роли набор
  прав — только тот, у кого есть и старые, и новые права.
- **Нельзя управлять более сильным пользователем.** Сменить пароль,
  заблокировать, изменить или удалить можно только того, чьи глобальные права
  входят в твои.
- **`admin` — системная роль**: у неё всегда все права; удалить её,
  переименовать или урезать по правам нельзя. Новые права выдаются ей
  миграциями.
- **Последний администратор неприкосновенен**: снять с него роль, заблокировать
  или удалить нельзя — проверка в транзакции под общей блокировкой, так что и
  параллельные запросы не оставят систему без админа.

## Runtime-настройки

Часть поведения (сейчас — `allow_self_registration`) хранится не в конфиге, а
в БД и меняется через `GET/PUT /settings` (право `settings.manage`) без
передеплоя и рестарта.

## Для сторонних сервисов

- **Полная интеграция**: подключить `auth-core` + `auth-postgres` +
  `auth-crypto` как библиотеки прямо в свой Rust-сервис (без HTTP вообще).
- **Лёгкая проверка токена без БД**: `auth_api::extract::{JwtVerifier,
  RemoteAuthCtx}` + `auth_crypto::Ed25519Verifier` — проверка подписи и срока
  JWT по публичным ключам из `GET /.well-known/jwks.json`, приватный ключ не
  нужен. Мгновенный отзыв сессии при этом не учитывается — токен живёт до
  своего `exp` (по умолчанию 15 минут).
- **Через HTTP**: обычные запросы к `auth-server`, `Authorization: Bearer`.

## Разработка

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # интеграционным тестам auth-postgres нужен Docker
```

То же гоняет CI (`.github/workflows/ci.yml`) на каждый push в `main` и PR,
плюс `cargo audit` и сборку прод-образа.

## Статус

Шесть крейтов собраны и покрыты тестами (юнит + интеграционные на
`testcontainers`). К первому релизу в работе — журнал аудита (вход/выход,
изменения пользователей, ролей и настроек). Админка `apps/admin-ui` —
заготовка, будет обновлена позже.

## Лицензия

Двойная лицензия: [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE) — на выбор пользователя.
