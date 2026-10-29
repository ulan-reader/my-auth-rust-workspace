[English](README.md) | **Русский** | [Қазақша](README.kk.md)

# Auth Workspace

Гексагональный сервис аутентификации и авторизации на Rust: пользователи, роли
(глобальные и с областью действия — `scope`), права, сессии с ротацией
refresh-токенов, журнал аудита и runtime-настройки (например, включение
саморегистрации) без передеплоя.

В первую очередь это библиотека: её можно встроить в любой Rust + Axum-сервис,
реализовать порты под своё хранилище или просто запустить готовый HTTP-сервер.

## Три способа использовать

| Способ | Что берёте | Когда |
|---|---|---|
| **Библиотека, своё хранилище** | `auth-core` + своя реализация его портов | у вас уже есть слой работы с БД, нужны только правила |
| **Библиотека, готовое хранилище** | `auth-core` + `auth-postgres` + `auth-crypto` | встроить авторизацию в свой Rust-сервис без HTTP посередине |
| **Сервер** | `auth-server` (Docker-образ) | любой язык; общение по HTTP, проверка JWT по JWKS |

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

Зависимости идут только внутрь; `auth-postgres`, `auth-crypto` и
`auth-telemetry` друг про друга не знают. Любой адаптер можно заменить, не
трогая остальное — например, подставить SQLite вместо Postgres, реализовав те же
порты (`crates/auth-core/src/ports.rs`).

## Крейты

| Крейт | Что делает | README |
|---|---|---|
| `auth-core` | Домен, порты, use-case'ы (`AuthService`, `UserService`, `RoleService`, `AccessService`, `SettingsService`, `AuditService`, `SetupService`) | [crates/auth-core](crates/auth-core/README.ru.md) |
| `auth-postgres` | Порты на sqlx/Postgres, транзакции, миграции | [crates/auth-postgres](crates/auth-postgres/README.ru.md) |
| `auth-crypto` | Argon2id, JWT (EdDSA/Ed25519) + JWKS, refresh-токены | [crates/auth-crypto](crates/auth-crypto/README.ru.md) |
| `auth-telemetry` | tracing → OTLP/HTTP → Jaeger | [crates/auth-telemetry](crates/auth-telemetry/README.ru.md) |
| `auth-api` | axum-роутер поверх core, DTO, HTTP-коды ошибок, rate-limit, CORS, лёгкий JWT-экстрактор для сторонних сервисов | [crates/auth-api](crates/auth-api/README.ru.md) |
| `auth-server` | Собирает всё вместе, запускает HTTP, CLI (`jwt-keygen`) | [crates/auth-server](crates/auth-server/README.ru.md) |

`apps/admin-ui` — фронт админки на Leptos (CSR). В workspace не входит,
собирается отдельно через `trunk` и пока остаётся заготовкой.

## Быстрый старт (Docker)

Нужен только Docker — Rust и C++ build tools на машине не требуются.

```powershell
copy .env.example .env

# сгенерировать ключ подписи JWT и вписать вывод в .env
docker compose --profile dev run --rm auth-dev cargo run -p auth-server -- jwt-keygen

# вписать в .env AUTH__SETUP__TOKEN (минимум 32 символа), например вывод:
#   openssl rand -base64 32

# Postgres + Jaeger + сервер с пересборкой при сохранении файлов
docker compose --profile dev up
```

Сервер — `http://localhost:8080`, Jaeger UI — `http://localhost:16686`.

### Первый администратор

Создаётся один раз через API, CLI не нужен:

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

Нужны Rust 1.98.1+ и (на Windows) Visual Studio C++ build tools.

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

Все секции описаны в [crates/auth-server](crates/auth-server/README.ru.md).

## Пример запросов

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body (@{ email = "admin@example.com"; password = "super-secret-1" } | ConvertTo-Json)).access_token
$auth = @{ Authorization = "Bearer $token" }

Invoke-RestMethod -Uri http://localhost:8080/users -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/auth/me/permissions?scope=space:wiki" -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/audit?action=role.assign" -Headers $auth
```

Полный список маршрутов — в [crates/auth-api](crates/auth-api/README.ru.md).

## Модель прав

- **Глобальная роль** (`RoleScope::Global`) — права действуют везде.
- **Роль с областью действия** (`RoleScope::Scoped`) — права действуют только
  внутри конкретного `scope` (непрозрачная строка вида `space:wiki`,
  `project:42` — что она значит, решает сервис-потребитель, auth это не
  интересует).
- Права в scope — это **глобальные права плюс назначенные именно в этом
  scope**. Правило соответствия (`RoleScope::check_assignment`) живёт в домене,
  а не размазано по хендлерам.
- **Админы раздела**: `roles.assign`, выданный внутри `space:wiki`, позволяет
  раздавать роли только в `space:wiki` — не в других разделах и не глобальные.
- Вошедшему пользователю не нужно никакого права, чтобы узнать свои права:
  `GET /auth/me/permissions?scope=...`. Клиент (например, вики) по ответу решает,
  какие кнопки показать.

### Свои права

Сервисы-потребители регистрируют свои права миграцией в базе auth:

```sql
select register_permission('wiki.article.delete', 'Удаление любой статьи');
```

Функция проверяет код и идемпотентна. Роль `admin` получает новое право сама,
через триггер; остальные — через роль.

### Защита от эскалации прав

- **Нельзя выдать больше, чем имеешь сам.** Назначить, снять, изменить или
  удалить роль может только тот, у кого есть все её права; задать роли набор
  прав — только тот, у кого есть и старые, и новые права.
- **Нельзя управлять более сильным пользователем.** Сменить пароль,
  заблокировать, изменить или удалить можно только того, чьи глобальные права
  входят в твои.
- **`admin` — системная роль**: у неё всегда все права (новые — тоже, через
  триггер); удалить её, сменить ей код или редактировать её набор прав нельзя.
- **Последний администратор неприкосновенен**: снять с него роль, заблокировать
  или удалить нельзя — проверка в транзакции под общей блокировкой, так что и
  параллельные запросы не оставят систему без админа.

## Транзакции

Каждый use-case — одна транзакция (`UnitOfWork::begin` → вызовы репозиториев →
`commit`). Ошибка на любом шаге — `commit` не будет, транзакция откатится при
drop. Проверки, которые должны оставаться верными до коммита (права роли, «это
не admin»), идут под блокировкой строки (`RoleRepository::lock`), поэтому
параллельные правки одной роли выполняются по очереди.

## Журнал аудита

Каждое изменение доступа пишется в `audit_events` **в той же транзакции**, что и
само изменение: нет изменения — нет записи; не удалось записать — изменение
откатится. Таблица только дописывается (`UPDATE`, `DELETE` и `TRUNCATE`
запрещены триггером).

- Действия админа: роли (создание, изменение, удаление, права, назначение и
  снятие со scope), пользователи (создание, изменение, пароль, активация и
  деактивация, удаление), настройки, первоначальная настройка.
- Действия самого пользователя: регистрация, вход, выход, выход со всех
  устройств, смена своего пароля, повторное предъявление отозванного
  refresh-токена (`actor` пустой — это реакция системы).
- Не пишутся: неудачные входы (от них защищают rate-limit и логи WARN), обычное
  обновление токенов, отклонённые запросы.
- Детали — плоские строки, которые явно кладёт сервис: пароли, хеши и токены
  туда не попадают.

Чтение — `GET /audit?actor_id=&action=&target_type=&target_id=&page=&per_page=`
(право `audit.view`), новые сверху.

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
- **Через HTTP**: обычные запросы к `auth-server` с `Authorization: Bearer`;
  права для интерфейса — из `GET /auth/me/permissions?scope=...`.

## Разработка

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # интеграционным тестам auth-postgres нужен Docker
```

То же гоняет CI (`.github/workflows/ci.yml`) на каждый push в `main` и PR,
плюс `cargo audit` и сборку прод-образа.

Без локального Rust тесты запускаются в Docker (Git Bash):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src:ro" -v //var/run/docker.sock:/var/run/docker.sock -e CARGO_TARGET_DIR=/tmp/target -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway -w /src rust:1.98-slim-bookworm cargo test --workspace
```

## Статус

Версия 0.2.0, до 1.0: API крейтов ещё может меняться между минорными версиями;
каждое несовместимое изменение перечислено в [CHANGELOG.ru.md](CHANGELOG.ru.md).
Юнит-тесты на in-memory заглушках и интеграционные на настоящем Postgres
(`testcontainers`) покрывают ядро и хранилище; у HTTP-слоя своих тестов пока нет.
`apps/admin-ui` — заготовка.

Пока не сделано: подтверждение email и сброс пароля, блокировка аккаунта после
неудачных входов, список своих сессий, OpenAPI-описание, хранение аудита по сроку.

## Лицензия

Двойная лицензия: [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE) — на выбор пользователя.
