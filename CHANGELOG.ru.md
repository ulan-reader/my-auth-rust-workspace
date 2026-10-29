[English](CHANGELOG.md) | **Русский** | [Қазақша](CHANGELOG.kk.md)

# Журнал изменений

Здесь перечислены все заметные изменения проекта. Формат —
[Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — по
[семантическому версионированию](https://semver.org/lang/ru/). До 1.0
несовместимое изменение поднимает минорную версию.

## [0.2.0] - Не выпущено

### Добавлено

- **Транзакции (Unit of Work).** Новые порты `UnitOfWork` и `Tx`: каждый
  use-case выполняется в одной транзакции и откатывается при drop, если не был
  закоммичен. В `auth-postgres` — `PgUnitOfWork` / `PgTx`.
- **Блокировка роли.** `RoleRepository::lock` (`SELECT ... FOR UPDATE`)
  возвращает `LockedRole` с правами, прочитанными под блокировкой; проверки над
  ролью теперь идут внутри транзакции, поэтому параллельные правки одной роли
  выполняются по очереди.
- **Администрирование в scope.** `roles.assign` проверяется в том scope, куда
  назначают: админ раздела раздаёт роли только у себя.
- **Свои права.** `GET /auth/me/permissions?scope=...` и
  `AccessService::my_permissions` — никакого права не требуется.
- **Журнал аудита.** Таблица `audit_events` (только дописывается), порт
  `AuditRepository`, `PgAuditRepository`, `AuditService`, `GET /audit` с
  фильтрами и страницами, право `audit.view`. Каждое изменение доступа и действия
  самого пользователя пишутся в той же транзакции, что и изменение; коды
  действий — в `service::audit_actions`.
- **У `admin` всегда все права**, в том числе добавленные позже (триггер
  `permissions_grant_admin`).
- **SQL-функция `register_permission(code, description)`**, через которую
  сервисы-потребители добавляют свои права из миграций; проверяет код и
  идемпотентна.
- README на английском для workspace и каждого крейта, русские и казахские
  версии рядом; этот журнал изменений на трёх языках.

### Изменено

- **Несовместимо:** пишущие методы репозиториев принимают `&mut dyn Tx` и
  больше сами не коммитят.
- **Несовместимо:** `SettingsRepository::set_allow_self_registration`
  принимает `Tx`.
- **Несовместимо:** в `Ports` новое поле `audit`; `AuthService::new`,
  `UserService::new`, `RoleService::new` и `SettingsService::new` принимают
  `Arc<dyn AuditRepository>`.
- **Несовместимо:** в `RoleRepository` новый обязательный метод `lock`; свои
  адаптеры должны реализовать его вместе с `AuditRepository`.
- `assign` с невалидной строкой scope теперь возвращает `Validation` раньше
  проверки, существует ли роль.
- `logout` открывает транзакцию, только если есть сессия для отзыва.
- Воркер очистки сессий пишет неудачный проход в лог как ошибку, а не
  молча его теряет.

### Исправлено

- `set_permissions` возвращал набор прав, прочитанный через пул, который не
  видел незакоммиченное изменение; теперь читает внутри транзакции.
- Гонка между проверкой прав до транзакции и записью (time-of-check/time-of-use)
  при изменении, удалении роли, смене её прав, назначении и снятии.

### Миграции

- `20261029120000_admin_all_permissions.sql` — триггер и `register_permission`.
- `20261030120000_audit.sql` — `audit_events`, её триггеры, право `audit.view`.

## [0.1.0] - 2026-10-24

Первый публичный релиз.

- Гексагональный workspace: `auth-core`, `auth-postgres`, `auth-crypto`,
  `auth-telemetry`, `auth-api`, `auth-server`.
- Пользователи, глобальные роли и роли со scope, права, защита от эскалации,
  неприкосновенный последний администратор.
- Сессии с ротацией refresh-токенов и обнаружением повторного использования;
  Argon2id; JWT (EdDSA/Ed25519) с JWKS и ротацией ключей.
- Runtime-настройки (`allow_self_registration`), одноразовая первоначальная
  настройка (`POST /setup`).
- Rate-limit, CORS, трассировка OpenTelemetry, Docker-образы, CI.

[0.2.0]: https://github.com/ulan-reader/my-auth-rust-workspace/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ulan-reader/my-auth-rust-workspace/releases/tag/v0.1.0
