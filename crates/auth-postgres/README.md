# auth-postgres

Адаптер хранения: реализации портов `auth-core` на `sqlx`/Postgres.

## Схема

`users`, `roles`, `permissions`, `role_permissions`, `user_roles`,
`sessions`, `app_settings` — см. `migrations/`. Миграции гоняются через
`sqlx::migrate!` (`auth_postgres::migrate(&pool)`).

Важная деталь схемы: `user_roles.scope` хранит `''` вместо `NULL` для
глобальных ролей — в Postgres `NULL` в уникальном индексе не конфликтует сам
с собой, а повторное назначение одной и той же глобальной роли должно давать
`Conflict`.

## Особенности

- `sqlx 0.9` требует `&'static str` для SQL (защита `SqlSafeStr`) — все
  запросы литеральные, без `format!`.
- `PgSessionRepository::rotate` использует `SELECT ... FOR UPDATE` в
  транзакции — параллельный refresh одним и тем же токеном не может выдать
  два валидных результата.

## Тесты

Интеграционные, на `testcontainers` — поднимают настоящий Postgres в Docker:

```powershell
cargo test -p auth-postgres   # нужен запущенный Docker
```
