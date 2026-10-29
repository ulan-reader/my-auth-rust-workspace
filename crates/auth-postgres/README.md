**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-postgres

Storage adapter: implementations of the `auth-core` ports on `sqlx`/Postgres.

## Transactions

`PgUnitOfWork::begin` opens a `PgTx` (a wrapper over `sqlx::Transaction`).
Writing repository methods take it as `&mut dyn Tx` and get the connection back
with a downcast; a transaction created by another adapter gives `Internal`. A
`PgTx` dropped without `commit` is rolled back.

## Schema

`users`, `roles`, `permissions`, `role_permissions`, `user_roles`, `sessions`,
`app_settings`, `audit_events` — see `migrations/`. Migrations run through
`sqlx::migrate!` (`auth_postgres::migrate(&pool)`); `auth-server` applies them on
start. Released migrations are never edited — only new ones are added.

Schema details:

- `user_roles.scope` stores `''` instead of `NULL` for global roles: `NULL` in a
  unique index does not conflict with itself in Postgres, and assigning the same
  global role twice must give `Conflict`.
- `audit_events.scope` is `NULL` for global events (no uniqueness there), and
  `actor_id` has no foreign key: records about a deleted user's actions stay.
- `audit_events` is append-only: `UPDATE`, `DELETE` and `TRUNCATE` are blocked by
  a trigger. Cleaning old records later needs a separate migration that disables
  the trigger explicitly.

## Functions and triggers

- `register_permission(code, description)` — how other services add their
  permissions from their own migrations. Validates the code with the same rule as
  `PermissionCode` and is idempotent (repeated calls update the description).
- `permissions_grant_admin` — every new permission is granted to `admin`
  automatically.

## Locks

- `RoleRepository::lock` — `SELECT ... FOR UPDATE` on the role row, then reads
  its permissions under the lock. Concurrent operations on the same role wait.
- `admin_guard` — locks the `admin` role row and checks that an active admin is
  still left after unassigning, deactivating or deleting.
- `PgSessionRepository::rotate` — `SELECT ... FOR UPDATE`: a parallel refresh
  with the same token cannot produce two valid results.
- `SetupRepository::create_first_admin` — locks the `app_settings` row: of
  parallel setup requests exactly one passes. It opens and commits its own
  transaction and writes `setup.complete` to the audit log inside it.

## Notes

- `sqlx 0.9` requires a `&'static str` for SQL (`SqlSafeStr`): all queries are
  literals or `concat!`, no `format!`.
- Audit details are a `jsonb` object of strings, written with
  `jsonb_object(keys, values)` — the adapter needs no `serde_json`.

## Tests

Integration tests on `testcontainers` start a real Postgres in Docker:

```powershell
cargo test -p auth-postgres   # Docker must be running
```

They cover rollback on drop and on errors, the last-admin guard under
concurrency, role locks, the audit log (rollback, filters, append-only) and the
SQL functions.
