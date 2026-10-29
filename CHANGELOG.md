**English** | [Русский](CHANGELOG.ru.md) | [Қазақша](CHANGELOG.kk.md)

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/). Before 1.0 a breaking change bumps
the minor version.

## [0.2.0] - Unreleased

### Added

- **Transactions (Unit of Work).** New ports `UnitOfWork` and `Tx`: every use
  case runs in one transaction and rolls back on drop if it is not committed.
  `auth-postgres` implements them with `PgUnitOfWork` / `PgTx`.
- **Role lock.** `RoleRepository::lock` (`SELECT ... FOR UPDATE`) returns a
  `LockedRole` with its permissions read under the lock; checks on a role are now
  made inside the transaction, so concurrent edits of one role are serialized.
- **Scoped administration.** `roles.assign` is checked in the scope being
  assigned to: a scope admin hands out roles only in their own scope.
- **Own permissions.** `GET /auth/me/permissions?scope=...` and
  `AccessService::my_permissions` — no permission required.
- **Audit log.** Table `audit_events` (append-only), port `AuditRepository`,
  `PgAuditRepository`, `AuditService`, `GET /audit` with filters and paging,
  permission `audit.view`. Every change of access and the user's own actions are
  recorded in the same transaction as the change; action codes are in
  `service::audit_actions`.
- **`admin` always has every permission**, including ones added later (trigger
  `permissions_grant_admin`).
- **`register_permission(code, description)`** SQL function for consuming
  services to add their permissions from migrations; validates the code and is
  idempotent.
- English README for the workspace and every crate, Russian (`README.ru.md`)
  and Kazakh (`README.kk.md`) versions next to it; this changelog in the same
  three languages.

### Changed

- **Breaking:** writing repository methods take `&mut dyn Tx` and no longer
  commit by themselves.
- **Breaking:** `SettingsRepository::set_allow_self_registration` takes a `Tx`.
- **Breaking:** `Ports` has a new `audit` field; `AuthService::new`,
  `UserService::new`, `RoleService::new` and `SettingsService::new` take an
  `Arc<dyn AuditRepository>`.
- **Breaking:** `RoleRepository` has a new required method `lock`; adapters of
  your own must implement it together with `AuditRepository`.
- `assign` with an invalid scope string now returns `Validation` before checking
  whether the role exists.
- `logout` opens a transaction only when there is a session to revoke.
- The session cleanup worker logs a failed run as an error instead of dropping it.

### Fixed

- `set_permissions` returned the permission set read through the pool, which did
  not see the uncommitted change; it now reads inside the transaction.
- A race between permission checks made before the transaction and the write
  (time-of-check/time-of-use) on role update, delete, permission change and
  (un)assignment.

### Migrations

- `20261029120000_admin_all_permissions.sql` — trigger and `register_permission`.
- `20261030120000_audit.sql` — `audit_events`, its triggers, permission `audit.view`.

## [0.1.0] - 2026-10-24

First public release.

- Hexagonal workspace: `auth-core`, `auth-postgres`, `auth-crypto`,
  `auth-telemetry`, `auth-api`, `auth-server`.
- Users, global and scoped roles, permissions, escalation protection, the
  untouchable last administrator.
- Sessions with refresh-token rotation and reuse detection; Argon2id; JWT
  (EdDSA/Ed25519) with JWKS and key rotation.
- Runtime settings (`allow_self_registration`), one-time initial setup
  (`POST /setup`).
- Rate limit, CORS, OpenTelemetry tracing, Docker images, CI.

[0.2.0]: https://github.com/ulan-reader/my-auth-rust-workspace/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ulan-reader/my-auth-rust-workspace/releases/tag/v0.1.0
