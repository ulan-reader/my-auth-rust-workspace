**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-core

Domain and use cases. No sqlx, axum, argon2 or jwt here — only business rules
and the ports (traits) that adapters implement.

## Modules

- `domain.rs` — entities (`User`, `Role`, `Permission`, `Session`) and validated
  newtypes (`Email`, `RoleCode`, `PermissionCode`, `ScopeId`, ...): an invalid
  value simply cannot exist, parsing always goes through `parse()`.
- `error.rs` — the single `AuthError` for the whole domain.
- `ports.rs` — outgoing ports:
  - transactions: `UnitOfWork` (`begin`) and `Tx` (`commit`, rollback on drop);
  - storage: `UserRepository`, `RoleRepository` (including `lock`),
    `AssignmentRepository`, `PermissionRepository`, `SessionRepository`,
    `SettingsRepository`, `SetupRepository`, `AuditRepository`;
  - crypto and time: `PasswordHasher`, `AccessTokenCodec` / `AccessTokenVerifier`,
    `RefreshTokenProvider`, `Clock`.
- `service/` — use cases: `AuthService` (login, refresh, logout, register, own
  password), `AccessService` (permission checks, own permissions), `UserService`,
  `RoleService`, `SettingsService`, `SetupService`, `AuditService` (reading the
  audit log). `Ports` bundles all ports for `Service::from_ports`.
- `testing.rs` (`cfg(test)` only) — in-memory fakes of every port.

## Contracts for adapters

- Writing methods take `&mut dyn Tx` and never commit; reading methods go
  around the transaction and do not see its uncommitted changes.
- If a method returned an error, the caller does not commit — the transaction
  rolls back on drop.
- "No record": `Ok(None)` for `find_*`, `Err(NotFound)` for operations on a
  specific record; uniqueness violation → `Conflict`, broken reference →
  `Validation`, anything else → `AuthError::internal(..)`.
- A `Tx` may only be passed to repositories of the adapter that created it.

## Notable behaviour

- **One use case — one transaction.** Checks that must hold until commit (the
  role's permissions, "this is not admin") are done under `RoleRepository::lock`.
- **Scoped administration**: `roles.assign` is checked in the scope being
  assigned to, so a scope admin hands out roles only in their own scope.
- **Audit in the same transaction**: every change of access and the user's own
  actions are recorded with `AuditRepository::record` before `commit`. Codes are
  in `service::audit_actions`.
- **Refresh-token rotation with reuse detection**: presenting an already revoked
  token is a sign of theft — all of the user's sessions are revoked.
- **Login does not reveal whether an email exists** — a wrong password, an
  unknown email and garbage input give the same `InvalidCredentials`, with
  `verify_dummy` on the "empty" branches to even out response time.
- **Session revocation and user deactivation take effect immediately** —
  `authenticate` re-checks the session and the user on every call instead of
  trusting a non-expired JWT.

## Tests

```powershell
cargo test -p auth-core
cargo clippy -p auth-core -- -D warnings
```

All use cases are tested on the in-memory fakes (`testing.rs`), without a DB.
