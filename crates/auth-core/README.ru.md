[English](README.md) | **Русский** | [Қазақша](README.kk.md)

# auth-core

Домен и use-case'ы. Ни sqlx, ни axum, ни argon2, ни jwt здесь нет — только
бизнес-правила и порты (трейты), которые реализуют адаптеры.

## Модули

- `domain.rs` — сущности (`User`, `Role`, `Permission`, `Session`) и
  валидируемые newtype'ы (`Email`, `RoleCode`, `PermissionCode`, `ScopeId`, ...):
  невалидное значение просто не может существовать, парсинг всегда через `parse()`.
- `error.rs` — единственный `AuthError` на весь домен.
- `ports.rs` — исходящие порты:
  - транзакции: `UnitOfWork` (`begin`) и `Tx` (`commit`, откат при drop);
  - хранение: `UserRepository`, `RoleRepository` (в том числе `lock`),
    `AssignmentRepository`, `PermissionRepository`, `SessionRepository`,
    `SettingsRepository`, `SetupRepository`, `AuditRepository`;
  - крипто и время: `PasswordHasher`, `AccessTokenCodec` / `AccessTokenVerifier`,
    `RefreshTokenProvider`, `Clock`.
- `service/` — use-case'ы: `AuthService` (вход, refresh, выход, регистрация,
  смена своего пароля), `AccessService` (проверка прав, свои права),
  `UserService`, `RoleService`, `SettingsService`, `SetupService`, `AuditService`
  (чтение журнала аудита). `Ports` собирает все порты для `Service::from_ports`.
- `testing.rs` (только `cfg(test)`) — in-memory заглушки всех портов.

## Договорённости для адаптеров

- Пишущие методы принимают `&mut dyn Tx` и сами не коммитят; читающие идут мимо
  транзакции и не видят её незакоммиченных изменений.
- Если метод вернул ошибку, вызывающий не коммитит — транзакция откатится при drop.
- «Записи нет»: `Ok(None)` для `find_*`, `Err(NotFound)` для операций над
  конкретной записью; нарушение уникальности → `Conflict`, битая ссылка →
  `Validation`, всё остальное → `AuthError::internal(..)`.
- `Tx` можно передавать только в репозитории того адаптера, который её создал.

## Особенности

- **Один use-case — одна транзакция.** Проверки, которые должны оставаться
  верными до коммита (права роли, «это не admin»), идут под `RoleRepository::lock`.
- **Администрирование в scope**: `roles.assign` проверяется в том scope, куда
  назначают, поэтому админ раздела раздаёт роли только у себя.
- **Аудит в той же транзакции**: каждое изменение доступа и действия самого
  пользователя пишутся через `AuditRepository::record` перед `commit`. Коды —
  в `service::audit_actions`.
- **Ротация refresh-токена с защитой от повторного использования**: если
  предъявлен уже отозванный токен — это признак кражи, отзываются все сессии
  пользователя.
- **Вход не подсказывает, есть ли такой email** — неверный пароль, неизвестный
  email и мусорный ввод дают одинаковый `InvalidCredentials`, с `verify_dummy`
  на «пустых» ветках для выравнивания времени ответа.
- **Отзыв сессии и деактивация пользователя действуют мгновенно** —
  `authenticate` каждый раз перепроверяет сессию и пользователя, а не просто
  доверяет непросроченному JWT.

## Тесты

```powershell
cargo test -p auth-core
cargo clippy -p auth-core -- -D warnings
```

Все use-case'ы тестируются на in-memory заглушках (`testing.rs`), без БД.
