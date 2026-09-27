# auth-core

Домен и use-case'ы. Ни sqlx, ни axum, ни argon2, ни jwt здесь нет — только
бизнес-правила и порты (трейты), которые реализуют адаптеры.

## Модули

- `domain.rs` — сущности (`User`, `Role`, `Permission`, `Session`) и
  валидируемые newtype'ы (`Email`, `RoleCode`, `ScopeId`, ...) — невалидное
  значение просто не может существовать, парсинг всегда через `parse()`.
- `error.rs` — единственный `AuthError` на весь домен.
- `ports.rs` — исходящие порты: `UserRepository`, `RoleRepository`,
  `SessionRepository`, `PasswordHasher`, `AccessTokenCodec`,
  `RefreshTokenProvider`, `SettingsRepository`, `Clock`.
- `service/` — use-case'ы: `AuthService` (login/refresh/logout/register),
  `AccessService` (проверка прав), `UserService`, `RoleService`,
  `SettingsService`.
- `testing.rs` (только `cfg(test)`) — in-memory заглушки всех портов.

## Особенности

- **Ротация refresh-токена с защитой от повторного использования**: если
  предъявлен уже отозванный токен — это признак кражи, отзываются все сессии
  пользователя.
- **Логин не подсказывает, есть ли такой email** — неверный пароль,
  неизвестный email и мусорный ввод дают одинаковый `InvalidCredentials`, с
  `verify_dummy` на «пустых» ветках для выравнивания времени ответа.
- **Отзыв сессии/деактивация пользователя действуют мгновенно** —
  `authenticate` каждый раз перепроверяет сессию и активность пользователя, а
  не просто доверяет непросроченному JWT.

## Тесты

```powershell
cargo test -p auth-core
cargo clippy -p auth-core -- -D warnings
```

Все use-case'ы тестируются на in-memory заглушках (`testing.rs`), без БД.
