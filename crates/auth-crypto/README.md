# auth-crypto

Реализации крипто-портов `auth-core`.

- `Argon2PasswordHasher` — Argon2id, параметры (`m_cost`/`t_cost`/`p_cost`)
  настраиваются через `Argon2Config`. Хеш CPU-тяжёлый, поэтому каждый вызов
  уходит в `spawn_blocking`. `verify_dummy` считает хеш от dummy-пароля один
  раз при старте и сверяется с ним — время ответа на несуществующий email не
  отличается от времени на неверный пароль.
- `JwtCodec` — HS256. Срок жизни токена (`exp`) проверяется вручную по
  переданному `now`, а не системными часами — так `authenticate` в core
  остаётся детерминированно тестируемым.
- `Sha256RefreshTokenProvider` — 32 случайных байта (base64url), в БД
  хранится SHA-256 от токена, не сам токен.

## Тесты

```powershell
cargo test -p auth-crypto
cargo clippy -p auth-crypto -- -D warnings
```
