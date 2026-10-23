# auth-crypto

Реализации крипто-портов `auth-core`.

- `Argon2PasswordHasher` — Argon2id, параметры (`m_cost`/`t_cost`/`p_cost`)
  настраиваются через `Argon2Config`. Хеш CPU-тяжёлый, поэтому каждый вызов
  уходит в `spawn_blocking`. `verify_dummy` считает хеш от dummy-пароля один
  раз при старте и сверяется с ним — время ответа на несуществующий email не
  отличается от времени на неверный пароль.
- `JwtCodec` — EdDSA (Ed25519): подписывает access-токены текущим ключом
  (`kid` в заголовке) и принимает ещё и ключи из `extra_verification_keys` —
  на время ротации. Публичные ключи отдаёт в формате JWKS (`jwks()`).
  Срок жизни токена (`exp`) проверяется вручную по переданному `now`, а не
  системными часами — так `authenticate` в core остаётся детерминированно
  тестируемым.
- `Ed25519Verifier` — только проверка, без приватного ключа: собирается из
  JWKS (`from_jwks_json`) для сторонних сервисов.
- `generate_signing_key()` — новый seed Ed25519 и публичный ключ (base64url),
  за ней стоит `auth-server jwt-keygen`.
- `Sha256RefreshTokenProvider` — 32 случайных байта (base64url), в БД
  хранится SHA-256 от токена, не сам токен.

## Тесты

```powershell
cargo test -p auth-crypto
cargo clippy -p auth-crypto -- -D warnings
```
