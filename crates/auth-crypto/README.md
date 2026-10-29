**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-crypto

Implementations of the `auth-core` crypto ports.

- `Argon2PasswordHasher` — Argon2id; the parameters (`m_cost` / `t_cost` /
  `p_cost`) are set through `Argon2Config`. Hashing is CPU-heavy, so every call
  goes to `spawn_blocking`. `verify_dummy` computes the hash of a dummy password
  once at start-up and verifies against it — the response time for a
  non-existent email matches the one for a wrong password.
- `JwtCodec` — EdDSA (Ed25519): signs access tokens with the current key (`kid`
  in the header) and also accepts the keys from `extra_verification_keys` during
  rotation. Publishes the public keys as JWKS (`jwks()`). Token expiry (`exp`) is
  checked by hand against the passed `now`, not the system clock — so
  `authenticate` in core stays deterministically testable.
- `Ed25519Verifier` — verification only, no private key: built from JWKS
  (`from_jwks_json`) for other services.
- `generate_signing_key()` — a new Ed25519 seed and its public key (base64url);
  it backs `auth-server jwt-keygen`.
- `Sha256RefreshTokenProvider` — 32 random bytes (base64url); the DB stores the
  SHA-256 of the token, never the token itself.

## Tests

```powershell
cargo test -p auth-crypto
cargo clippy -p auth-crypto -- -D warnings
```
