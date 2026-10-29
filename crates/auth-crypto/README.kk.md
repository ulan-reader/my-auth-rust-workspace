[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# auth-crypto

`auth-core` крипто-порттарының іске асырылуы.

- `Argon2PasswordHasher` — Argon2id, параметрлері (`m_cost` / `t_cost` /
  `p_cost`) `Argon2Config` арқылы бапталады. Хештеу процессорды көп жүктейді,
  сондықтан әр шақыру `spawn_blocking`-ке жіберіледі. `verify_dummy` іске
  қосылғанда жалған құпиясөздің хешін бір рет есептеп, онымен салыстырады —
  жоқ email-ге жауап беру уақыты қате құпиясөзге жауап беру уақытынан
  ерекшеленбейді.
- `JwtCodec` — EdDSA (Ed25519): access-токендерге ағымдағы кілтпен қол қояды
  (тақырыпта `kid`) және ротация кезінде `extra_verification_keys` кілттерін де
  қабылдайды. Ашық кілттерді JWKS пішімінде береді (`jwks()`). Токен мерзімі
  (`exp`) жүйелік сағатпен емес, берілген `now` бойынша қолмен тексеріледі —
  осылайша core ішіндегі `authenticate` детерминистік түрде тексеріле береді.
- `Ed25519Verifier` — тек тексеру, жеке кілтсіз: басқа сервистер үшін JWKS-тен
  (`from_jwks_json`) жиналады.
- `generate_signing_key()` — жаңа Ed25519 seed және ашық кілт (base64url);
  `auth-server jwt-keygen` осыған сүйенеді.
- `Sha256RefreshTokenProvider` — 32 кездейсоқ байт (base64url); дерекқорда
  токеннің өзі емес, оның SHA-256 хеші сақталады.

## Тесттер

```powershell
cargo test -p auth-crypto
cargo clippy -p auth-crypto -- -D warnings
```
