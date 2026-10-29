[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# auth-core

Домен және use-case'тер. Мұнда sqlx, axum, argon2 немесе jwt жоқ — тек бизнес
ережелері және адаптерлер іске асыратын порттар (трейттер).

## Модульдер

- `domain.rs` — нысандар (`User`, `Role`, `Permission`, `Session`) және
  тексерілетін newtype'тар (`Email`, `RoleCode`, `PermissionCode`, `ScopeId`, ...):
  жарамсыз мән мүлдем бола алмайды, талдау әрқашан `parse()` арқылы жүреді.
- `error.rs` — бүкіл доменге ортақ жалғыз `AuthError`.
- `ports.rs` — шығыс порттары:
  - транзакциялар: `UnitOfWork` (`begin`) және `Tx` (`commit`, drop кезінде кері қайтару);
  - сақтау: `UserRepository`, `RoleRepository` (соның ішінде `lock`),
    `AssignmentRepository`, `PermissionRepository`, `SessionRepository`,
    `SettingsRepository`, `SetupRepository`, `AuditRepository`;
  - крипто және уақыт: `PasswordHasher`, `AccessTokenCodec` / `AccessTokenVerifier`,
    `RefreshTokenProvider`, `Clock`.
- `service/` — use-case'тер: `AuthService` (кіру, refresh, шығу, тіркелу, өз
  құпиясөзін ауыстыру), `AccessService` (рұқсаттарды тексеру, өз рұқсаттары),
  `UserService`, `RoleService`, `SettingsService`, `SetupService`, `AuditService`
  (аудит журналын оқу). `Ports` барлық портты `Service::from_ports` үшін жинайды.
- `testing.rs` (тек `cfg(test)`) — барлық порттың in-memory жалғандары.

## Адаптерлерге арналған келісімдер

- Жазатын әдістер `&mut dyn Tx` қабылдайды және өздері commit жасамайды; оқитын
  әдістер транзакцияны айналып өтеді және оның commit жасалмаған өзгерістерін
  көрмейді.
- Әдіс қате қайтарса, шақырушы commit жасамайды — транзакция drop кезінде кері
  қайтарылады.
- «Жазба жоқ»: `find_*` үшін `Ok(None)`, нақты жазбаға қатысты операциялар үшін
  `Err(NotFound)`; бірегейлікті бұзу → `Conflict`, сынған сілтеме →
  `Validation`, қалғаны → `AuthError::internal(..)`.
- `Tx`-ті тек оны жасаған адаптердің репозиторийлеріне беруге болады.

## Ерекшеліктер

- **Бір use-case — бір транзакция.** Commit-ке дейін дұрыс болып қалуы керек
  тексерулер (рөлдің рұқсаттары, «бұл admin емес») `RoleRepository::lock`
  астында жүреді.
- **Scope ішіндегі әкімшілік**: `roles.assign` рөл тағайындалатын scope ішінде
  тексеріледі, сондықтан бөлім әкімшісі рөлдерді тек өз бөлімінде береді.
- **Аудит сол транзакцияда**: қол жеткізудің әр өзгерісі мен пайдаланушының өз
  әрекеттері `commit`-ке дейін `AuditRepository::record` арқылы жазылады.
  Кодтар — `service::audit_actions` ішінде.
- **Қайта пайдаланудан қорғалған refresh-токен ротациясы**: бұрын кері
  шақырылған токен ұсынылса, бұл ұрлықтың белгісі — пайдаланушының барлық
  сессиясы кері шақырылады.
- **Кіру email-дің бар-жоғын білдірмейді** — қате құпиясөз, белгісіз email және
  мағынасыз енгізу бірдей `InvalidCredentials` береді, жауап уақытын теңестіру
  үшін «бос» тармақтарда `verify_dummy` орындалады.
- **Сессияны кері шақыру және пайдаланушыны өшіру лезде әрекет етеді** —
  `authenticate` мерзімі өтпеген JWT-ға жай сенбей, әр шақыруда сессия мен
  пайдаланушыны қайта тексереді.

## Тесттер

```powershell
cargo test -p auth-core
cargo clippy -p auth-core -- -D warnings
```

Барлық use-case дерекқорсыз, in-memory жалғандарында (`testing.rs`) тексеріледі.
