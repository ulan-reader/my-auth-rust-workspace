[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# Auth Workspace

Rust тіліндегі гексагоналды аутентификация және авторизация сервисі:
пайдаланушылар, рөлдер (жаһандық және әрекет аумағы бар — `scope`), рұқсаттар,
refresh-токендері ротацияланатын сессиялар, аудит журналы және қайта
орналастырусыз өзгертілетін runtime-баптаулар (мысалы, өзін-өзі тіркеуді қосу).

Бұл ең алдымен кітапхана: оны кез келген Rust + Axum сервисіне енгізуге, порттарды
өз қоймаңызға іске асыруға немесе дайын HTTP-серверді жай ғана іске қосуға болады.

## Пайдаланудың үш тәсілі

| Тәсіл | Не аласыз | Қашан |
|---|---|---|
| **Кітапхана, өз қоймаңыз** | `auth-core` + оның порттарын өзіңіз іске асырасыз | дерекқормен жұмыс қабаты бар, тек ережелер керек |
| **Кітапхана, дайын қойма** | `auth-core` + `auth-postgres` + `auth-crypto` | авторизацияны Rust-сервисіңізге арада HTTP-сыз енгізу |
| **Сервер** | `auth-server` (Docker бейнесі) | кез келген тіл; HTTP арқылы байланыс, JWT-ны JWKS бойынша тексеру |

## Архитектура

```
                     ┌─────────────┐
                     │  auth-core  │  домен, порттар (трейттер), use-case'тер
                     └──────┬──────┘  sqlx, axum, argon2 жоқ — тек домен
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐  ┌────────▼───────┐  ┌────────▼───────┐
│ auth-postgres │  │  auth-crypto   │  │ auth-telemetry │
│(ДҚ адаптері)  │  │ Argon2/JWT/RT  │  │ tracing→Jaeger │
└───────┬───────┘  └────────┬───────┘  └────────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                     ┌──────▼──────┐
                     │  auth-api   │  core үстіндегі axum-роутер (DTO, HTTP-қателер)
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ auth-server │  composition root: конфиг → жинау → іске қосу
                     └─────────────┘
```

Тәуелділіктер тек ішке қарай бағытталған; `auth-postgres`, `auth-crypto` және
`auth-telemetry` бір-бірі туралы білмейді. Кез келген адаптерді қалғанына
тиіспей ауыстыруға болады — мысалы, сол порттарды (`crates/auth-core/src/ports.rs`)
іске асырып, Postgres орнына SQLite қолдану.

## Крейттер

| Крейт | Не істейді | README |
|---|---|---|
| `auth-core` | Домен, порттар, use-case'тер (`AuthService`, `UserService`, `RoleService`, `AccessService`, `SettingsService`, `AuditService`, `SetupService`) | [crates/auth-core](crates/auth-core/README.kk.md) |
| `auth-postgres` | sqlx/Postgres-тегі порттар, транзакциялар, миграциялар | [crates/auth-postgres](crates/auth-postgres/README.kk.md) |
| `auth-crypto` | Argon2id, JWT (EdDSA/Ed25519) + JWKS, refresh-токендер | [crates/auth-crypto](crates/auth-crypto/README.kk.md) |
| `auth-telemetry` | tracing → OTLP/HTTP → Jaeger | [crates/auth-telemetry](crates/auth-telemetry/README.kk.md) |
| `auth-api` | core үстіндегі axum-роутер, DTO, HTTP қате кодтары, rate-limit, CORS, басқа сервистерге арналған жеңіл JWT-экстрактор | [crates/auth-api](crates/auth-api/README.kk.md) |
| `auth-server` | Бәрін біріктіреді, HTTP-ны іске қосады, CLI (`jwt-keygen`) | [crates/auth-server](crates/auth-server/README.kk.md) |

`apps/admin-ui` — Leptos (CSR) негізіндегі әкімші интерфейсі. Ол workspace-ке
кірмейді, `trunk` арқылы бөлек жиналады және әзірге дайындама күйінде.

## Жылдам бастау (Docker)

Тек Docker керек — машинада Rust пен C++ build tools қажет емес.

```powershell
copy .env.example .env

# JWT қолтаңба кілтін жасап, шығысын .env ішіне жазыңыз
docker compose --profile dev run --rm auth-dev cargo run -p auth-server -- jwt-keygen

# .env ішіне AUTH__SETUP__TOKEN жазыңыз (кемінде 32 таңба), мысалы мына команданың шығысы:
#   openssl rand -base64 32

# Postgres + Jaeger + файлды сақтаған сайын қайта жиналатын сервер
docker compose --profile dev up
```

Сервер — `http://localhost:8080`, Jaeger UI — `http://localhost:16686`.

### Алғашқы әкімші

API арқылы бір рет жасалады, CLI керек емес:

```powershell
Invoke-RestMethod http://localhost:8080/setup        # {"required": true}

Invoke-RestMethod -Method Post -Uri http://localhost:8080/setup -ContentType "application/json" `
  -Body (@{ setup_token = "<AUTH__SETUP__TOKEN>"; email = "admin@example.com"; password = "super-secret-1";
            first_name = "Admin"; second_name = "Root" } | ConvertTo-Json)    # 201
```

Осыдан кейін `/setup` біржола жабылады (дерекқордағы белгі): қайталанған және
қатар жіберілген сұраныстар `404` алады, `GET /setup` `{"required": false}`
қайтарады. `AUTH__SETUP__TOKEN` берілмесе, эндпоинт өшірулі. Баптаудан кейін
айнымалыны жоюға болады.

| Команда | Нені іске қосады |
|---|---|
| `docker compose up -d` | тек Postgres (2134 порты) және Jaeger |
| `docker compose --profile dev up` | + `auth-dev`: бастапқы код хосттан тіркеледі, `cargo watch` сақтаған сайын серверді қайта жинап, қайта қосады |
| `docker compose --profile prod up -d --build` | + `auth`: прод-бейне (`Dockerfile`, `runtime` мақсаты) |

Прод-бейне тәуелділіктерді бөлек қабатта кэштейді (`cargo-chef`): өз кодыңызды
өзгерту тек workspace крейттерін қайта жинайды. Миграциялар бинарьға енгізілген
және іске қосылғанда қолданылады.

## Docker-сіз іске қосу

Rust 1.98.1+ және (Windows-та) Visual Studio C++ build tools керек.

```powershell
docker compose up -d                                   # Postgres + Jaeger
copy .env.example .env                                 # JWT кілті мен AUTH__SETUP__TOKEN толтырыңыз
cargo run -p auth-server -- jwt-keygen                 # шығысы — .env ішіне
cargo run -p auth-server                               # 127.0.0.1:8080 тыңдайды
```

Алғашқы әкімші — жоғарыдағыдай `POST /setup` арқылы.

## Конфигурация

`config/default.toml` → `config/{AUTH_ENV}.toml` (әдепкі `AUTH_ENV=dev`,
прод-бейнеде `prod`) → `AUTH__БӨЛІМ__КІЛТ` орта айнымалылары. Құпиялар тек орта
арқылы (`.env`) беріледі, конфиг файлдарына жазылмайды:

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<base64url Ed25519 seed, jwt-keygen-нен>
AUTH__CRYPTO__JWT__KID=<кілт идентификаторы, мысалы күн>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
AUTH__SETUP__TOKEN=<тек бастапқы баптауға>
```

Барлық бөлім [crates/auth-server](crates/auth-server/README.kk.md) ішінде сипатталған.

## Сұраныс мысалдары

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body (@{ email = "admin@example.com"; password = "super-secret-1" } | ConvertTo-Json)).access_token
$auth = @{ Authorization = "Bearer $token" }

Invoke-RestMethod -Uri http://localhost:8080/users -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/auth/me/permissions?scope=space:wiki" -Headers $auth
Invoke-RestMethod -Uri "http://localhost:8080/audit?action=role.assign" -Headers $auth
```

Маршруттардың толық тізімі — [crates/auth-api](crates/auth-api/README.kk.md) ішінде.

## Рұқсаттар моделі

- **Жаһандық рөл** (`RoleScope::Global`) — рұқсаттары барлық жерде әрекет етеді.
- **Әрекет аумағы бар рөл** (`RoleScope::Scoped`) — рұқсаттары тек нақты
  `scope` ішінде әрекет етеді (`space:wiki`, `project:42` сияқты мөлдір емес жол;
  оның мағынасын тұтынушы сервис шешеді, auth-қа бұл маңызды емес).
- Scope ішіндегі рұқсаттар — **жаһандық рұқсаттар плюс дәл осы scope ішінде
  тағайындалғандары**. Сәйкестік ережесі (`RoleScope::check_assignment`)
  хендлерлерде емес, доменде тұрады.
- **Бөлім әкімшілері**: `space:wiki` ішінде берілген `roles.assign` рөлдерді тек
  `space:wiki` ішінде таратуға мүмкіндік береді — басқа бөлімдерде емес және
  жаһандық рөлдерді емес.
- Жүйеге кірген пайдаланушыға өз рұқсаттарын білу үшін ешқандай рұқсат керек
  емес: `GET /auth/me/permissions?scope=...`. Клиент (мысалы, вики) жауапқа
  қарап, қандай батырмаларды көрсету керегін шешеді.

### Өз рұқсаттарыңыз

Тұтынушы сервистер өз рұқсаттарын auth дерекқорындағы миграциямен тіркейді:

```sql
select register_permission('wiki.article.delete', 'Кез келген мақаланы жою');
```

Функция кодты тексереді және идемпотентті. `admin` рөлі жаңа рұқсатты
триггер арқылы өзі алады; қалғандары — рөл арқылы.

### Артықшылықты асыра пайдаланудан қорғау

- **Өзіңде барынан артық беруге болмайды.** Рөлді тағайындау, алып тастау,
  өзгерту немесе жою үшін оның барлық рұқсаты сізде болуы керек; рөлге рұқсаттар
  жиынын беру үшін ескі де, жаңа да рұқсаттар сізде болуы керек.
- **Өзіңнен күштірек пайдаланушыны басқаруға болмайды.** Құпиясөзді ауыстыру,
  бұғаттау, өзгерту немесе жою тек жаһандық рұқсаттары сіздің рұқсаттарыңызға
  кіретін пайдаланушыға ғана рұқсат етілген.
- **`admin` — жүйелік рөл**: оның әрқашан барлық рұқсаты бар (жаңалары да,
  триггер арқылы); оны жоюға, кодын өзгертуге немесе рұқсаттар жиынын
  түзетуге болмайды.
- **Соңғы әкімшіге қол сұғуға болмайды**: одан рөлді алып тастау, оны бұғаттау
  немесе жою мүмкін емес — тексеру ортақ бұғаттау астында транзакцияда жүреді,
  сондықтан қатар сұраныстар да жүйені әкімшісіз қалдыра алмайды.

## Транзакциялар

Әр use-case — бір транзакция (`UnitOfWork::begin` → репозиторийлерді шақыру →
`commit`). Кез келген қадамдағы қате — `commit` болмайды, транзакция drop кезінде
кері қайтарылады. Commit-ке дейін дұрыс болып қалуы керек тексерулер (рөлдің
рұқсаттары, «бұл admin емес») жол бұғатталған күйде (`RoleRepository::lock`)
жүреді, сондықтан бір рөлді қатар өзгерту кезекпен орындалады.

## Аудит журналы

Қол жеткізудің әр өзгерісі `audit_events` кестесіне **өзгерістің өзімен бір
транзакцияда** жазылады: өзгеріс жоқ — жазба жоқ; жазу сәтсіз болса —
өзгеріс кері қайтарылады. Кесте тек толықтырылады (`UPDATE`, `DELETE` және
`TRUNCATE` триггермен тыйым салынған).

- Әкімші әрекеттері: рөлдер (жасау, өзгерту, жою, рұқсаттар, scope-пен
  тағайындау және алып тастау), пайдаланушылар (жасау, өзгерту, құпиясөз,
  белсендіру және өшіру, жою), баптаулар, бастапқы баптау.
- Пайдаланушының өз әрекеттері: тіркелу, кіру, шығу, барлық құрылғылардан шығу,
  өз құпиясөзін ауыстыру, кері шақырылған refresh-токенді қайта ұсыну (`actor`
  бос — бұл жүйенің реакциясы).
- Жазылмайды: сәтсіз кірулер (олардан rate-limit және WARN логтары қорғайды),
  токендерді әдеттегі жаңарту, қабылданбаған сұраныстар.
- Мәліметтер — сервис анық салатын жай жолдар: құпиясөздер, хештер мен
  токендер оған түспейді.

Оқу — `GET /audit?actor_id=&action=&target_type=&target_id=&page=&per_page=`
(`audit.view` рұқсаты), жаңалары жоғарыда.

## Runtime-баптаулар

Мінез-құлықтың бір бөлігі (қазір — `allow_self_registration`) конфигте емес,
дерекқорда сақталады және `GET/PUT /settings` арқылы (`settings.manage` рұқсаты)
қайта орналастырусыз және қайта іске қосусыз өзгереді.

## Басқа сервистерге

- **Толық интеграция**: `auth-core` + `auth-postgres` + `auth-crypto`
  кітапханаларын тікелей Rust-сервисіңізге қосу (HTTP мүлдем жоқ).
- **Дерекқорсыз жеңіл токен тексеру**: `auth_api::extract::{JwtVerifier,
  RemoteAuthCtx}` + `auth_crypto::Ed25519Verifier` — JWT қолтаңбасы мен
  мерзімін `GET /.well-known/jwks.json` ашық кілттері бойынша тексеру, жеке кілт
  керек емес. Сессияны лезде кері шақыру бұл жағдайда ескерілмейді — токен өз
  `exp` уақытына дейін өмір сүреді (әдепкі 15 минут).
- **HTTP арқылы**: `Authorization: Bearer` бар `auth-server`-ге қарапайым
  сұраныстар; интерфейске арналған рұқсаттар —
  `GET /auth/me/permissions?scope=...` арқылы.

## Әзірлеу

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # auth-postgres интеграциялық тесттеріне Docker керек
```

Дәл осыны CI (`.github/workflows/ci.yml`) `main`-ға әр push кезінде және PR-да
орындайды, оған қоса `cargo audit` және прод-бейнені жинау.

Жергілікті Rust болмаса, тесттер Docker-де іске қосылады (Git Bash):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src:ro" -v //var/run/docker.sock:/var/run/docker.sock -e CARGO_TARGET_DIR=/tmp/target -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway -w /src rust:1.98-slim-bookworm cargo test --workspace
```

## Күйі

0.2.0 нұсқасы, 1.0-ге дейін: крейттердің API-і кіші нұсқалар арасында әлі
өзгеруі мүмкін; әр үйлесімсіз өзгеріс [CHANGELOG.kk.md](CHANGELOG.kk.md) ішінде
көрсетілген. In-memory жалғандарындағы юнит-тесттер мен нақты Postgres-тегі
(`testcontainers`) интеграциялық тесттер ядро мен қойманы қамтиды; HTTP қабатының
өз тесттері әзірге жоқ. `apps/admin-ui` — дайындама.

Әзірге жасалмаған: email растау және құпиясөзді қалпына келтіру, сәтсіз
кірулерден кейін аккаунтты бұғаттау, өз сессияларыңыздың тізімі, OpenAPI
сипаттамасы, аудитті мерзім бойынша сақтау.

## Лицензия

Қос лицензия: [MIT](LICENSE-MIT) немесе [Apache-2.0](LICENSE-APACHE) — пайдаланушының таңдауы бойынша.
