[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# auth-server

Composition root және workspace-тегі жалғыз бинарь. Конфигті оқиды,
адаптерлерді (`auth-postgres`, `auth-crypto`) `auth-core` порттарының артына
жинайды, axum арқылы `auth-api` іске қосады, JWKS пен health-check береді.

## Конфигурация

`config/default.toml` (+ `config/{AUTH_ENV}.toml`, әдепкі `AUTH_ENV=dev`) +
`AUTH__SECTION__KEY` орта айнымалылары (қос астын сызу — бөлгіш). Репозиторий
түбіріндегі `.env` `dotenvy` арқылы жүктеледі; үлгісі — `.env.example`.

Міндетті құпиялар (тек орта арқылы, файлға емес):

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SIGNING_KEY=<32 байттық Ed25519 seed, base64url>
AUTH__CRYPTO__JWT__KID=<кілт идентификаторы>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
AUTH__SETUP__TOKEN=<кемінде 32 таңба, тек бастапқы баптауға>
```

Қалған бөлімдер (`config/default.toml`):

| Бөлім | Кілттер | Ескертпе |
|---|---|---|
| `server` | `bind` | Docker-де — `0.0.0.0:8080` |
| `api` | `request_timeout_secs`, `allowed_origins` | бос `allowed_origins` браузерден басқа доменге сұраныстарға тыйым салады; тек `http(s)://хост[:порт]` рұқсат, жарамсыз origin серверді іске қоспайды |
| `api.rate_limit` | `per_second`, `burst_size`, `trusted_proxies` | қосылыс IP-і бойынша `/auth/login`, `/auth/register`, `/auth/me/password` және `/setup` шектеуі; `X-Forwarded-For` тек `trusted_proxies` проксилерінен ескеріледі |
| `auth` | `access_ttl_secs`, `refresh_ttl_secs` | 15 минут / 30 күн |
| `crypto.argon2` | `m_cost_kib`, `t_cost`, `p_cost`, `max_concurrent` | әдепкілер — OWASP минимумы; `max_concurrent` (әдепкі — ядролар саны) бір мезгілдегі хештерді шектейді, жадтың шыңы ≈ `max_concurrent × m_cost_kib` |
| `setup` | `token` | тек `AUTH__SETUP__TOKEN` арқылы; берілмесе — `/setup` өшірулі; 32 таңбадан қысқа болса — сервер іске қосылмайды |
| `crypto.jwt` | `extra_verification_keys` | кілт ротациясы кезіндегі ескі ашық кілттер |
| `postgres` | `max_connections`, `min_connections`, `acquire_timeout_secs` | |
| `maintenance` | `session_cleanup_interval_secs`, `session_retention_secs` | өлі сессияларды фондық тазалау |
| `telemetry` | `enabled`, `service_name`, `otlp_endpoint`, `sample_ratio`, `log_level` | |

## CLI

```powershell
cargo run -p auth-server                                    # серверді іске қосу
cargo run -p auth-server -- jwt-keygen
```

`jwt-keygen` жаңа Ed25519 кілтін (`SIGNING_KEY`) және оның ашық бөлігін
шығарады. Оған конфиг те, дерекқор да керек емес. Ротация кезінде ескі ашық
кілт ескі `kid` астында `crypto.jwt.extra_verification_keys` ішіне салынады,
сонда бұрын берілген токендер өз TTL-ін аяқтайды.

## Бастапқы баптау

Алғашқы әкімшіні `POST /setup` (`AUTH__SETUP__TOKEN` құпиясы) дәл бір рет
жасайды: бір транзакцияда барлық рұқсаты бар `admin` рөлі, пайдаланушы және
тағайындау жасалады, `app_settings.setup_completed_at` белгісі қойылады және
аудит журналына `setup.complete` жазылады. Қатар сұраныстар баптаулар жолын
бұғаттау арқылы кезекке тұрады — дәл біреуі өтеді. Әкімші бұрыннан бар
дерекқорларды `setup` миграциясы бапталған деп белгілейді. Толығырақ — түбірлік
README ішінде.

## Қызметтік эндпоинттер

- `GET /.well-known/jwks.json` — JWT тексеруге арналған ашық кілттер, аутентификациясыз.
- `GET /health/live` — процесс тірі (дерекқорға жүгінбейді).
- `GET /health/ready` — Postgres қолжетімді, әйтпесе `503`.

## Өмірлік цикл

- Миграциялар іске қосылғанда қолданылады.
- Фондық процесс `session_retention_secs`-тен ескі мерзімі өткен және кері
  шақырылған сессияларды жояды — іске қосылғанда бірден, содан кейін әр
  `session_cleanup_interval_secs` сайын. Сәтсіз өту логқа қате ретінде
  жазылады, процесс жұмысын жалғастырады.
- Ctrl+C және SIGTERM (`docker stop`, Kubernetes) — graceful shutdown: сервер
  ағымдағы сұраныстарды аяқтайды, тазалау процесі тоқтайды.

## Docker

Репозиторий түбіріндегі `Dockerfile`, екі мақсат:

- `dev` — тіркелген бастапқы код үстіндегі `cargo watch`, сақтаған сайын қайта жинау;
- `runtime` — `debian:bookworm-slim` негізіндегі прод-бейне, артықшылығы жоқ
  пайдаланушы, `AUTH_ENV=prod`.

Іске қосу — `docker-compose.yml` арқылы (`dev` / `prod` профильдері), түбірлік README қараңыз.
