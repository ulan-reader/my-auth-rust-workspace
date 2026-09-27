# auth-server

Composition root: единственный бинарь в workspace. Читает конфиг, собирает
адаптеры (`auth-postgres`/`auth-crypto`) за портами `auth-core`, поднимает
`auth-api` через axum.

## Конфиг

`config/default.toml` (+ `config/{AUTH_ENV}.toml`, дефолт `AUTH_ENV=dev`) +
переменные окружения `AUTH__SECTION__KEY` (двойное подчёркивание —
разделитель). `.env` в корне репо подхватывается через `dotenvy`.

Обязательные секреты (только через env, не в файл):

```
AUTH__POSTGRES__URL=postgres://...
AUTH__CRYPTO__JWT__SECRET=<минимум 32 байта>
AUTH__CRYPTO__JWT__ISSUER=...
AUTH__CRYPTO__JWT__AUDIENCE=...
```

## CLI

```powershell
cargo run -p auth-server                                    # запуск сервера
cargo run -p auth-server -- bootstrap-admin --email .. --password ..
```

`bootstrap-admin` создаёт первого администратора в обход проверки прав
(иначе создать первого пользователя некому — `POST /users` сам требует уже
залогиненного админа). Идемпотентна, безопасно перезапускать.

## Docker

`docker-compose.yml` в корне репо: Postgres + Jaeger (`http://localhost:16686`).
