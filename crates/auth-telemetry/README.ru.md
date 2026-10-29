[English](README.md) | **Русский** | [Қазақша](README.kk.md)

# auth-telemetry

Инициализация `tracing` → OTLP/HTTP → Jaeger. Вызывается один раз в
`auth-server`; спаны из всех крейтов (`#[instrument]` в `auth-core` и
`auth-postgres`) попадают в тот же подписчик автоматически — этим крейтам нужен
только `tracing`, больше ничего в `Cargo.toml` добавлять не надо.

`TelemetryConfig.enabled = false` — просто fmt-логи в консоль, без OTLP
(удобно локально без поднятого Jaeger).

```powershell
cargo test -p auth-telemetry
cargo clippy -p auth-telemetry -- -D warnings
```
