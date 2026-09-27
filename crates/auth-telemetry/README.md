# auth-telemetry

Инициализация `tracing` → OTLP/HTTP → Jaeger. Вызывается один раз в
`auth-server`; спаны из всех крейтов (`#[instrument]` в `auth-core` и
`auth-postgres`) утекают в тот же подписчик автоматически — им для этого
ничего в `Cargo.toml` добавлять не нужно, только `tracing`.

`TelemetryConfig.enabled = false` — просто fmt-логи в консоль, без OTLP
(удобно для локалки без поднятого Jaeger).

```powershell
cargo test -p auth-telemetry
cargo clippy -p auth-telemetry -- -D warnings
```
