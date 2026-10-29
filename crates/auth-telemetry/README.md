**English** | [Русский](README.ru.md) | [Қазақша](README.kk.md)

# auth-telemetry

Sets up `tracing` → OTLP/HTTP → Jaeger. Called once in `auth-server`; spans from
every crate (`#[instrument]` in `auth-core` and `auth-postgres`) reach the same
subscriber automatically — those crates only need `tracing`, nothing else in
their `Cargo.toml`.

`TelemetryConfig.enabled = false` gives plain fmt logs to the console without
OTLP (handy locally without a running Jaeger).

```powershell
cargo test -p auth-telemetry
cargo clippy -p auth-telemetry -- -D warnings
```
