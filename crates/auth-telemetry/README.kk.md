[English](README.md) | [Русский](README.ru.md) | **Қазақша**

# auth-telemetry

`tracing` → OTLP/HTTP → Jaeger баптауы. `auth-server` ішінде бір рет
шақырылады; барлық крейттің спандары (`auth-core` және `auth-postgres` ішіндегі
`#[instrument]`) сол жазылушыға автоматты түрде түседі — бұл крейттерге тек
`tracing` керек, `Cargo.toml`-ға басқа ештеңе қосудың қажеті жоқ.

`TelemetryConfig.enabled = false` — OTLP-сыз, консольге қарапайым fmt-логтар
(Jaeger көтерілмеген жергілікті ортада ыңғайлы).

```powershell
cargo test -p auth-telemetry
cargo clippy -p auth-telemetry -- -D warnings
```
