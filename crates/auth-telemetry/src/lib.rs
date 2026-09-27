//! Инициализация tracing -> OTLP/HTTP -> Jaeger. `otlp_endpoint` — база без пути
//! (например `http://localhost:4318`), `/v1/traces` добавляется здесь.

use std::time::Duration;

use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use serde::Deserialize;
use thiserror::Error;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn default_enabled() -> bool {
    true
}
fn default_service_name() -> String {
    "auth-service".into()
}
fn default_otlp_endpoint() -> String {
    "http://localhost:4318".into()
}
fn default_sample_ratio() -> f64 {
    1.0
}
fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub service_name: String,
    /// База без пути, напр. `http://localhost:4318`.
    pub otlp_endpoint: String,
    pub sample_ratio: f64,
    /// Директива для `EnvFilter`, напр. `info` или `auth_core=debug,info`.
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            service_name: default_service_name(),
            otlp_endpoint: default_otlp_endpoint(),
            sample_ratio: default_sample_ratio(),
            log_level: default_log_level(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("не удалось собрать OTLP-экспортёр: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
    #[error("подписчик tracing уже инициализирован")]
    AlreadyInit(#[from] tracing_subscriber::util::TryInitError),
}

/// Держи живым до конца процесса. `Drop` шлёт оставшиеся спаны перед выходом —
/// без этого хвост батча перед завершением процесса теряется.
pub struct TelemetryGuard(Option<SdkTracerProvider>);

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn init(cfg: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    let env_filter = EnvFilter::try_new(&cfg.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    if !cfg.enabled {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()?;
        return Ok(TelemetryGuard(None));
    }

    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(format!(
            "{}/v1/traces",
            cfg.otlp_endpoint.trim_end_matches('/')
        ))
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(Duration::from_secs(5))
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::TraceIdRatioBased(cfg.sample_ratio))
        .with_resource(
            Resource::builder()
                .with_service_name(cfg.service_name.clone())
                .build(),
        )
        .build();
    let tracer = provider.tracer("auth");

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;

    Ok(TelemetryGuard(Some(provider)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = TelemetryConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.otlp_endpoint, "http://localhost:4318");
    }

    // Инициализация подписчика — процесс-глобальная операция (try_init можно
    // вызвать один раз за весь тестовый бинарник), поэтому проверяем только
    // ветку enabled=false в одном тесте, не борясь за глобальное состояние с
    // остальными тестами workspace.
    #[test]
    fn init_disabled_does_not_panic() {
        let cfg = TelemetryConfig {
            enabled: false,
            ..Default::default()
        };
        let _ = init(&cfg);
    }
}
