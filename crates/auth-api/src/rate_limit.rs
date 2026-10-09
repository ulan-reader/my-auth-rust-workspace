use std::sync::Arc;

use serde::Deserialize;
use tower_governor::{governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor};

fn default_per_second() -> u64 {
    2
}
fn default_burst_size() -> u32 {
    5
}

/// Квота: `burst_size` запросов можно отправить сразу, дальше — по одному
/// каждые `per_second` секунд. `SmartIpKeyExtractor` сначала смотрит
/// X-Forwarded-For/X-Real-IP (для работы за reverse-proxy типа Caddy), и
/// только если их нет — берёт реальный peer IP соединения.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub per_second: u64,
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: default_per_second(),
            burst_size: default_burst_size(),
        }
    }
}

pub type Governor = tower_governor::governor::GovernorConfig<
    SmartIpKeyExtractor,
    governor::middleware::NoOpMiddleware,
>;

pub fn build(cfg: &RateLimitConfig) -> Arc<Governor> {
    Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(cfg.per_second)
            .burst_size(cfg.burst_size)
            .finish()
            .expect("валидная конфигурация rate-limit (per_second > 0)"),
    )
}
