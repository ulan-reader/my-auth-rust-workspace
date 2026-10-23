use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{extract::ConnectInfo, http::Request};
use governor::middleware::NoOpMiddleware;
use serde::Deserialize;
use tower_governor::{
    GovernorError,
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::KeyExtractor,
};

use crate::ConfigError;

fn default_per_second() -> u64 {
    2
}
fn default_burst_size() -> u32 {
    5
}

/// Квота: `burst_size` запросов сразу, дальше по одному каждые `per_second` секунд.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub per_second: u64,
    pub burst_size: u32,
    /// IP reverse-proxy, которым разрешено сообщать адрес клиента через
    /// `X-Forwarded-For`. Пусто -> заголовок игнорируется, ключ = IP соединения.
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: default_per_second(),
            burst_size: default_burst_size(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientIpKeyExtractor {
    trusted_proxies: Arc<[IpAddr]>,
}

impl ClientIpKeyExtractor {
    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_proxies.contains(ip)
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // ConnectInfo кладёт axum::serve(.., into_make_service_with_connect_info)
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;
        if !self.is_trusted(&peer) {
            return Ok(peer);
        }

        // Справа — то, что дописали наши прокси; первый недоверенный адрес и есть клиент.
        let chain: Vec<IpAddr> = req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        Ok(chain
            .into_iter()
            .rev()
            .find(|ip| !self.is_trusted(ip))
            .unwrap_or(peer))
    }
}

pub type Governor = GovernorConfig<ClientIpKeyExtractor, NoOpMiddleware>;

pub fn build(cfg: &RateLimitConfig) -> Result<Arc<Governor>, ConfigError> {
    let config = GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor {
            trusted_proxies: cfg.trusted_proxies.clone().into(),
        })
        .per_second(cfg.per_second)
        .burst_size(cfg.burst_size)
        .finish()
        .ok_or_else(|| {
            ConfigError("api.rate_limit: per_second и burst_size должны быть > 0".into())
        })?;

    // Без чистки таблица лимитера растёт на каждый новый IP бесконечно.
    let limiter = config.limiter().clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            limiter.retain_recent();
        }
    });

    Ok(Arc::new(config))
}
