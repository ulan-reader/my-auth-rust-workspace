use std::net::SocketAddr;

use auth_core::{AuthError, service::AuthPolicy};
use auth_crypto::CryptoConfig;
use auth_postgres::PostgresConfig;
use auth_telemetry::TelemetryConfig;
use chrono::TimeDelta;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

fn default_access_ttl() -> i64 {
    900
}
fn default_refresh_ttl() -> i64 {
    2_592_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthPolicyConfig {
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
}

impl Default for AuthPolicyConfig {
    fn default() -> Self {
        Self {
            access_ttl_secs: default_access_ttl(),
            refresh_ttl_secs: default_refresh_ttl(),
        }
    }
}

impl AuthPolicyConfig {
    pub fn build(&self) -> Result<AuthPolicy, AuthError> {
        let access = TimeDelta::try_seconds(self.access_ttl_secs)
            .ok_or_else(|| AuthError::validation("access_ttl_secs вне диапазона"))?;
        let refresh = TimeDelta::try_seconds(self.refresh_ttl_secs)
            .ok_or_else(|| AuthError::validation("refresh_ttl_secs вне диапазона"))?;
        AuthPolicy::new(access, refresh)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub api: auth_api::ApiConfig,
    pub postgres: PostgresConfig,
    #[serde(default)]
    pub auth: AuthPolicyConfig,
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}
