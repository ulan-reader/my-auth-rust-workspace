//! auth-api — axum-роутер поверх auth-core. Ни sqlx, ни argon2, ни jwt здесь нет —
//! только use-case'ы core и HTTP-обвязка (DTO, коды ошибок, извлечение AuthCtx).

pub mod dto;
pub mod error;
pub mod extract;
pub mod rate_limit;
mod routes;

use std::sync::Arc;
use std::time::Duration;

use auth_core::{
    ports::PermissionRepository,
    service::{
        AccessService, AuthPolicy, AuthService, Ports, RoleService, SettingsService, SetupService,
        UserService,
    },
};
use axum::{
    Router,
    http::{HeaderValue, Method, header},
};
use rate_limit::RateLimitConfig;
use secrecy::SecretString;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::warn;

#[derive(Clone)]
pub struct ApiState {
    pub auth: AuthService,
    pub users: UserService,
    pub roles: RoleService,
    pub access: AccessService,
    pub permissions: Arc<dyn PermissionRepository>,
    pub settings: SettingsService,
    pub setup: SetupService,
}

impl ApiState {
    pub fn from_ports(
        ports: &Ports,
        policy: AuthPolicy,
        setup_token: Option<SecretString>,
    ) -> Self {
        Self {
            auth: AuthService::from_ports(ports, policy),
            users: UserService::from_ports(ports),
            roles: RoleService::from_ports(ports),
            access: AccessService::from_ports(ports),
            permissions: ports.permissions.clone(),
            settings: SettingsService::from_ports(ports),
            setup: SetupService::from_ports(ports, setup_token),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub request_timeout_secs: u64,
    /// Пусто -> CORS открыт для всех источников (годится для локальной разработки,
    /// в проде задай явный список: `["https://admin.example.com"]`).
    pub allowed_origins: Vec<String>,
    pub rate_limit: RateLimitConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: 15,
            allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Ошибка конфигурации API: сервер не должен стартовать с ней.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Только `http(s)://хост[:порт]`: без пути, '*', query и пробелов.
fn parse_origin(raw: &str) -> Result<HeaderValue, ConfigError> {
    let origin = raw.trim();
    let invalid = |why: &str| ConfigError(format!("api.allowed_origins: {origin:?} — {why}"));
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| invalid("нужна схема http:// или https://"))?;
    if host.is_empty() || host.contains(['/', '*', '?', '#', ' ']) {
        return Err(invalid("только схема://хост[:порт], без пути и '*'"));
    }
    HeaderValue::from_str(origin).map_err(|_| invalid("недопустимые символы"))
}

fn build_cors(origins: &[String]) -> Result<CorsLayer, ConfigError> {
    if origins.is_empty() {
        // без allow_origin браузер блокирует любые кросс-доменные запросы
        warn!("api.allowed_origins пуст — кросс-доменные запросы из браузера запрещены");
        return Ok(CorsLayer::new());
    }
    let parsed = origins
        .iter()
        .map(|o| parse_origin(o))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(parsed)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(600)))
}

pub fn router(state: ApiState, cfg: &ApiConfig) -> Result<Router, ConfigError> {
    let governor = rate_limit::build(&cfg.rate_limit)?;
    Ok(Router::new()
        .nest("/users", routes::users::router())
        .nest("/roles", routes::roles::router())
        .nest("/permissions", routes::roles::permissions_router())
        .nest("/settings", routes::settings::router())
        .nest("/auth", routes::auth::router(governor.clone()))
        .nest("/setup", routes::setup::router(governor))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(cfg.request_timeout_secs),
        ))
        .layer(build_cors(&cfg.allowed_origins)?))
}
