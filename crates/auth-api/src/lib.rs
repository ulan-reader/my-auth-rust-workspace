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
        AccessService, AuthPolicy, AuthService, Ports, RoleService, SettingsService, UserService,
    },
};
use axum::{Router, http::HeaderValue};
use rate_limit::RateLimitConfig;
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
}

impl ApiState {
    pub fn from_ports(ports: &Ports, policy: AuthPolicy) -> Self {
        Self {
            auth: AuthService::from_ports(ports, policy),
            users: UserService::from_ports(ports),
            roles: RoleService::from_ports(ports),
            access: AccessService::from_ports(ports),
            permissions: ports.permissions.clone(),
            settings: SettingsService::from_ports(ports),
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

fn build_cors(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        warn!(
            "api.allowed_origins пуст — CORS открыт для всех источников, это ок только для локальной разработки"
        );
        return CorsLayer::permissive();
    }
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| match o.parse() {
            Ok(v) => Some(v),
            Err(_) => {
                warn!(origin = %o, "невалидный origin в api.allowed_origins, пропущен");
                None
            }
        })
        .collect();
    CorsLayer::new()
        .allow_origin(parsed)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

pub fn router(state: ApiState, cfg: &ApiConfig) -> Router {
    Router::new()
        .nest("/auth", routes::auth::router(&cfg.rate_limit))
        .nest("/users", routes::users::router())
        .nest("/roles", routes::roles::router())
        .nest("/permissions", routes::roles::permissions_router())
        .nest("/settings", routes::settings::router())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(cfg.request_timeout_secs),
        ))
        .layer(build_cors(&cfg.allowed_origins))
}
