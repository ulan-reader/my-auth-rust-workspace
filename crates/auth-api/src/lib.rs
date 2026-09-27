//! auth-api — axum-роутер поверх auth-core. Ни sqlx, ни argon2, ни jwt здесь нет —
//! только use-case'ы core и HTTP-обвязка (DTO, коды ошибок, извлечение AuthCtx).

pub mod dto;
pub mod error;
pub mod extract;
mod routes;

use std::sync::Arc;
use std::time::Duration;

use auth_core::{
    ports::PermissionRepository,
    service::{
        AccessService, AuthPolicy, AuthService, Ports, RoleService, SettingsService, UserService,
    },
};
use axum::Router;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

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
pub struct ApiConfig {
    pub request_timeout_secs: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: 15,
        }
    }
}

pub fn router(state: ApiState, cfg: &ApiConfig) -> Router {
    Router::new()
        .nest("/auth", routes::auth::router())
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
        .layer(CorsLayer::permissive()) // на проде заменить на реальный фронт CorsLayer::new().allow_origin(...)
}
