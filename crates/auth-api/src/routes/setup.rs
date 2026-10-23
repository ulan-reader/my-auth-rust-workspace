use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{ApiState, error::ApiError, rate_limit::Governor};

#[derive(Serialize)]
struct SetupStatus {
    required: bool,
}

async fn status(State(state): State<ApiState>) -> Result<Json<SetupStatus>, ApiError> {
    Ok(Json(SetupStatus {
        required: state.setup.is_required().await?,
    }))
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub setup_token: SecretString,
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

async fn initialize(
    State(state): State<ApiState>,
    Json(req): Json<SetupRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .setup
        .initialize(auth_core::service::SetupInput {
            setup_token: req.setup_token,
            email: req.email,
            password: req.password,
            first_name: req.first_name,
            second_name: req.second_name,
        })
        .await?;
    Ok(StatusCode::CREATED) // дальше обычный POST /auth/login
}

/// Под rate-limit: перебор секрета и хеширование пароля на каждом запросе.
pub fn router(governor: Arc<Governor>) -> Router<ApiState> {
    Router::new()
        .route("/", get(status).post(initialize))
        .layer(tower_governor::GovernorLayer::new(governor))
}
