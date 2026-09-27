use auth_core::domain::RuntimeSettings;
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};

use crate::{ApiState, error::ApiError, extract::AuthCtx};

#[derive(Serialize)]
pub struct SettingsDto {
    pub allow_self_registration: bool,
}

impl From<RuntimeSettings> for SettingsDto {
    fn from(s: RuntimeSettings) -> Self {
        Self {
            allow_self_registration: s.allow_self_registration,
        }
    }
}

async fn get_settings(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
) -> Result<Json<SettingsDto>, ApiError> {
    Ok(Json(state.settings.get(&ctx).await?.into()))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub allow_self_registration: bool,
}

async fn update_settings(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsDto>, ApiError> {
    let s = state
        .settings
        .set_allow_self_registration(&ctx, req.allow_self_registration)
        .await?;
    Ok(Json(s.into()))
}

pub fn router() -> Router<ApiState> {
    Router::new().route("/", get(get_settings).put(update_settings))
}
