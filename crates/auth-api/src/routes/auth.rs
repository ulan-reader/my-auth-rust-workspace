use axum::{Json, Router, extract::State, routing::post};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{ApiState, dto::TokenPairDto, error::ApiError, extract::AuthCtx};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

async fn register(
    State(state): State<ApiState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<TokenPairDto>, ApiError> {
    let res = state
        .auth
        .register(auth_core::service::RegisterInput {
            email: req.email,
            password: req.password,
            first_name: req.first_name,
            second_name: req.second_name,
        })
        .await?;
    Ok(Json(res.tokens.into()))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: SecretString,
}

async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenPairDto>, ApiError> {
    let res = state.auth.login(&req.email, &req.password).await?;
    Ok(Json(res.tokens.into()))
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: SecretString,
}

async fn refresh(
    State(state): State<ApiState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenPairDto>, ApiError> {
    let tokens = state.auth.refresh(&req.refresh_token).await?;
    Ok(Json(tokens.into()))
}

async fn logout(
    State(state): State<ApiState>,
    Json(req): Json<RefreshRequest>,
) -> Result<(), ApiError> {
    state.auth.logout(&req.refresh_token).await?;
    Ok(())
}

async fn logout_all(State(state): State<ApiState>, AuthCtx(ctx): AuthCtx) -> Result<(), ApiError> {
    state.auth.logout_all(ctx).await.map_err(ApiError::from)?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: SecretString,
    pub new_password: SecretString,
}

#[derive(serde::Serialize)]
pub struct ChangePasswordResponse {
    /// Сколько ЧУЖИХ сессий отозвано (текущая, из-под которой сделан запрос, жива).
    pub other_sessions_revoked: u64,
}

async fn change_password(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, ApiError> {
    let other_sessions_revoked = state
        .auth
        .change_own_password(&ctx, &req.old_password, &req.new_password)
        .await?;
    Ok(Json(ChangePasswordResponse {
        other_sessions_revoked,
    }))
}

async fn me(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
) -> Result<Json<crate::dto::UserDto>, ApiError> {
    Ok(Json(state.users.me(&ctx).await?.into()))
}

pub fn router(governor: std::sync::Arc<crate::rate_limit::Governor>) -> Router<ApiState> {
    let limited = Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/me/password", post(change_password))
        .layer(tower_governor::GovernorLayer::new(governor));

    let rest = Router::new()
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/me", axum::routing::get(me));

    limited.merge(rest)
}
