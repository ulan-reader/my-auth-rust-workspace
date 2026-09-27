use auth_core::AuthError;
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
) -> Result<(), ApiError> {
    state.auth.refresh(&req.refresh_token).await?;
    Ok(())
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

async fn me(AuthCtx(ctx): AuthCtx) -> Json<crate::dto::UserDto> {
    Json(
        auth_core::service::UserWithRoles {
            user: ctx.user,
            roles: Vec::new(),
        }
        .into(),
    )
}

// подавляем неиспользуемый импорт AuthError в некоторых конфигурациях компилятора
#[allow(unused_imports)]
use AuthError as _AuthErrorReexportForDocs;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/me", axum::routing::get(me))
}
